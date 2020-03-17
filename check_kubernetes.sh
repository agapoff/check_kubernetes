#!/bin/bash
# shellcheck disable=SC2181,SC2207

##########################
# Perform checks against Kubernetes API or with tab help of kubectl utility
# Designed for usage with Nagios, Icinga, Zabbix, Shinken... Whatever.
#
# 2018/06/28 Vitaly Agapov <v.agapov@quotix.com>
# 2020 Roosembert Palacios <roosemberth@posteo.ch>
##########################

usage() {
    cat <<- EOF
	Usage $0 [-m <MODE>|-h] [-o <TIMEOUT>] [-H <APISERVER> [-T <TOKEN>|-t <TOKENFILE>]] [-K <KUBE_CONFIG>]
	         [-N <NAMESPACE>] [-n <NAME>] [-w <WARN>] [-c <CRIT>]

	Options are:
	  -m MODE          Which check to perform
	  -H APISERVER     API URL to query, kubectl is used if this option is not set
	  -T TOKEN         Authorization token for API
	  -t TOKENFILE     Path to file with token in it
	  -K KUBE_CONFIG   Path to kube-config file for kubectl utility
	  -N NAMESPACE     Optional namespace for some modes. By default all namespaces will be used
	  -n NAME          Optional deployment name or pod app label depending on the mode being used. By default all objects will be checked
	  -o TIMEOUT       Timeout in seconds; default is 15
	  -w WARN          Warning threshold for
	                    - TLS expiration days for TLS mode; default is 30
	                    - Pod restart count in pods mode; default is 30
	  -c CRIT          Critical threshold for
	                    - Pod restart count (in pods mode); default is 150
	                    - Unbound Persistent Volumes in unboundpvs mode; default is 5
	  -b               Brief mode (more suitable for Zabbix)
	  -h               Show this help and exit

	Modes are:
	  apiserver        Not for kubectl, should be used for each apiserver independently
	  components       Check for health of k8s components (etcd, controller-manager, scheduler etc.)
	  nodes            Check for active nodes
	  pods             Check for restart count of containters in the pods
	  deployments      Check for deployments availability
	  daemonsets       Check for daemonsets readiness
	  unboundpvs       Check for unbound persistent volumes.
	  replicasets      Check for replicasets readiness
	  statefulsets     Check for statefulsets readiness
	  tls              Check for tls secrets expiration dates
	EOF

    exit 2
}

BRIEF=0
TIMEOUT=15

die() {
  if [ "$BRIEF" = 1 ]; then
    echo "-1"
  else
    echo "$1"
  fi
  exit "${2:-2}"
}

while getopts ":m:H:T:t:K:N:n:o:c:w:bh" arg; do
    case $arg in
        h) usage ;;
        m) MODE="$OPTARG" ;;
        o) TIMEOUT="${OPTARG}" ;;
        H) APISERVER="${OPTARG%/}" ;;
        T) TOKEN="$OPTARG" ;;
        t) TOKENFILE="$OPTARG" ;;
        K) export KUBECONFIG="$OPTARG" ;;
        N) NAMESPACE="$OPTARG" ;;
        n) NAME="$OPTARG" ;;
        w) WARN="$OPTARG" ;;
        c) CRIT="$OPTARG" ;;
        b) BRIEF=1 ;;
        *) usage ;;
    esac
done

[ -z "$MODE" ] && usage

if [ "$APISERVER" ]; then
    [ -z "$TOKEN" ] && [ -z "$TOKENFILE" ] && usage
else
    command -v kubectl &>/dev/null || die "CRITICAL: kubectl is required as api-server is not defined"
fi

command -v jq &>/dev/null || die "CRITICAL: jq is required"

getJSON() {
    kubectl_command=$1
    api_path=$2

    if [ "$APISERVER" ]; then
        if [ -z "$TOKEN" ]; then
            TOKEN="$(cat "$TOKENFILE")"
        fi
        data=$(timeout "$TIMEOUT" curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/$api_path")
        code=$?
        if [ $code = 124 ]; then
            die "Timed out after $TIMEOUT seconds"
        fi
        if [[ "$api_path" =~ healthz ]]; then
            echo "$data"
            return
        fi
        kind=$(echo "$data" | jq -r ".kind")
        if [ "$kind" = Status ]; then
            message=$(echo "$data" | jq -r ".message")
            die "API call failed: $message"
        elif [ -z "$kind" ]; then
            die "Could not access API"
        fi
    else
        data=$(timeout "$TIMEOUT" kubectl "$kubectl_command" -o json 2>&1)
        code=$?
        if [ $code -gt 0 ]; then
            if [ $code = 124 ]; then
                die "Timed out after $TIMEOUT seconds"
            else
                die "${data/#\{*\}/}"
            fi
        fi
    fi
    echo "$data" | sed 's/^[[:blank:]]*//' | tr -d '\n'
}

OUTPUT=""
EXITCODE=0

kubectl_ns="--all-namespaces"
if [ "$NAMESPACE" ]; then
    api_ns="/namespaces/$NAMESPACE"
    kubectl_ns="--namespace=$NAMESPACE"
fi

mode_apiserver() {
    if [ -z "$APISERVER" ]; then
        die "Apiserver URL should be defined in this mode"
    fi
    data=$(getJSON "" "healthz")
    [ $? -gt 0 ] && die "$data"
    if [ "$data" = ok ]; then
        OUTPUT="OK. Kuberenetes apiserver health is OK"
        EXITCODE=0
    else
        OUTPUT="CRITICAL. Kuberenetes apiserver health is $data"
        EXITCODE=2
    fi
}

mode_nodes() {
    data="$(getJSON "get nodes" "api/v1/nodes")"
    [ $? -gt 0 ] && die "$data"
    nodes=($(echo "$data" | jq -r ".items[].metadata.name"))

    for node in "${nodes[@]}"; do
        ready="$(echo "$data" | jq -r ".items[] | select(.metadata.name==\"$node\") | \
                                       .status.conditions[] | select(.type==\"Ready\") | \
                                       .status")"
        if [ "$ready" != True ]; then
            EXITCODE=2
            OUTPUT="${OUTPUT}Node $node not ready. "
        fi
        for condition in OutOfDisk MemoryPressure DiskPressure; do
            state="$(echo "$data" | jq -r ".items[] | select(.metadata.name==\"$node\") | \
                                           .status.conditions[] | select(.type==\"$condition\") | \
                                           .status")"
            if [ "$state" = True ]; then
                [ $EXITCODE -lt 1 ] && EXITCODE=1
                OUTPUT="$OUTPUT $node $condition."
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z "${nodes[*]}" ]; then
            OUTPUT="No nodes found"
            EXITCODE=2
        else
            OUTPUT="OK. ${#nodes[@]} nodes are Ready"
            BRIEF_OUTPUT="${#nodes[@]}"
        fi
    else
        BRIEF_OUTPUT="-1"
    fi
}

mode_components() {
    healthy_comps=""
    unhealthy_comps=""
    data="$(getJSON "get cs" "api/v1/componentstatuses")"
    [ $? -gt 0 ] && die "$data"
    components=($(echo "$data" | jq -r ".items[].metadata.name"))

    for comp in "${components[@]}"; do
        healthy=$(echo "$data" | jq -r ".items[] | select(.metadata.name==\"$comp\") | \
                                        .conditions[] | select(.type==\"Healthy\") | \
                                        .status")
        if [ "$healthy" != True ]; then
            EXITCODE=2
            unhealthy_comps="$unhealthy_comps $comp"
        else
            healthy_comps="$healthy_comps $comp"
        fi
    done

    BRIEF_OUTPUT="$healthy_comps"
    if [ $EXITCODE = 0 ]; then
        if [ -z "${components[*]}" ]; then
            OUTPUT="No components found"
            EXITCODE=2
        else
            OUTPUT="OK. Healthy: $healthy_comps"
        fi
    else
        OUTPUT="CRITICAL. Unhealthy: $unhealthy_comps; Healthy: $healthy_comps"
    fi
}

mode_unboundpvs() {
    CRIT=${CRIT:-5}
    data=$(getJSON "get pvs" "api/v1/persistentvolumes")
    [ $? -gt 0 ] && die "$data"
    declare -A pvsArr unboundPvsArr
    while IFS="=" read -r key value; do
        pvsArr[$key]="$value"
    done < <(echo "$data" | jq -r ".items[] | \"\(.metadata.name)=\(.status.phase)\"")

    while IFS=":" read -r name status claimRef; do
        OUTPUT="Persistent volume $name is $status (referenced by $claimRef)\n$OUTPUT"
        unboundPvsArr[$name]="$status:$claimRef"
    done < <(echo "$data" | \
             jq -r ".items[] | \
                     select(.status.phase!=\"Bound\") | \
                    \"\(.metadata.name):\(.status.phase):\(.spec.claimRef.uid)\"")

    BRIEF_OUTPUT="${#pvsArr[*]}"
    if [ ${#unboundPvsArr[*]} -gt 0 ]; then
        BRIEF_OUTPUT="-${#unboundPvsArr[*]}"
        if [ ${#unboundPvsArr[*]} -ge "$CRIT" ]; then
            OUTPUT="CRITICAL. Unbound persistentvolumes:\n$OUTPUT"
            EXITCODE=2
        else
            OUTPUT="WARNING. Unbound persistentvolumes:\n$OUTPUT"
            EXITCODE=1
        fi
    else
        OUTPUT="OK. ${#pvsArr[*]} persistentvolumes correctly bound."
    fi
}

mode_tls() {
    WARN=${WARN:-30}

    count_ok=0
    count_warn=0
    count_crit=0
    nowdate=$(date +%s)

    fulldata=$(getJSON "get secrets $kubectl_ns" "api/v1$api_ns/secrets/")
    [ $? -gt 0 ] && die "$fulldata"
    data=$(echo "$fulldata" | \
           jq -r ".items[] | select (.type==\"kubernetes.io/tls\")")

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | \
                      jq -r " select(.metadata.name==\"$NAME\") | \
                             .metadata.namespace" | sort -u))
    else
        namespaces=($(echo "$data" | jq -r ".metadata.namespace" | sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        if [ "$NAME" ]; then
            certs=("$NAME")
        else
            certs=($(echo "$data" | jq -r "select(.metadata.namespace==\"$ns\") | \
                                           .metadata.name"))
        fi
        for cert in "${certs[@]}"; do
            notafter=$(echo "$data" | \
                       jq -r " select(.metadata.namespace==\"$ns\" and .metadata.name==\"$cert\") | \
                              .data.\"tls.crt\"" | \
                       base64 -d | \
                       openssl x509 -enddate -noout | \
                       sed 's/notAfter=//')
            enddate=$(date -d "$notafter" +%s)
            diff="$((enddate-nowdate))"

            if [ "$diff" -le 0 ]; then
                ((count_crit++))
                EXITCODE=2
                OUTPUT="$OUTPUT $ns/$cert is expired."
            elif [ "$diff" -le "$((WARN*24*3600))" ]; then
                ((count_warn++))
                if [ "$EXITCODE" == 0 ]; then
                    EXITCODE=1
                fi
                OUTPUT="$OUTPUT $ns/$cert is about to expire in $((diff/3600/24)) days."
            else
                ((count_ok++))
            fi
        done
    done

    BRIEF_OUTPUT="$count_ok"
    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No TLS certs found"
            EXITCODE=2
        else
            if [ $count_ok -gt 1 ]; then
                OUTPUT="OK. $count_ok TLS secrets are OK"
            else
                OUTPUT="OK. TLS secret is OK"
            fi
        fi
    fi
}

mode_pods() {
    WARN=${WARN:-30}
    CRIT=${CRIT:-150}
    if [ "$WARN" -gt "$CRIT" ]; then
        WARN=$CRIT
    fi

    count_ready=0
    count_failed=0
    max_restart_count=0
    bad_container=""
    data=$(getJSON "get pods $kubectl_ns" "api/v1$api_ns/pods/")
    [ $? -gt 0 ] && die "$data"

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | \
                      jq -r ".items[] | select(.metadata.labels.app==\"$NAME\") | \
                             .metadata.namespace" | \
                      sort -u))
    else
        namespaces=($(echo "$data" | \
                      jq -r ".items[].metadata.namespace" | \
                      sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        nsdata="$(echo "$data" | jq -cr ".items[] | select(.metadata.namespace==\"$ns\")")"
        if [ "$NAME" ]; then
            pods=($(echo "$nsdata" | \
                    jq -r "select(.status.reason!=\"Evicted\" \
                                   and .metadata.labels.app==\"$NAME\") | \
                           .metadata.name"))
        else
            pods=($(echo "$nsdata" | \
                    jq -r "select(.status.reason!=\"Evicted\") | \
                           .metadata.name"))
        fi
        for pod in "${pods[@]}"; do
            containers=($(echo "$nsdata" | \
                          jq -r "select(.metadata.name==\"$pod\") | \
                                 .status.containerStatuses[].name"))
            for container in "${containers[@]}"; do
                restart_count=$(echo "$nsdata" | \
                                jq -r "select(.metadata.name==\"$pod\") | \
                                       .status.containerStatuses[] | \
                                        select(.name==\"$container\") | \
                                       .restartCount")
                if [ "$restart_count" -gt "$max_restart_count" ]; then
                    bad_container="$ns/$pod/$container"
                    max_restart_count=$restart_count
                fi
            done
            ready=$(echo "$nsdata" | \
                    jq -r "select(.metadata.name==\"$pod\") | \
                           .status.conditions[] | \
                            select(.type==\"Ready\") | \
                           .status")
            if [ "$ready" != True ]; then
                ((count_failed++))
            else
                ((count_ready++))
            fi
        done
    done

    if [ "$max_restart_count" -ge "$WARN" ]; then
        BRIEF_OUTPUT="-$max_restart_count"
    else
        BRIEF_OUTPUT="$count_ready"
    fi

    if [ -z "$ns" ]; then
        OUTPUT="No pods found"
        EXITCODE=2
    else
        if [ "$max_restart_count" -ge "$WARN" ]; then
            OUTPUT="Container $bad_container: $max_restart_count restarts. "
            EXITCODE=1
            if [ "$max_restart_count" -ge "$CRIT" ]; then
                EXITCODE=2
            fi
        fi
        OUTPUT="$OUTPUT$count_ready pods ready, $count_failed pods not ready"
    fi
}

mode_deployments() {
    count_avail=0
    count_failed=0
    data=$(getJSON "get deployments $kubectl_ns" "apis/apps/v1$api_ns/deployments/")
    [ $? -gt 0 ] && die "$data"

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r ".items[] | select(.metadata.name==\"$NAME\") | \
                                            .metadata.namespace" | sort -u))
    else
        namespaces=($(echo "$data" | jq -r ".items[].metadata.namespace" | sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        nsdata="$(echo "$data" | jq -cr ".items[] | select(.metadata.namespace==\"$ns\")")"
        if [ "$NAME" ]; then
            deps=("$NAME")
        else
            deps=($(echo "$nsdata" | jq -r ".metadata.name"))
        fi
        for dep in "${deps[@]}"; do
            avail="$(echo "$nsdata" | jq -r "select(.metadata.name==\"$dep\") | \
                                             .status.conditions[] | select(.type==\"Available\") | \
                                             .status")"
            if [ "$avail" != True ]; then
                ((count_failed++))
                EXITCODE=2
                OUTPUT="Deployment $ns/$dep"
            else
                ((count_avail++))
            fi
        done
    done

    BRIEF_OUTPUT="$count_avail"
    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No deployments found"
            EXITCODE=2
        else
            if [ $count_avail -gt 1 ]; then
                OUTPUT="OK. $count_avail deploymens are available"
            else
                OUTPUT="OK. Deployment available"
            fi
        fi
    else
        if [ $count_failed = 1 ]; then
            OUTPUT="$OUTPUT not available"
        else
            OUTPUT="$OUTPUT and $((--count_failed)) more are not available"
        fi
    fi
}

mode_daemonsets() {
    count_avail=0
    count_failed=0
    data=$(getJSON "get ds $kubectl_ns" "apis/apps/v1$api_ns/daemonsets/")
    [ $? -gt 0 ] && die "$data"

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r ".items[] | select(.metadata.name==\"$NAME\") | \
                                            .metadata.namespace" | sort -u))
    else
        namespaces=($(echo "$data" | jq -r ".items[].metadata.namespace" | sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        if [ "$NAME" ]; then
            daemonsets=("$NAME")
        else
            daemonsets=($(echo "$data" | jq -r ".items[] | select(.metadata.namespace==\"$ns\") | \
                                                .metadata.name"))
        fi
        for ds in "${daemonsets[@]}"; do
            declare -A statusArr
            while IFS="=" read -r key value; do
               statusArr[$key]="$value"
            done < <(echo "$data" | jq -r ".items[] | \
                                            select(.metadata.namespace==\"$ns\" and .metadata.name==\"$ds\") | \
                                           .status | to_entries | map(\"\(.key)=\(.value)\") | \
                                           .[]")
            if [ $EXITCODE == 0 ]; then
                OUTPUT="Daemonset $ns/$ds ${statusArr[numberReady]}/${statusArr[desiredNumberScheduled]} ready"
            fi
            if [ "${statusArr[numberReady]}" != "${statusArr[desiredNumberScheduled]}" ]; then
                ((count_failed++))
                EXITCODE=2
            else
                ((count_avail++))
            fi
        done
    done

    BRIEF_OUTPUT="$count_avail"
    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No daemonsets found"
            EXITCODE=2
        else
            if [ $count_avail -gt 1 ]; then
                OUTPUT="OK. $count_avail daemonsets are ready"
            else
                OUTPUT="OK. $OUTPUT"
            fi
        fi
    else
        if [ $count_failed = 1 ]; then
            OUTPUT="$OUTPUT"
        else
            OUTPUT="${OUTPUT}. $((--count_failed)) more are not ready"
        fi
    fi
}

mode_replicasets() {
    count_avail=0
    count_failed=0

    data=$(getJSON "get rs $kubectl_ns" "apis/apps/v1$api_ns/replicasets/")
    [ $? -gt 0 ] && die "$data"

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | \
                      jq -r ".items[] | select(.metadata.name==\"$NAME\") | \
                             .metadata.namespace" | \
                      sort -u))
    else
        namespaces=($(echo "$data" | jq -r ".items[].metadata.namespace" | sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        if [ "$NAME" ]; then
            replicasets=("$NAME")
        else
            replicasets=($(echo "$data" | \
                           jq -r ".items[] | select(.metadata.namespace==\"$ns\") | \
                                  .metadata.name"))
        fi
        for rs in "${replicasets[@]}"; do
            declare -A statusArr
            while IFS="=" read -r key value; do
               statusArr[$key]="$value"
            done < <(echo "$data" | \
                     jq -r ".items[] | select(.metadata.namespace==\"$ns\" and .metadata.name==\"$rs\") | \
                            .status | to_entries | map(\"\(.key)=\(.value)\") | .[]")
            OUTPUT="Replicaset $ns/$rs ${statusArr[readyReplicas]}/${statusArr[availableReplicas]} ready"
            if [ "${statusArr[readyReplicas]}" != "${statusArr[availableReplicas]}" ]; then
                ((count_failed++))
                EXITCODE=2
            else
                ((count_avail++))
            fi
        done
    done

    BRIEF_OUTPUT="$count_avail"
    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No replicasets found"
            EXITCODE=2
        else
            if [ $count_avail -gt 1 ]; then
                OUTPUT="OK. $count_avail replicasets are ready"
            else
                OUTPUT="OK. $OUTPUT"
            fi
        fi
    else
        if [ $count_failed = 1 ]; then
            OUTPUT="$OUTPUT"
        else
            OUTPUT="${OUTPUT}. $((--count_failed)) more are not ready"
        fi
    fi
}

mode_statefulsets() {
    count_avail=0
    count_failed=0
    data=$(getJSON "get rs $kubectl_ns" "apis/apps/v1$api_ns/statefulsets/")
    [ $? -gt 0 ] && die "$data"

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | \
                      jq -r ".items[] | select(.metadata.name==\"$NAME\") | \
                             .metadata.namespace" | \
                      sort -u))
    else
        namespaces=($(echo "$data" | \
                      jq -r ".items[].metadata.namespace" | \
                      sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        if [ "$NAME" ]; then
            statefulsets=("$NAME")
        else
            statefulsets=($(echo "$data" | \
                            jq -r ".items[] | select(.metadata.namespace==\"$ns\") | \
                                   .metadata.name"))
        fi
        for rs in "${statefulsets[@]}"; do
            declare -A statusArr
            while IFS="=" read -r key value; do
               statusArr[$key]="$value"
            done < <(echo "$data" | \
                     jq -r ".items[] | select(.metadata.namespace==\"$ns\" and .metadata.name==\"$rs\") | \
                            .status | to_entries | map(\"\(.key)=\(.value)\") | .[]")
            OUTPUT="Statefulset $ns/$rs ${statusArr[readyReplicas]}/${statusArr[currentReplicas]} ready"
            if [ "${statusArr[readyReplicas]}" != "${statusArr[currentReplicas]}" ]; then
                ((count_failed++))
                EXITCODE=2
            else
                ((count_avail++))
            fi
        done
    done

    BRIEF_OUTPUT="$count_avail"
    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No statefulsets found"
            EXITCODE=2
        else
            if [ $count_avail -gt 1 ]; then
                OUTPUT="OK. $count_avail statefulsets are ready"
            else
                OUTPUT="OK. $OUTPUT"
            fi
        fi
    else
        if [ $count_failed = 1 ]; then
            OUTPUT="$OUTPUT"
        else
            OUTPUT="${OUTPUT}. $((--count_failed)) more are not ready"
        fi
    fi
}

case "$MODE" in
    (apiserver) mode_apiserver ;;
    (components) mode_components ;;
    (daemonsets) mode_daemonsets ;;
    (deployments) mode_deployments ;;
    (nodes) mode_nodes ;;
    (unboundpvs) mode_unboundpvs ;;
    (pods) mode_pods ;;
    (replicasets) mode_replicasets ;;
    (statefulsets) mode_statefulsets ;;
    (tls) mode_tls ;;
    (*) usage ;;
esac

if [ "$BRIEF" = 1 ]; then
    if [ "$EXITCODE" = 0 ]; then
        echo "${BRIEF_OUTPUT:-1}"
    elif [ -z "$BRIEF_FAIL_OUTPUT" ]; then
        echo "${BRIEF_OUTPUT:-0}"
    else
        echo "${BRIEF_FAIL_OUTPUT}"
    fi
else
    echo "$OUTPUT"
fi

exit $EXITCODE
