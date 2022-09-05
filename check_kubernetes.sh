#!/bin/bash
# shellcheck disable=SC2181,SC2207,SC2199,SC2076

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
	                    - Job failed count in jobs mode; default is 1
	                    - Pvc storage utilization; default is 80%
	  -c CRIT          Critical threshold for
	                    - Pod restart count (in pods mode); default is 150
	                    - Unbound Persistent Volumes in unboundpvs mode; default is 5
	                    - Job failed count in jobs mode; default is 2
	                    - Pvc storage utilization; default is 90%
	  -M EXIT_CODE     Exit code when resource is missing; default is 2 (CRITICAL)
	  -h               Show this help and exit

	Modes are:
	  apiserver        Not for kubectl, should be used for each apiserver independently
	  nodes            Check for active nodes
	  daemonsets       Check for daemonsets readiness
	  deployments      Check for deployments availability
	  jobs             Check for failed jobs
	  pods             Check for restart count of containters in the pods
	  replicasets      Check for replicasets readiness
	  statefulsets     Check for statefulsets readiness
	  tls              Check for tls secrets expiration dates
	  pvc              Check for pvc utilization
	  unboundpvs       Check for unbound persistent volumes
	EOF

    exit 2
}

TIMEOUT=15
unset NAME

die() {
    echo "$1"
  exit "${2:-2}"
}

while getopts ":m:M:H:T:t:K:N:n:o:c:w:h" arg; do
    case $arg in
        h) usage ;;
        m) MODE="$OPTARG" ;;
        M) MISSING_EXITCODE="${OPTARG}" ;;
        o) TIMEOUT="${OPTARG}" ;;
        H) APISERVER="${OPTARG%/}" ;;
        T) TOKEN="$OPTARG" ;;
        t) TOKENFILE="$OPTARG" ;;
        K) export KUBECONFIG="$OPTARG" ;;
        N) NAMESPACE="$OPTARG" ;;
        n) NAME="$OPTARG" ;;
        w) WARN="$OPTARG" ;;
        c) CRIT="$OPTARG" ;;
        *) usage ;;
    esac
done

[ -z "$MODE" ] && usage
MISSING_EXITCODE="${MISSING_EXITCODE:-2}"

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
        data=$(eval timeout "$TIMEOUT" kubectl "$kubectl_command" -o json 2>&1)
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
        OUTPUT="OK. Kubernetes apiserver is healthy"
        EXITCODE=0
    else
        data=$(echo "$data" | grep "\[\-\]")
        OUTPUT="CRITICAL. Kubernetes apiserver health is $data"
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
                OUTPUT="${OUTPUT}$node $condition. "
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z "${nodes[*]}" ]; then
            OUTPUT="No nodes found"
            EXITCODE="$MISSING_EXITCODE"
        else
            OUTPUT="OK. ${#nodes[@]} nodes are ready"
        fi
    fi
}

mode_unboundpvs() {
    CRIT=${CRIT:-5}
    data=$(getJSON "get pv" "api/v1/persistentvolumes")
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

    if [ ${#unboundPvsArr[*]} -gt 0 ]; then
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

mode_pvc() {
    WARN=${WARN:-80}
    CRIT=${CRIT:-90}
    WARN_ERROR=0
    CRIT_ERROR=0
    PVC_COUNT=0

    data="$(getJSON "get nodes" "api/v1/nodes")"
    [ $? -gt 0 ] && die "$data"
    nodes=($(echo "$data" | jq -r ".items[].metadata.name"))

    for node in "${nodes[@]}"; do
        data="$(getJSON "get nodes" "api/v1/nodes/$node/proxy/stats/summary")"
        [ $? -gt 0 ] && die "$data"
        pods=($(echo "$data" | jq -r ".pods[].podRef.name"))
        for pod in "${pods[@]}"; do
            pod_volumes="$(echo "$data" | jq -r ".pods[] | select(.podRef.name==\"$pod\") | .volume" 2>/dev/null)"
            [ "$pod_volumes" == "null" ] && continue
            for volumes in "${pod_volumes[@]}"; do
                volumes_list="$(echo "$volumes" | jq -r ".[] | select(.pvcRef.name!=null)")"
                volumes_namespace=$(echo "$volumes_list" | jq -r ".pvcRef.namespace" | uniq)
                for pvc_volumes in "${volumes_list[@]}"; do
                    [ -z "$pvc_volumes" ] && continue
                    for volume_name in $(echo "$pvc_volumes" | jq -r ".name"); do
                        #volume_bytes_available=$(echo "$pvc_volumes" | jq -r ". | select(.name==\"$volume_name\") | .availableBytes")
                        volume_bytes_capacity=$(echo "$pvc_volumes" | jq -r ". | select(.name==\"$volume_name\") | .capacityBytes")
                        volume_bytes_used=$(echo "$pvc_volumes" | jq -r ". | select(.name==\"$volume_name\") | .usedBytes")
                        #volume_inodes_free=$(echo "$pvc_volumes" | jq -r ". | select(.name==\"$volume_name\") | .inodesFree")
                        volume_inodes_used=$(echo "$pvc_volumes" | jq -r ". | select(.name==\"$volume_name\") | .inodesUsed")
                        volume_inodes_capacity=$(echo "$pvc_volumes" | jq -r ". | select(.name==\"$volume_name\") | .inodes")
                        volume_bytes_utilization=$(echo "100 * $volume_bytes_used / $volume_bytes_capacity" | bc)
                        volume_inodes_utilization=$(echo "100 * $volume_inodes_used / $volume_inodes_capacity" | bc)

                        ((PVC_COUNT++))

                        if [ "$volume_bytes_utilization" -gt "$WARN" ] && [ "$volume_bytes_utilization" -lt "$CRIT" ]; then
                             OUTPUT="${OUTPUT}High storage utilization on pvc $volume_name (namespace:$volumes_namespace): $volume_bytes_utilization% ($volume_bytes_used/$volume_bytes_capacity Bytes)\n"
                            ((WARN_ERROR++))
                        fi
                        if [ "$volume_bytes_utilization" -gt "$CRIT" ]; then
                             OUTPUT="${OUTPUT}Very high storage utilization on pvc $volume_name: $volume_bytes_utilization% ($volume_bytes_used/$volume_bytes_capacity Bytes)\n"
                            ((CRIT_ERROR++))
                        fi
                        if [ "$volume_inodes_utilization" -gt "$WARN" ] && [ "$volume_inodes_utilization" -lt "$CRIT" ]; then
                             OUTPUT="${OUTPUT}High inodes utilization on pvc $volume_name: $volume_inodes_utilization% ($volume_inodes_used/$volume_inodes_capacity)\n"
                            ((WARN_ERROR++))
                        fi
                        if [ "$volume_inodes_utilization" -gt "$CRIT" ]; then
                             OUTPUT="${OUTPUT}Very high inodes utilization on pvc $volume_name: $volume_inodes_utilization% ($volume_inodes_used/$volume_inodes_capacity)\n"
                            ((CRIT_ERROR++))
                        fi
                    done
                done
            done
        done
    done

    if [ "$WARN_ERROR" -eq "0" ] && [ "$CRIT_ERROR" -eq "0" ]; then
        echo "OK. No problems on $PVC_COUNT pvc"
    elif [ "$WARN_ERROR" -ne "0" ] && [ "$CRIT_ERROR" -eq "0" ]; then
        echo "WARNING.\n${OUTPUT}"
        exit 1
    elif [ "$CRIT_ERROR" -ne "0" ]; then
        echo "CRITICAL.\n${OUTPUT}"
        exit 2
    else
        echo "ERROR.\n${OUTPUT}"
        exit 3
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
                       base64 -d 2>/dev/null | \
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

    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No TLS certs found"
            EXITCODE="$MISSING_EXITCODE"
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
    count_succeeded=0
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
        nsdata="$(echo "$data" | jq -c -r ".items[] | select(.metadata.namespace==\"$ns\")")"
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
                                 .status.containerStatuses[]?.name"))
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
            count_status=$(echo "$nsdata" | \
                    jq -r "select(.metadata.name==\"$pod\") | \
                           .status.phase")
            if [ "$count_status" == "Running" ]; then
                ((count_ready++))
            elif [ "$count_status" == "Succeeded" ]; then
                ((count_succeeded++))
            else
                ((count_failed++))
            fi
            if [ "$restart_count" -ge "$WARN" ]; then
                OUTPUT="${OUTPUT}Container $bad_container: $restart_count restarts.\n"
                EXITCODE=1
                if [ "$restart_count" -ge "$CRIT" ]; then
                    EXITCODE=2
                fi
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
    if [ -z "$ns" ]; then
        OUTPUT="No pods found"
        EXITCODE="$MISSING_EXITCODE"
    else
             OUTPUT="OK. $count_ready pods ready, $count_succeeded pods succeeded, $count_failed pods not ready\n${OUTPUT}"
        fi
    else
        if [ $EXITCODE = 1 ]; then
            OUTPUT="WARNING. $count_ready pods ready, $count_succeeded pods succeeded, $count_failed pods not ready\n${OUTPUT}"
        else
            OUTPUT="ERROR. $count_ready pods ready, $count_succeeded pods succeeded, $count_failed pods not ready\n${OUTPUT}"
            fi
        fi
}

mode_deployments() {
    count_avail=0
    count_failed=0
    rawdata=$(getJSON "get deployments $kubectl_ns" "apis/apps/v1$api_ns/deployments/")
    [ $? -gt 0 ] && die "$rawdata"

    # deflate the data
    data="$(echo "$rawdata" | jq -r '.items[] | {name: .metadata.name, namespace: .metadata.namespace, status: .status.conditions}')"

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r "select(.name==\"$NAME\") | \
                                            .namespace" | sort -u))
    else
        namespaces=($(echo "$data" | jq -r ".namespace" | sort -u))
    fi

    for ns in "${namespaces[@]}"; do
        nsdata="$(echo "$data" | jq -c -r "select(.namespace==\"$ns\")")"
        availdeps=($(echo "$nsdata" | jq -r "{name: .name, status: .status[]|select(.type==\"Available\")} | \
                                             select(.status.status == \"True\") | .name"))
        if [ "$NAME" ]; then
            deps=("$NAME")
        else
            deps=($(echo "$nsdata" | jq -r ".name"))
        fi
        for dep in "${deps[@]}"; do
            if [[ " ${availdeps[@]} " =~ " $dep " ]]; then
                ((count_avail++))
            else
                ((count_failed++))
                EXITCODE=2
                OUTPUT="Deployment $ns/$dep"
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No deployments found"
            EXITCODE="$MISSING_EXITCODE"
        else
            if [ $count_avail -gt 1 ]; then
                OUTPUT="OK. $count_avail deployments are available"
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
            if [ "$EXITCODE" == 0 ]; then
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

    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No daemonsets found"
            EXITCODE="$MISSING_EXITCODE"
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

    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No replicasets found"
            EXITCODE="$MISSING_EXITCODE"
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
    data=$(getJSON "get statefulsets $kubectl_ns" "apis/apps/v1$api_ns/statefulsets/")
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
            OUTPUT="${OUTPUT}Statefulset $ns/$rs ${statusArr[readyReplicas]}/${statusArr[currentReplicas]} ready\n"
            if [ "${statusArr[readyReplicas]}" != "${statusArr[currentReplicas]}" ]; then
                ((count_failed++))
                EXITCODE=2
            else
                ((count_avail++))
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No statefulsets found"
            EXITCODE="$MISSING_EXITCODE"
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

mode_jobs() {
    WARN=${WARN:-1}
    CRIT=${CRIT:-2}

    total_jobs=0
    declare -i total_failed_count=0
    declare -i job_fail_count
    data=$(getJSON "get jobs $kubectl_ns" "apis/batch/v1$api_ns/jobs/")
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
            jobs=("$NAME")
        else
            jobs=($(echo "$data" | \
                            jq -r ".items[] | select(.metadata.namespace==\"$ns\") | \
                                   .metadata.name"))
        fi
        for job in "${jobs[@]}"; do
            ((total_jobs++))
            job_fail_count=$(echo "$data" | jq -r ".items[] | select(.status.failed and .metadata.name==\"$job\") | .status.failed")
            total_failed_count="$((total_failed_count+job_fail_count))"
            if [ "$job_fail_count" -ge "${WARN}" ]; then
                OUTPUT="${OUTPUT}Job $job has $job_fail_count failures\n"
                EXITCODE=1
            elif [ "$job_fail_count" -ge "${CRIT}" ]; then
                EXITCODE=2
            fi
        done
        if [ "$total_failed_count" -ge "${CRIT}" ]; then
            EXITCODE=2
        elif [ "$total_failed_count" -ge "${WARN}" ]; then
            EXITCODE=1
        fi
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z "$ns" ]; then
            OUTPUT="No jobs found"
        else
            OUTPUT="OK. $total_jobs checked. ${total_failed_count} failed jobs is below threshold\n"
        fi
    else
        if [ "$EXITCODE" -eq 1 ] ; then
            OUTPUT="WARNING. ${OUTPUT}"
        elif [ "$EXITCODE" -ge 2 ] ; then
            OUTPUT="CRITICAL. ${OUTPUT}"
        fi
        if [ -z "$NAME" ] && [ "$EXITCODE" -ge 1 ] ; then
            OUTPUT="${OUTPUT}${total_failed_count} jobs have failed"
        fi
    fi
}

case "$MODE" in
    (apiserver) mode_apiserver ;;
    (daemonsets) mode_daemonsets ;;
    (deployments) mode_deployments ;;
    (nodes) mode_nodes ;;
    (unboundpvs) mode_unboundpvs ;;
    (pods) mode_pods ;;
    (replicasets) mode_replicasets ;;
    (statefulsets) mode_statefulsets ;;
    (tls) mode_tls ;;
    (jobs) mode_jobs ;;
    (pvc) mode_pvc ;;
    (*) usage ;;
esac

printf "$OUTPUT"

exit $EXITCODE
