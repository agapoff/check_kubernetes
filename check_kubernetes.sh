#!/bin/bash

##########################
# Perform checks against Kubernetes API or with tab help of kubectl utility
# Designed for usage with Nagios, Icinga, Zabbix, Shinken... Whatever.
#
# Vitaly Agapov <v.agapov@quotix.com>
# 2018/06/28
##########################

usage() {
    echo "Usage $0 [-m <MODE>|-h] [-o <TIMEOUT>] [-H <APISERVER> [-T <TOKEN>|-t <TOKENFILE>]] [-K <KUBE_CONFIG>]"
    echo "         [-N <NAMESPACE>] [-n <NAME>] [-w <WARN>] [-c <CRIT>]"
    echo
    echo "Options are:"
    echo "  -m MODE          Which check to perform"
    echo "  -H APISERVER     API URL to query, kubectl is used if this option is not set"
    echo "  -T TOKEN         Authorization token for API"
    echo "  -t TOKENFILE     Path to file with token in it"
    echo "  -K KUBE_CONFIG   Path to kube-config file for kubectl utility"
    echo "  -N NAMESPACE     Optional namespace for some modes. By default all namespaces will be used"
    echo "  -n NAME          Optional deployment name or pod app label depending on the mode being used. By default all objects will be checked"
    echo "  -o TIMEOUT       Timeout in seconds; default is 15"
    echo "  -w WARN          Warning threshold for TLS expiration days and for pod restart count (in pods mode); default is 30"
    echo "  -c CRIT          Critical threshold for pod restart count (in pods mode); default is 150"
    echo "  -b               Brief mode (more suitable for Zabbix)"
    echo "  -h               Show this help and exit"
    echo
    echo "Modes are:"
    echo "  apiserver        Not for kubectl, should be used for each apiserver independently"
    echo "  components       Check for health of k8s components (etcd, controller-manager, scheduler etc.)"
    echo "  nodes            Check for active nodes"
    echo "  pods             Check for restart count of containters in the pods"
    echo "  deployments      Check for deployments availability"
    echo "  daemonsets       Check for daemonsets readiness"
    echo "  replicasets      Check for replicasets readiness"
    echo "  statefulsets     Check for statefulsets readiness"
    echo "  tls              Check for tls secrets expiration dates"

    exit 2
}

BRIEF=0
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

[ -z $MODE ] && usage
if [ "$APISERVER" ]; then
    [ -z "$TOKEN" -a -z "$TOKENFILE" ] && usage
else
    type kubectl >/dev/null 2>&1 || { echo "CRITICAL: kubectl is required as api-server is not defined"; exit 2; }
fi
type jq >/dev/null 2>&1 || { echo "CRITICAL: jq is required"; exit 2; }
TIMEOUT=${TIMEOUT:-15}

getJSON() {
    kubectl_command=$1
    api_path=$2
    if [ "$APISERVER" ]; then
        if [ -z $TOKEN ]; then
            TOKEN=$(cat $TOKENFILE)
        fi
        data=$(timeout $TIMEOUT curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/$api_path)
        code=$?
        if [ $code = 124 ]; then
            echo "Timed out after $TIMEOUT seconds"
            return 2
        fi
        if [[ "$api_path" =~ healthz ]]; then
            echo $data
            return
        fi
        kind=$(echo "$data" | jq -r '.kind')
        if [ "$kind" = Status ]; then
            message=$(echo "$data" | jq -r '.message')
            echo "API call failed: $message"
            return 2
        elif [ -z "$kind" ]; then
            echo "Could not access API"
            return 2
        fi
    else
        data=$(timeout $TIMEOUT kubectl $kubectl_command -o json 2>&1)
        code=$?
        if [ $code -gt 0 ]; then
            if [ $code = 124 ]; then
                echo "Timed out after $TIMEOUT seconds"
            else
                echo $data | sed 's/^{.*}//'
            fi
            return 2
        fi
    fi
    echo $data
}

OUTPUT=""
EXITCODE=0

if [ $MODE = nodes ]; then
    data=$(getJSON "get nodes" "api/v1/nodes")
    if [ $? -gt 0 ]; then
        # Some error occurred during calling API or executing kubectl
        echo $data
        exit 2
    fi
    #echo "$data"
    nodes=($(echo "$data" | jq -r '.items[].metadata.name'))
    for node in ${nodes[@]}; do
        nodeoutput=""
        ready=$(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$node'")| .status.conditions[] | select(.type=="Ready") | .status')
        if [ "$ready" != True ]; then
            EXITCODE=2
                OUTPUT="${OUTPUT}Node $node not ready. "
        fi
        for condition in OutOfDisk MemoryPressure DiskPressure; do
            state=$(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$node'") | .status.conditions[] | select(.type=="'$condition'") | .status')
            if [ "$state" = True ]; then
                [ $EXITCODE -lt 1 ] && EXITCODE=1
                OUTPUT="$OUTPUT $node $condition."
            fi
        done
    done
    
    if [ $EXITCODE = 0 ]; then
        if [ -z $nodes ]; then
            OUTPUT="No nodes found"
            EXITCODE=2
        else
            OUTPUT="OK. ${#nodes[@]} nodes are Ready"
        fi
    fi
    if [ $BRIEF = 1 ]; then
	    if [ $EXITCODE = 0 ]; then
		    OUTPUT="${#nodes[@]}"
	    elif [ $EXITCODE = 2 ]; then
		    OUTPUT="0"
	    else
		    OUTPUT="-1"
	    fi
    fi

elif [ $MODE = components ]; then
    healthy_comps=""
    unhealthy_comps=""
    data=$(getJSON "get cs" "api/v1/componentstatuses")
    if [ $? -gt 0 ]; then
        echo $data
        exit 2
    fi
    components=($(echo "$data" | jq -r '.items[].metadata.name'))
    for comp in ${components[@]}; do
        healthy=$(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$comp'")| .conditions[] | select(.type=="Healthy") | .status')
        if [ "$healthy" != True ]; then
            EXITCODE=2
            unhealthy_comps="$unhealthy_comps $comp"
        else
            healthy_comps="$healthy_comps $comp"
        fi
    done
    
    if [ $EXITCODE = 0 ]; then
        if [ -z $components ]; then
            OUTPUT="No components found"
            EXITCODE=2
        else
            OUTPUT="OK. Healthy: $healthy_comps"
        fi
    else
        OUTPUT="CRITICAL. Unhealthy: $unhealthy_comps; Healthy: $healthy_comps"
    fi
    if [ $BRIEF = 1 ]; then
	    if [ $EXITCODE = 0 ]; then
		    OUTPUT="$healthy_comps"
	    else
		    OUTPUT="0"
	    fi
    fi

elif [ $MODE = tls ]; then
    WARN=${WARN:-30}

    count_ok=0
    count_warn=0
    count_crit=0
    nowdate=$(date +%s)
    if [ "$NAMESPACE" ]; then
        api_ns="/namespaces/$NAMESPACE"
        kubectl_ns="--namespace=$NAMESPACE"
    else
        kubectl_ns="--all-namespaces"
    fi
    fulldata=$(getJSON "get secrets $kubectl_ns" "api/v1$api_ns/secrets/")
    if [ $? -gt 0 ]; then
        # Some error occurred during calling API or executing kubectl
        echo $fulldata
        exit 2
    fi
    data=$(echo "$fulldata" | jq -r '.items[] | select (.type=="kubernetes.io/tls")')
    #echo $data
    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r 'select(.metadata.name=="'$NAME'") | .metadata.namespace' | sort -u))
    else
        namespaces=($(echo "$data" | jq -r '.metadata.namespace' | sort -u))
    fi
    for ns in ${namespaces[@]}; do
        if [ "$NAME" ]; then
            certs=($NAME)
        else
            certs=($(echo "$data" | jq -r 'select(.metadata.namespace=="'$ns'") | .metadata.name'))
        fi
        for cert in ${certs[@]}; do
            notafter=$(echo "$data" | jq -r 'select(.metadata.namespace=="'$ns'" and .metadata.name=="'$cert'") | .data."tls.crt"' | base64 -d | openssl x509 -enddate -noout | sed 's/notAfter=//')
            enddate=$(date -d "$notafter" +%s)
            diff="$(($enddate-$nowdate))"

            if [ "$diff" -le 0 ]; then
                ((count_crit++))
                EXITCODE=2
                OUTPUT="$OUTPUT $ns/$cert is expired."
            elif [ "$diff" -le "$((${WARN}*24*3600))" ]; then
                ((count_warn++))
                if [ "$EXITCODE" == 0 ]; then
                    EXITCODE=1
                fi
                OUTPUT="$OUTPUT $ns/$cert is about to expire in $((${diff}/3600/24)) days."
            else
                ((count_ok++))
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z $ns ]; then
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
    if [ $BRIEF = 1 ]; then
	    OUTPUT="$count_ok"
    fi

elif [ $MODE = deployments ]; then
    count_avail=0
    count_failed=0
    if [ "$NAMESPACE" ]; then
        api_ns="/namespaces/$NAMESPACE"
        kubectl_ns="--namespace=$NAMESPACE"
    else
        kubectl_ns="--all-namespaces"
    fi
    data=$(getJSON "get deployments $kubectl_ns" "apis/apps/v1$api_ns/deployments/")
    if [ $? -gt 0 ]; then
        # Some error occurred during calling API or executing kubectl
        echo $data
        exit 2
    fi
    #echo $data
    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$NAME'") | .metadata.namespace' | sort -u))
    else
        namespaces=($(echo "$data" | jq -r '.items[].metadata.namespace' | sort -u))
    fi
    for ns in ${namespaces[@]}; do
        if [ "$NAME" ]; then
            deps=($NAME)
        else
            deps=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'") | .metadata.name'))
        fi
        for dep in ${deps[@]}; do
            avail=$(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$dep'") | .status.conditions[] | select(.type=="Available") | .status')
            if [ "$avail" != True ]; then
                ((count_failed++))
                EXITCODE=2
                OUTPUT="Deployment $ns/$dep"
            else
                ((count_avail++))
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z $ns ]; then
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
    if [ $BRIEF = 1 ]; then
	    OUTPUT="$count_avail"
    fi

elif [ $MODE = daemonsets ]; then
    count_avail=0
    count_failed=0
    if [ "$NAMESPACE" ]; then
        api_ns="/namespaces/$NAMESPACE"
        kubectl_ns="--namespace=$NAMESPACE"
    else
        kubectl_ns="--all-namespaces"
    fi
    data=$(getJSON "get ds $kubectl_ns" "apis/apps/v1$api_ns/daemonsets/")
    if [ $? -gt 0 ]; then
        # Some error occurred during calling API or executing kubectl
        echo $data
        exit 2
    fi
    #echo $data
    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$NAME'") | .metadata.namespace' | sort -u))
    else
        namespaces=($(echo "$data" | jq -r '.items[].metadata.namespace' | sort -u))
    fi
    for ns in ${namespaces[@]}; do
        if [ "$NAME" ]; then
            daemonsets=($NAME)
        else
            daemonsets=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'") | .metadata.name'))
        fi
        for ds in ${daemonsets[@]}; do
            declare -A statusArr
            while IFS="=" read -r key value; do
               statusArr[$key]="$value"
            done < <(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$ds'") | .status | to_entries|map("\(.key)=\(.value)")|.[]')
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

    if [ $EXITCODE = 0 ]; then
        if [ -z $ns ]; then
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
    if [ $BRIEF = 1 ]; then
	    OUTPUT="$count_avail"
    fi

elif [ $MODE = pods ]; then
    WARN=${WARN:-30}
    CRIT=${CRIT:-150}
    if [ $WARN -gt $CRIT ]; then
        WARN=$CRIT
    fi

    count_ready=0
    count_failed=0
    max_restart_count=0
    bad_container=""
    if [ "$NAMESPACE" ]; then
        api_ns="/namespaces/$NAMESPACE"
        kubectl_ns="--namespace=$NAMESPACE"
    else
        kubectl_ns="--all-namespaces"
    fi
    data=$(getJSON "get pods $kubectl_ns" "api/v1$api_ns/pods/")
    if [ $? -gt 0 ]; then
        # Some error occurred during calling API or executing kubectl
        echo $data
        exit 2
    fi
    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r '.items[] | select(.metadata.labels.app=="'$NAME'") | .metadata.namespace' | sort -u))
    else
        namespaces=($(echo "$data" | jq -r '.items[].metadata.namespace' | sort -u))
    fi
    for ns in ${namespaces[@]}; do
        if [ "$NAME" ]; then
            pods=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .status.reason!="Evicted" and .metadata.labels.app=="'$NAME'") | .metadata.name'))
        else
            pods=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .status.reason!="Evicted") | .metadata.name'))
        fi
        for pod in ${pods[@]}; do
            containers=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$pod'") | .status.containerStatuses[].name'))
            for container in ${containers[@]}; do
                restart_count=$(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$pod'") | .status.containerStatuses[] | select(.name=="'$container'") | .restartCount')
                if [ $restart_count -gt $max_restart_count ]; then
                    bad_container="$ns/$pod/$container"
                    max_restart_count=$restart_count
                fi
            done
            ready=$(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$pod'") | .status.conditions[] | select(.type=="Ready") | .status')
            if [ "$ready" != True ]; then
                ((count_failed++))
            else
                ((count_ready++))
            fi
        done
    done

    if [ -z $ns ]; then
        OUTPUT="No pods found"
        EXITCODE=2
    else
        if [ $max_restart_count -ge $WARN ]; then
            OUTPUT="Container $bad_container: $max_restart_count restarts. "
            EXITCODE=1
            if [ $max_restart_count -ge $CRIT ]; then
                EXITCODE=2
            fi
        fi
        OUTPUT="$OUTPUT$count_ready pods ready, $count_failed pods not ready"
    fi
    if [ $BRIEF = 1 ]; then
	    if [ $max_restart_count -ge $WARN ]; then
		    OUTPUT="-$max_restart_count"
	    else
		    OUTPUT="$count_ready"
	    fi
    fi

elif [ $MODE = apiserver ]; then
    if [ -z $APISERVER ]; then
        echo "Apiserver URL should be defined in this mode"
        exit 2
    fi
    data=$(getJSON "" "healthz")
    if [ $? -gt 0 ]; then
        OUTPUT="$data"
        EXITCODE=2
    elif [ "$data" = ok ]; then
        OUTPUT="OK. Kuberenetes apiserver health is OK"
        EXITCODE=0
    else
        OUTPUT="CRITICAL. Kuberenetes apiserver health is $data"
        EXITCODE=2
    fi
    if [ $BRIEF = 1 ]; then
	    if [ $EXITCODE = 0 ]; then
		    OUTPUT="1"
	    else
		    OUTPUT="0"
	    fi
    fi

elif [ $MODE = replicasets ]; then
    count_avail=0
    count_failed=0
    if [ "$NAMESPACE" ]; then
        api_ns="/namespaces/$NAMESPACE"
        kubectl_ns="--namespace=$NAMESPACE"
    else
        kubectl_ns="--all-namespaces"
    fi
    data=$(getJSON "get rs $kubectl_ns" "apis/apps/v1$api_ns/replicasets/")
    if [ $? -gt 0 ]; then
	    # Some error occurred during calling API or executing kubectl
	    if [ $BRIEF = 1 ]; then
		    echo "-1"
	    else
		    echo $data
	    fi
	    exit 2
    fi

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$NAME'") | .metadata.namespace' | sort -u))
    else
        namespaces=($(echo "$data" | jq -r '.items[].metadata.namespace' | sort -u))
    fi
    for ns in ${namespaces[@]}; do
        if [ "$NAME" ]; then
            replicasets=($NAME)
        else
            replicasets=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'") | .metadata.name'))
        fi
        for rs in ${replicasets[@]}; do
            declare -A statusArr
            while IFS="=" read -r key value; do
               statusArr[$key]="$value"
            done < <(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$rs'") | .status | to_entries|map("\(.key)=\(.value)")|.[]')
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
        if [ -z $ns ]; then
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
    if [ $BRIEF = 1 ]; then
	    OUTPUT="$count_avail"
    fi

elif [ $MODE = statefulsets ]; then
    count_avail=0
    count_failed=0
    if [ "$NAMESPACE" ]; then
        api_ns="/namespaces/$NAMESPACE"
        kubectl_ns="--namespace=$NAMESPACE"
    else
        kubectl_ns="--all-namespaces"
    fi
    data=$(getJSON "get rs $kubectl_ns" "apis/apps/v1$api_ns/statefulsets/")
    if [ $? -gt 0 ]; then
	    # Some error occurred during calling API or executing kubectl
	    if [ $BRIEF = 1 ]; then
		    echo "-1"
	    else
		    echo $data
	    fi
	    exit 2
    fi

    if [ "$NAME" ]; then
        namespaces=($(echo "$data" | jq -r '.items[] | select(.metadata.name=="'$NAME'") | .metadata.namespace' | sort -u))
    else
        namespaces=($(echo "$data" | jq -r '.items[].metadata.namespace' | sort -u))
    fi
    for ns in ${namespaces[@]}; do
        if [ "$NAME" ]; then
            statefulsets=($NAME)
        else
            statefulsets=($(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'") | .metadata.name'))
        fi
        for rs in ${statefulsets[@]}; do
            declare -A statusArr
            while IFS="=" read -r key value; do
               statusArr[$key]="$value"
            done < <(echo "$data" | jq -r '.items[] | select(.metadata.namespace=="'$ns'" and .metadata.name=="'$rs'") | .status | to_entries|map("\(.key)=\(.value)")|.[]')
            OUTPUT="Statefulset $ns/$rs ${statusArr[readyReplicas]}/${statusArr[currentReplicas]} ready"
            if [ "${statusArr[readyReplicas]}" != "${statusArr[currentReplicas]}" ]; then
                ((count_failed++))
                EXITCODE=2
            else
                ((count_avail++))
            fi
        done
    done

    if [ $EXITCODE = 0 ]; then
        if [ -z $ns ]; then
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
    if [ $BRIEF = 1 ]; then
	    OUTPUT="$count_avail"
    fi

else
    usage
fi

echo $OUTPUT
exit $EXITCODE
