# CHECK_KUBERNETES

Nagios-style checks against Kubernetes API. Designed for usage with Nagios, Icinga, Zabbix... Whatever.

## Dependencies

 * jq
 * openssl
 * bc (for mode pvc)

## Script usage

	Usage $0 [-m <MODE>|-h] [-o <TIMEOUT>] [-H <APISERVER> [-T <TOKEN>|-t <TOKENFILE>]] [-K <KUBE_CONFIG>]
	         [-N <NAMESPACE>] [-n <NAME>] [-w <WARN>] [-c <CRIT>] [-v]

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
	                    - API cert expiration days for apicert mode; default is 30
	  -c CRIT          Critical threshold for
	                    - Pod restart count (in pods mode); default is 150
	                    - Unbound Persistent Volumes in unboundpvs mode; default is 5
	                    - Job failed count in jobs mode; default is 2
	                    - Pvc storage utilization; default is 90%
	                    - API cert expiration days for apicert mode; default is 15
	  -M EXIT_CODE     Exit code when resource is missing; default is 2 (CRITICAL)
	  -v               Show current Version
	  -h               Show this help and exit

	Modes are:
	  apiserver        Not for kubectl, should be used for each apiserver independently
	  apicert          Check the apicert expiration date
	  nodes            Check for active nodes
	  daemonsets       Check for daemonsets readiness
	  deployments      Check for deployments availability
	  jobs             Check for failed jobs
	  pods             Check for restart count of containters in the pods
	  replicasets      Check for replicasets readiness
	  statefulsets     Check for statefulsets readiness
	  tls              Check for tls secrets expiration dates
	  pvc              Check for pvc utilization
	  unboundpvs       Check for unbound persistent volumes.
	  components       Check for health of k8s components (Deprecated in K8s 1.19+)

## Examples:

Check apiserver health using tokenfile:

    ./check_kubernetes.sh -m apiserver -H https://<...>:6443 -t /path/to/tokenfile
    OK. Kubernetes apiserver health is OK

Check whether all deployments are available using token:

    ./check_kubernetes.sh -m deployments -H https://<...>:6443 -T eYN6...
    OK. 27 deploymens are available

Check one definite deployment using kubectl:

    ./check_kubernetes.sh -m deployments -K /path/to/kube_config -N ingress-nginx -n nginx-ingress-controller
    OK. Deployment available

Check nodes using kubectl with default kube config:

    ./check_kubernetes.sh -m nodes -H https://<...>:6443
    OK. 4 nodes are Ready

Check pods (by the restarts count):

    ./check_kubernetes.sh -m pods -H https://<...>:6443 -N kube-system -w 5
    WARNING. Container kube-system/calico-node-5kc4n/calico-node: 6 restarts. 22 pods ready, 0 pods not ready

Check daemonstets (compare number of desired and number of ready pods):

    ./check_kubernetes.sh -m daemonsets -K ~/.kube/cluster -N monitoring
    OK. Daemonset monitoring/node-exporter 5/5 ready
    
Check replicasets (compare number of desired and number of ready pods):

    ./check_kubernetes.sh -m replicasets -K ~/.kube/cluster -N monitoring
    OK. Replicaset monitoring/node-exporter 5/5 ready

Check statefulsets (compare number of desired and number of ready pods):

    ./check_kubernetes.sh -m statefulsets -K ~/.kube/cluster -N monitoring
    OK. Statefulset monitoring/node-exporter 5/5 ready

Check TLS certs:

    ./check_kubernetes.sh -m tls -H https://<...>:6443 -T $TOKEN -N kube-system
    kube-system/k8s-local-cert is about to expire in 18 days

Check failed jobs with any name:

    ./check_kubernetes.sh -m jobs
    CRITICAL. Job bad has 5 failures. Job bad2 has 4 failures. 9 jobs in total have failed

Checked failed jobs named 'good':

    ./check_kubernetes.sh -m jobs -n good
    OK: 0 failed jobs is below threshold

Check utilization if pvc (if consumes more than %):

    ./check_kubernetes.sh -m pvc
    CRITICAL. Very high storage utilization on pvc prometheus-data: 93% (86106636288/157459890176 Bytes)

Check expiration date for API TLS certificate:
    ./check_kubernetes.sh -m apicert -H https://<...>:6443 -T $TOKEN
    OK. API cert expires in 278 days


## Brief mode (removed in v1.1.0)

All modes support the -b brief option.  In this mode, a single numerical output is returned.  The number is positive on success and zero or negative on error.

For boolean checks, 1 is returned on success and 0 on error.

For numerical checks, the number is returned on success and zero or a negative number on error.  For example, when used with pods, the number of pods is returned, but minus the number of restarts if it exceeds the warning threshold (so if 3 pods are ok and 1 failed, 3 is returned, but if 4 pods are ok with none failed but 157 restarts with default settings, -157 is returned).  Sometimes positivity suffices, sometimes you need to monitor the exact number.

## ServiceAccount and token

All the needed objects (ServiceAccount, Secret, ClusterRole, RoleBinding) can be created by Terraform with terraform.tf file or with this command:

    kubectl apply -f https://raw.githubusercontent.com/agapoff/check_kubernetes/master/account.yaml

For mode pvc or tls you need to enable the permissions in the yaml first. Those two can have security implications and are thus disabled by default.

Then in order to get the token just issue this command:

    kubectl -n monitoring get secret monitoring -o "jsonpath={.data.token}" | openssl enc -d -base64 -A

## Example configuration for Icinga

Command:

    object CheckCommand "check-kubernetes" {
      import "plugin-check-command"
    
      command = [ PluginDir + "/check_kubernetes.sh" ]
    
      arguments = {
        "-H" = "$kube_apiserver$"
        "-m" = "$kube_mode$"
        "-o" = "$kube_timeout$"
        "-T" = "$kube_pass$"
        "-t" = "$kube_tokenfile$"
        "-K" = "$kube_config$"
        "-N" = "$kube_ns$"
        "-n" = "$kube_name$"
        "-w" = "$kube_warn$"
        "-c" = "$kube_crit$"
      }
      vars.kube_host = "$host.address$"
      vars.kube_port = 6443
      vars.kube_scheme = "https"
      vars.kube_apiserver = "$kube_scheme$://$kube_host$:$kube_port$"
    }
    
Services:
    
    apply Service "k8s apiserver health" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "apiserver"
      assign where "k8s-master" in host.vars.roles
    }
    
    apply Service "k8s components health" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "components"
      assign where "k8s-api" in host.vars.roles
    }
    
    apply Service "k8s nodes" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "nodes"
      assign where "k8s-api" in host.vars.roles
    }
    
    apply Service "k8s deployments" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "deployments"
      assign where "k8s-api" in host.vars.roles
    }

    apply Service "k8s daemonsets" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "daemonsets"
      assign where "k8s-api" in host.vars.roles
    }
    
    apply Service "k8s replicasets" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "replicasets"
      assign where "k8s-api" in host.vars.roles
    }
    
    apply Service "k8s TLS certs" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "tls"
      assign where "k8s-api" in host.vars.roles
    }

    apply Service "k8s pvc" {
      import "generic-service"
      check_interval = 1h
      check_command = "check-kubernetes"
      vars.kube_mode = "pvc"
      assign where "k8s-api" in host.vars.roles
    }
    
    apply Service "k8s pods" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "pods"
      assign where "k8s-api" in host.vars.roles
    }
    
    apply Service "k8s ingress controller" {
      import "generic-service"
      check_command = "check-kubernetes"
      vars.kube_mode = "deployments"
      vars.kube_ns = "ingress-nginx"
      vars.kube_name = "nginx-ingress-controller"
      assign where "k8s-api" in host.vars.roles
    }
    
Host template:

    template Host "k8s-host" {
      import "generic-host"
    
      vars.kube_pass = "..."
      vars.kube_scheme = "https"
      vars.kube_port = 6443
    }
    
Hosts:
   
    # VIP address of the API     
    object Host "k8s-api" {
      import "k8s-host"
      address = "<...>"
      vars.roles = [ "k8s-api" ]
    }
    
    object Host "k8s-master1" {
      import "linux-host"
      import "k8s-host"
      address = "<...>"
      vars.roles = [ "k8s-master" ]
    }


## Licence: GNU GPL v3
