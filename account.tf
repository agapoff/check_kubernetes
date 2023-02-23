resource "kubernetes_namespace_v1" "monitoring" {
  metadata {
    annotations = {
      name = "monitoring"
    }

    name = "monitoring"
  }
}

resource "kubernetes_service_account_v1" "monitoring" {
  metadata {
    name      = "monitoring"
    namespace = kubernetes_namespace_v1.monitoring.metadata.0.name
  }

  secret {
    name = "monitoring"
  }
}

resource "kubernetes_secret_v1" "monitoring" {
  depends_on = [
    kubernetes_service_account_v1.monitoring
  ]

  metadata {
    name      = "monitoring"
    namespace = kubernetes_namespace_v1.monitoring.metadata.0.name

    annotations = {
      "kubernetes.io/service-account.name"      = "monitoring"
      "kubernetes.io/service-account.namespace" = "monitoring"
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "kubernetes_cluster_role_v1" "monitoring" {
  metadata {
    name = "monitoring"
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "nodes", "secrets", "persistentvolumes"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["extensions", "apps"]
    resources  = ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["batch"]
    resources  = ["jobs"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "monitoring" {
  metadata {
    name = "monitoring"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "monitoring"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "monitoring"
    namespace = kubernetes_namespace_v1.monitoring.metadata.0.name
  }
}
