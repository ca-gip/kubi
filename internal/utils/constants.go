package utils

const (
	// TODO Add Environment variable
	ECDSAPublicPath = "/var/run/secrets/ecdsa/ecdsa-public.pem"
	ECDSAKeyPath    = "/var/run/secrets/ecdsa/ecdsa-key.pem"
	TlsCertPath     = "/var/run/secrets/certs/tls.crt"
	TlsKeyPath      = "/var/run/secrets/certs/tls.key"
	TlsCaFile       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	TokenFile       = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	KubiClusterRoleBindingReaderName = "kubi-reader"
	KubiDefaultNetworkPolicyName     = "kubi-default"

	KubiClusterRoleAppName    = "namespaced-service"
	KubiRoleBindingAppName    = "namespaced-service-binding"
	KubiServiceAccountAppName = "service"

	KubiRoleBindingDefaultName    = "default-sa"
	KubiServiceAccountDefaultName = "default"

	AuthenticatedGroup = "system:authenticated"

	ApplicationMaster = "application:masters"
	ApplicationViewer = "application:view"
	OPSMaster         = "ops:masters"

	KubiStageScratch = "scratch"
	KubiStageStaging = "staging"
	KubiStageStable  = "stable"

	KubiLocatorIntranet = "intranet"
	KubiLocatorExtranet = "extranet"

	KubiTenantUndeterminable = "undeterminable"
)
