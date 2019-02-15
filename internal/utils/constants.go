package utils

const (
	TlsCertPath                  = "/var/run/secrets/certs/tls.crt"
	TlsKeyPath                   = "/var/run/secrets/certs/tls.key"
	TlsCaFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	TokenFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	Dns1123LabelFmt       string = "^[a-z0-9][-a-z0-9]*$"
	DNS1123LabelMaxLength int    = 63
)

const (
	KubiResourcePrefix               = "kubi"
	KubiClusterRoleBindingName       = KubiResourcePrefix + "-admin"
	KubiClusterRoleBindingReaderName = KubiResourcePrefix + "-reader"
	KubiDefaultNetworkPolicyName     = KubiResourcePrefix + "-default"
	UnauthenticatedGroup             = "system:unauthenticated"

	KubiStageScratch = "scratch"
	KubiStageStaging = "staging"
	KubiStageStable  = "stable"

	KubiEnvironmentProduction  = "production"
	KubiEnvironmentIntegration = "integration"
	KubiEnvironmentDevelopment = "development"

	KubiTenantUndeterminable = "undeterminable"
)

var BlacklistedNamespaces = []string{
	"kube-system",
	"kube-public",
	"ingress-nginx",
	"default",
	KubiResourcePrefix,
}
