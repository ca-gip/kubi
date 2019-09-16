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
	KubiResourcePrefix = "kubi"

	KubiClusterRoleBindingReaderName = "kubi-reader"
	KubiDefaultNetworkPolicyName     = "kubi-default"

	AuthenticatedGroup = "system:authenticated"
	AdminGroup         = "system:masters"

	KubiStageScratch = "scratch"
	KubiStageStaging = "staging"
	KubiStageStable  = "stable"

	KubiEnvironmentProduction         = "production"
	KubiEnvironmentShortProduction    = "prd"
	KubiEnvironmentIntegration        = "integration"
	KubiEnvironmentShortInt           = "int"
	KubiEnvironmentUAT                = "uat"
	KubiEnvironmentPreproduction      = "pre-production"
	KubiEnvironmentShortPreproduction = "pprd"
	KubiEnvironmentDevelopment        = "development"
	KubiEnvironmentShortDevelopment   = "dev"

	KubiTenantUndeterminable = "undeterminable"
)

var BlacklistedNamespaces = []string{
	"kube-system",
	"kube-public",
	"ingress-nginx",
	"default",
	KubiResourcePrefix,
}

var LdapNsMapping = map[string][]string{
	KubiEnvironmentDevelopment:   []string{KubiEnvironmentDevelopment, KubiEnvironmentShortDevelopment},
	KubiEnvironmentIntegration:   []string{KubiEnvironmentIntegration, KubiEnvironmentShortInt},
	KubiEnvironmentUAT:           []string{KubiEnvironmentUAT},
	KubiEnvironmentPreproduction: []string{KubiEnvironmentPreproduction, KubiEnvironmentShortPreproduction},
	KubiEnvironmentProduction:    []string{KubiEnvironmentProduction, KubiEnvironmentShortProduction},
}
