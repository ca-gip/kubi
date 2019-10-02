package utils

const (
	ECDSAPublicPath              = "/var/run/secrets/certs/ecdsa-public.pem"
	ECDSAKeyPath                 = "/var/run/secrets/certs/ecdsa-key.pem"
	TlsCertPath                  = "/var/run/secrets/certs/tls.crt"
	TlsKeyPath                   = "/var/run/secrets/certs/tls.key"
	TlsCaFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	TokenFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	Dns1123LabelFmt       string = "^[a-z0-9][-a-z0-9]*$"
	DNS1123LabelMaxLength int    = 63
)

const (
	Empty = ""

	KubiResourcePrefix = "kubi"

	KubiClusterRoleBindingReaderName = "kubi-reader"
	KubiDefaultNetworkPolicyName     = "kubi-default"

	AuthenticatedGroup = "system:authenticated"
	AdminGroup         = "system:masters"
	ApplicationMaster  = "application:masters"
	OPSMaster          = "ops:masters"

	KubiStageScratch = "scratch"
	KubiStageStaging = "staging"
	KubiStageStable  = "stable"

	KubiLocatorIntranet = "intranet"
	KubiLocatorExtranet = "extranet"

	KubiEnvironmentProduction         = "production"
	KubiEnvironmentShortProduction    = "prd"
	KubiEnvironmentIntegration        = "integration"
	KubiEnvironmentShortInt           = "int"
	KubiEnvironmentUAT                = "uat"
	KubiEnvironmentPreproduction      = "preproduction"
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

var AllEnvironments = []string{
	KubiEnvironmentProduction,
	KubiEnvironmentShortProduction,
	KubiEnvironmentIntegration,
	KubiEnvironmentShortInt,
	KubiEnvironmentUAT,
	KubiEnvironmentPreproduction,
	KubiEnvironmentShortPreproduction,
	KubiEnvironmentDevelopment,
	KubiEnvironmentShortDevelopment,
}

var LdapMapping = map[string]string{
	KubiEnvironmentShortDevelopment:   KubiEnvironmentDevelopment,
	KubiEnvironmentShortInt:           KubiEnvironmentIntegration,
	KubiEnvironmentUAT:                KubiEnvironmentUAT,
	KubiEnvironmentShortPreproduction: KubiEnvironmentPreproduction,
	KubiEnvironmentShortProduction:    KubiEnvironmentProduction,
}
