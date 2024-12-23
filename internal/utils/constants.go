package utils

const (
	// TODO Add Environment variable
	ECDSAPublicPath              = "/var/run/secrets/ecdsa/ecdsa-public.pem"
	ECDSAKeyPath                 = "/var/run/secrets/ecdsa/ecdsa-key.pem"
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
	"admin",
	"default",
	KubiResourcePrefix,
}

var WhitelistedRoles = []string{
	"admin",
	"service",
	"user",
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
