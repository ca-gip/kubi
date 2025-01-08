package project

const (
	DNS1123LabelMaxLength             int    = 63
	Dns1123LabelFmt                   string = "^[a-z0-9][-a-z0-9]*$"
	KubiResourcePrefix                       = "kubi"
	KubiEnvironmentProduction                = "production"
	KubiEnvironmentShortProduction           = "prd"
	KubiEnvironmentIntegration               = "integration"
	KubiEnvironmentShortInt                  = "int"
	KubiEnvironmentUAT                       = "uat"
	KubiEnvironmentPreproduction             = "preproduction"
	KubiEnvironmentShortPreproduction        = "pprd"
	KubiEnvironmentDevelopment               = "development"
	KubiEnvironmentShortDevelopment          = "dev"
)

// TODO: Sort this and use the same names!
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

var WhitelistedRoles = []string{
	"admin",
	"service",
	"user",
}

// TODO: Make this dynamic
var BlacklistedNamespaces = []string{
	"kube-system",
	"kube-public",
	"ingress-nginx",
	"admin",
	"default",
	KubiResourcePrefix,
}

var EnvironmentNamesMapping = map[string]string{
	KubiEnvironmentShortDevelopment:   KubiEnvironmentDevelopment,
	KubiEnvironmentShortInt:           KubiEnvironmentIntegration,
	KubiEnvironmentUAT:                KubiEnvironmentUAT,
	KubiEnvironmentShortPreproduction: KubiEnvironmentPreproduction,
	KubiEnvironmentShortProduction:    KubiEnvironmentProduction,
}
