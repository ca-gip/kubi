package utils

const (
	TlsCertPath                  = "/var/run/secrets/certs/tls.crt"
	TlsKeyPath                   = "/var/run/secrets/certs/tls.key"
	TlsCaFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	TokenFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	Dns1123LabelFmt       string = "^[a-z0-9][-a-z0-9]*$"
	DNS1123LabelMaxLength int    = 63
	Dns1123LabelErrMsg    string = "a DNS-1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character"
)

const (
	KubiResourcePrefix         = "kubi"
	KubiClusterRoleBindingName = KubiResourcePrefix + "-admin"
)

var BlacklistedNamespaces = []string{
	"kube-system",
	"kube-public",
	"ingress-nginx",
	"default",
	KubiResourcePrefix,
}

func ApiPrefix() []string {
	return []string{
		"/api", "/apis", "/metrics", "/resetMetrics", "/logs", "/debug", "/healthz", "/swagger-ui", "/swaggerapi", "/ui", "/version", "/openapi", "swagger-2.0.0.pb-v1",
	}
}
