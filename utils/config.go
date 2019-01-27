package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"intomy.land/kubi/ldap"
	"intomy.land/kubi/types"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

var Config *types.Config

const (
	TlsCertPath = "/var/run/secrets/certs/tls.crt"
	TlsKeyPath  = "/var/run/secrets/certs/tls.key"
	TlsCaFile   = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	SATokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

var BlacklistedNamespaces = []string{
	"kube-system",
	"kube-public",
	"ingress-nginx",
	"default",
}

// Print error and exit if error occured
func check(e error) {
	if e != nil {
		Log.Error().Err(e)
	}
}

func checkf(e error, msg string) {
	if e != nil {
		Log.Error().Msgf("%v : %v", msg, e)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func ApiPrefix() []string {
	return []string{
		"/api", "/apis", "/metrics", "/resetMetrics", "/logs", "/debug", "/healthz", "/swagger-ui", "/swaggerapi", "/ui", "/version", "/openapi", "swagger-2.0.0.pb-v1",
	}
}

// Build the configuration from environment variable
// and validate that is consistent. If false, the program exit
// with validation message. The validation is not error safe but
// it limit misconfiguration ( lack of parameter ).
func MakeConfig() (*types.Config, error) {

	// TODO, if not exists in /var/run/secrets search in ~/.kube/config
	kubeToken, errToken := ioutil.ReadFile(SATokenFile)
	check(errToken)

	kubeCA, errCA := ioutil.ReadFile(TlsCaFile)
	check(errCA)

	caEncoded := base64.StdEncoding.EncodeToString(kubeCA)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if ok := rootCAs.AppendCertsFromPEM(kubeCA); !ok {
		log.Fatalf("Cannot add Kubernetes CA, exiting for security reason")
	}

	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// LDAP validation
	ldapPort, errLdapPort := strconv.Atoi(getEnv("LDAP_PORT", "389"))
	checkf(errLdapPort, "Invalid LDAP_PORT, must be an integer")

	useSSL, errLdapSSL := strconv.ParseBool(getEnv("LDAP_USE_SSL", "false"))
	checkf(errLdapSSL, "Invalid LDAP_USE_SSL, must be a boolean")

	skipTLS, errSkipTLS := strconv.ParseBool(getEnv("LDAP_SKIP_TLS", "true"))
	checkf(errSkipTLS, "Invalid LDAP_SKIP_TLS, must be a boolean")

	if len(os.Getenv("LDAP_PORT")) > 0 {
		envLdapPort, err := strconv.Atoi(os.Getenv("LDAP_PORT"))
		check(err)
		ldapPort = envLdapPort
		if ldapPort == 389 && os.Getenv("LDAP_SKIP_TLS") == "false" {
			skipTLS = false
		}
		if ldapPort == 636 && os.Getenv("LDAP_SKIP_TLS") == "false" {
			skipTLS = false
			useSSL = true
		}
	}

	ldapConfig := types.LdapConfig{
		UserBase:     os.Getenv("LDAP_USERBASE"),
		GroupBase:    os.Getenv("LDAP_GROUPBASE"),
		Host:         os.Getenv("LDAP_SERVER"),
		Port:         ldapPort,
		UseSSL:       useSSL,
		SkipTLS:      skipTLS,
		BindDN:       os.Getenv("LDAP_BINDDN"),
		BindPassword: os.Getenv("LDAP_PASSWD"),
		UserFilter:   "(cn=%s)",
		GroupFilter:  "(member=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid", "cn"},
	}
	config := &types.Config{
		Ldap:               ldapConfig,
		KubeCa:             caEncoded,
		KubeCaText:         string(kubeCA),
		KubeToken:          string(kubeToken),
		ApiServerURL:       getEnv("APISERVER_URL", "10.96.0.1:443"),
		ApiServerTLSConfig: *tlsConfig,
		TokenLifeTime:      getEnv("TOKEN_LIFETIME", "4h"),
	}

	err := validation.ValidateStruct(config,
		validation.Field(&config.ApiServerURL, validation.Required, is.URL),
		validation.Field(&config.KubeToken, validation.Required),
		validation.Field(&config.KubeCa, validation.Required, is.Base64),
		validation.Field(&config.ApiServerURL, validation.Required, is.URL),
	)
	errLdap := validation.ValidateStruct(&ldapConfig,
		validation.Field(&ldapConfig.UserBase, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.GroupBase, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.Host, validation.Required, is.URL),
		validation.Field(&ldapConfig.BindDN, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.BindPassword, validation.Required, validation.Length(2, 200)),
	)

	if err != nil {
		Log.Error().Err(err)
		return nil, err
	}
	if errLdap != nil {
		Log.Error().Msgf(strings.Replace(errLdap.Error(), "; ", "\n", -1))
		return nil, err
	}
	return config, nil
}

// Generate a new LDAP Client to make
// Bind or Group search
func LdapClient() *ldap.LDAPClient {
	return &ldap.LDAPClient{
		UserBase:     Config.Ldap.UserBase,
		GroupBase:    Config.Ldap.GroupBase,
		Host:         Config.Ldap.Host,
		Port:         Config.Ldap.Port,
		SkipTLS:      Config.Ldap.SkipTLS,
		UseSSL:       Config.Ldap.UseSSL,
		BindDN:       Config.Ldap.BindDN,
		BindPassword: Config.Ldap.BindPassword,
		UserFilter:   Config.Ldap.UserFilter,
		GroupFilter:  Config.Ldap.GroupFilter,
		Attributes:   Config.Ldap.Attributes,
	}
}
