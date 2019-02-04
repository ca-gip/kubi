package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"github.com/ca-gip/kubi/types"
	"github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"io/ioutil"
	"k8s.io/client-go/rest"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var Config *types.Config

// Build the configuration from environment variable
// and validate that is consistent. If false, the program exit
// with validation message. The validation is not error safe but
// it limit misconfiguration ( lack of parameter ).
func MakeConfig() (*types.Config, error) {

	// Check cluster deployment
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, rest.ErrNotInCluster
	}

	kubeToken, errToken := ioutil.ReadFile(TokenFile)
	Check(errToken)

	kubeCA, errCA := ioutil.ReadFile(TlsCaFile)
	Check(errCA)

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
	Checkf(errLdapPort, "Invalid LDAP_PORT, must be an integer")

	useSSL, errLdapSSL := strconv.ParseBool(getEnv("LDAP_USE_SSL", "false"))
	Checkf(errLdapSSL, "Invalid LDAP_USE_SSL, must be a boolean")

	skipTLSVerification, errSkipTLS := strconv.ParseBool(getEnv("LDAP_SKIP_TLS_VERIFICATION", "true"))
	Checkf(errSkipTLS, "Invalid LDAP_SKIP_TLS_VERIFICATION, must be a boolean")

	startTLS, errStartTLS := strconv.ParseBool(getEnv("LDAP_START_TLS", "false"))
	Checkf(errStartTLS, "Invalid LDAP_START_TLS, must be a boolean")

	if len(os.Getenv("LDAP_PORT")) > 0 {
		envLdapPort, err := strconv.Atoi(os.Getenv("LDAP_PORT"))
		Check(err)
		ldapPort = envLdapPort
		if ldapPort == 389 && os.Getenv("LDAP_SKIP_TLS") == "false" {
			skipTLSVerification = false
		}
		if ldapPort == 636 && os.Getenv("LDAP_SKIP_TLS") == "false" {
			skipTLSVerification = false
			useSSL = true
		}
	}

	// Configure Network Policies
	networkConfig, errNetworkConfig := makeNetworkConfig()
	if errNetworkConfig != nil {
		Log.Error().Msg(errNetworkConfig.Error())
		return nil, errNetworkConfig
	}

	ldapUserFilter := getEnv("LDAP_USERFILTER", "(cn=%s)")

	ldapConfig := types.LdapConfig{
		UserBase:            os.Getenv("LDAP_USERBASE"),
		GroupBase:           os.Getenv("LDAP_GROUPBASE"),
		AdminUserBase:       getEnv("LDAP_ADMIN_USERBASE", ""),
		AdminGroupBase:      getEnv("LDAP_ADMIN_GROUPBASE", ""),
		Host:                os.Getenv("LDAP_SERVER"),
		Port:                ldapPort,
		UseSSL:              useSSL,
		StartTLS:            startTLS,
		SkipTLSVerification: skipTLSVerification,
		BindDN:              os.Getenv("LDAP_BINDDN"),
		BindPassword:        os.Getenv("LDAP_PASSWD"),
		UserFilter:          ldapUserFilter,
		GroupFilter:         "(member=%s)",
		Attributes:          []string{"givenName", "sn", "mail", "uid", "cn", "userPrincipalName"},
	}
	config := &types.Config{
		Ldap:                ldapConfig,
		KubeCa:              caEncoded,
		KubeCaText:          string(kubeCA),
		KubeToken:           string(kubeToken),
		PublicApiServerURL:  getEnv("PUBLIC_APISERVER_URL", ""),
		ApiServerTLSConfig:  *tlsConfig,
		TokenLifeTime:       getEnv("TOKEN_LIFETIME", "4h"),
		NetworkPolicyConfig: networkConfig,
	}

	err := validation.ValidateStruct(config,
		validation.Field(&config.KubeToken, validation.Required),
		validation.Field(&config.KubeCa, validation.Required, is.Base64),
		validation.Field(&config.PublicApiServerURL, validation.Required, is.URL),
	)
	errLdap := validation.ValidateStruct(&ldapConfig,
		validation.Field(&ldapConfig.UserBase, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.GroupBase, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.Host, validation.Required, is.URL),
		validation.Field(&ldapConfig.BindDN, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.BindPassword, validation.Required, validation.Length(2, 200)),
	)

	if err != nil {
		Log.Error().Msgf(strings.Replace(err.Error(), "; ", "\n", -1))
		return nil, err
	}
	if errLdap != nil {
		Log.Error().Msgf(strings.Replace(errLdap.Error(), "; ", "\n", -1))
		return nil, err
	}
	return config, nil
}

func makeNetworkConfig() (*types.NetworkPolicyConfig, error) {
	if !hasEnv("PROVISIONING_NETWORK_POLICIES") || os.Getenv("PROVISIONING_NETWORK_POLICIES") != "true" {

		return nil, nil
	}
	result := types.NetworkPolicyConfig{}

	// Read egress ports
	portStrings := getEnv("PROVISIONING_EGRESS_ALLOWED_PORTS", "")
	if len(portStrings) > 0 {
		portSplits := strings.Split(portStrings, ",")
		for _, port := range portSplits {
			err := validation.Validate(port, is.Port)

			if err != nil {
				Log.Error().Msg(err.Error())
				return nil, err
			}
			if len(port) > 0 {
				result.AllowedPorts = append(result.AllowedPorts, port)
			}
		}
	}

	// Read egress ports
	cidrStrings := getEnv("PROVISIONING_EGRESS_ALLOWED_CIDR", "")
	if len(cidrStrings) > 0 {
		cidrSplits := strings.Split(cidrStrings, ",")
		for _, cidr := range cidrSplits {
			err := validation.Validate(cidr, validation.Match(regexp.MustCompile("^([0-9]{1,3}\\.){3}[0-9]{1,3}\\/[0-9]{1,2}$")))
			if err != nil {
				Log.Error().Msgf("cidr %v not valid. for example 10.0.0.0/24", cidr)
				return nil, err
			}
		}
		result.AllowedCidrs = cidrSplits
	}

	// Read namespaces ingress
	namespaceStrings := getEnv("PROVISIONING_INGRESS_ALLOWED_NAMESPACES", "")
	if len(namespaceStrings) > 0 {
		namespaceSplits := strings.Split(namespaceStrings, ",")
		for _, port := range namespaceSplits {
			err := validation.Validate(port, is.DNSName)
			if err != nil {
				Log.Error().Msg(err.Error())
				return nil, err
			}
		}
		result.AllowedNamespaceLabels = namespaceSplits
	}
	return &result, nil

}
