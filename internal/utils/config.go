package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ca-gip/kubi/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/rest"
	podSecurity "k8s.io/pod-security-admission/api"
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
		log.Fatalf("Cannot retrieve environment variable for Kubernetes service")
		return nil, rest.ErrNotInCluster
	}

	kubeToken, errToken := os.ReadFile(TokenFile)
	Check(errToken)

	kubeCA, errCA := os.ReadFile(TlsCaFile)
	Check(errCA)

	caEncoded := base64.StdEncoding.EncodeToString(kubeCA)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("Cannot retrieve system cert pool, exiting for security reason")
	}
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

	ldapPageSize, errLdapPageSize := strconv.Atoi(getEnv("LDAP_PAGE_SIZE", "1000"))
	Checkf(errLdapPageSize, "Invalid LDAP_PAGE_SIZE, must be an integer")

	ldapPort, errLdapPort := strconv.Atoi(getEnv("LDAP_PORT", "389"))
	Checkf(errLdapPort, "Invalid LDAP_PORT, must be an integer")

	useSSL, errLdapSSL := strconv.ParseBool(getEnv("LDAP_USE_SSL", "false"))
	Checkf(errLdapSSL, "Invalid LDAP_USE_SSL, must be a boolean")

	skipTLSVerification, errSkipTLS := strconv.ParseBool(getEnv("LDAP_SKIP_TLS_VERIFICATION", "true"))
	Checkf(errSkipTLS, "Invalid LDAP_SKIP_TLS_VERIFICATION, must be a boolean")

	startTLS, errStartTLS := strconv.ParseBool(getEnv("LDAP_START_TLS", "false"))
	Checkf(errStartTLS, "Invalid LDAP_START_TLS, must be a boolean")

	whitelist, errWhitelist := strconv.ParseBool(getEnv("WHITELIST", "false"))
	Checkf(errWhitelist, "Invalid WHITELIST, must be a boolean")

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

	networkpolicyEnabled, errNetpol := strconv.ParseBool(getEnv("PROVISIONING_NETWORK_POLICIES", "true"))
	Checkf(errNetpol, "Invalid LDAP_START_TLS, must be a boolean")

	customLabels := parseCustomLabels(getEnv("CUSTOM_LABELS", ""))

	ldapUserFilter := getEnv("LDAP_USERFILTER", "(cn=%s)")
	tenant := strings.ToLower(getEnv("TENANT", KubiTenantUndeterminable))

	// No need to state a default or crash, because kubernetes defaults to restricted.
	podSecurityAdmissionEnforcement, errPodSecurityAdmissionEnforcement := podSecurity.ParseLevel(strings.ToLower(getEnv("PODSECURITYADMISSION_ENFORCEMENT", string(podSecurity.LevelRestricted))))

	if errPodSecurityAdmissionEnforcement != nil {
		Log.Error().Msgf("PODSECURITYADMISSION_ENFORCEMENT is incorrect. %s ", errPodSecurityAdmissionEnforcement.Error())
	}

	// No need to state a default or crash, because kubernetes defaults to restricted.
	podSecurityAdmissionWarning, errPodSecurityAdmissionWarning := podSecurity.ParseLevel(strings.ToLower(getEnv("PODSECURITYADMISSION_WARNING", string(podSecurity.LevelRestricted))))

	if errPodSecurityAdmissionWarning != nil {
		Log.Error().Msgf("PODSECURITYADMISSION_WARNING is incorrect. %s ", errPodSecurityAdmissionWarning.Error())
	}

	// No need to state a default or crash, because kubernetes defaults to restricted.
	podSecurityAdmissionAudit, errPodSecurityAdmissionAudit := podSecurity.ParseLevel(strings.ToLower(getEnv("PODSECURITYADMISSION_AUDIT", string(podSecurity.LevelRestricted))))

	if errPodSecurityAdmissionAudit != nil {
		Log.Error().Msgf("PODSECURITYADMISSION_AUDIT is incorrect. %s ", errPodSecurityAdmissionAudit.Error())
	}

	ldapConfig := types.LdapConfig{
		UserBase:             os.Getenv("LDAP_USERBASE"),
		GroupBase:            os.Getenv("LDAP_GROUPBASE"),
		AppMasterGroupBase:   getEnv("LDAP_APP_GROUPBASE", ""),
		CustomerOpsGroupBase: getEnv("LDAP_CUSTOMER_OPS_GROUPBASE", ""),
		ServiceGroupBase:     getEnv("LDAP_SERVICE_GROUPBASE", ""),
		OpsMasterGroupBase:   getEnv("LDAP_OPS_GROUPBASE", ""),
		AdminUserBase:        getEnv("LDAP_ADMIN_USERBASE", ""),
		AdminGroupBase:       getEnv("LDAP_ADMIN_GROUPBASE", ""),
		ViewerGroupBase:      getEnv("LDAP_VIEWER_GROUPBASE", ""),
		PageSize:             uint32(ldapPageSize),
		Host:                 os.Getenv("LDAP_SERVER"),
		Port:                 ldapPort,
		UseSSL:               useSSL,
		StartTLS:             startTLS,
		SkipTLSVerification:  skipTLSVerification,
		BindDN:               os.Getenv("LDAP_BINDDN"),
		BindPassword:         os.Getenv("LDAP_PASSWD"),
		UserFilter:           ldapUserFilter,
		GroupFilter:          "(member=%s)",
		Attributes:           []string{"givenName", "sn", "mail", "uid", "cn", "userPrincipalName"},
	}
	config := &types.Config{
		Tenant:                          tenant,
		PodSecurityAdmissionEnforcement: podSecurityAdmissionEnforcement,
		PodSecurityAdmissionWarning:     podSecurityAdmissionWarning,
		PodSecurityAdmissionAudit:       podSecurityAdmissionAudit,
		Ldap:                            ldapConfig,
		KubeCa:                          caEncoded,
		KubeCaText:                      string(kubeCA),
		KubeToken:                       string(kubeToken),
		PublicApiServerURL:              getEnv("PUBLIC_APISERVER_URL", ""),
		ApiServerTLSConfig:              *tlsConfig,
		TokenLifeTime:                   getEnv("TOKEN_LIFETIME", "4h"),
		ExtraTokenLifeTime:              getEnv("EXTRA_TOKEN_LIFETIME", "720h"),
		Locator:                         getEnv("LOCATOR", KubiLocatorIntranet),
		NetworkPolicy:                   networkpolicyEnabled,
		CustomLabels:                    customLabels,
		DefaultPermission:               getEnv("DEFAULT_PERMISSION", ""),
		PrivilegedNamespaces:            strings.Split(getEnv("PRIVILEGED_NAMESPACES", ""), ","),
		Blacklist:                       strings.Split(getEnv("BLACKLIST", ""), ","),
		Whitelist:                       whitelist,
		BlackWhitelistNamespace:         getEnv("BLACK_WHITELIST_NAMESPACE", "default"),
	}

	// TODO: Remove validation through ozzo-validation
	err = validation.ValidateStruct(config,
		validation.Field(&config.KubeToken, validation.Required),
		validation.Field(&config.KubeCa, validation.Required, is.Base64),
		validation.Field(&config.PublicApiServerURL, validation.Required, is.URL),
	)
	// TODO: Get rid of Check method
	Check(err)

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

// Parse CustomLabels from a string to a map holding the key value
func parseCustomLabels(rawLabels string) (labels map[string]string) {
	labelsPattern := regexp.MustCompile(`(?P<key>\w+)=(?P<value>[^,]+)`)

	if !labelsPattern.MatchString(rawLabels) {
		return map[string]string{}
	}

	matches := labelsPattern.FindAllStringSubmatch(rawLabels, -1)
	labels = make(map[string]string, len(matches))
	for _, match := range matches {
		if !(match[1] == "creator" || match[1] == "customer") {
			labels[match[1]] = match[2]
		}
	}

	return
}

// Modifier that Fix too old resource version issues
var DefaultWatchOptionModifier = func(options *v1.ListOptions) {
	options.ResourceVersion = ""
	options.FieldSelector = fields.Everything().String()
}
