package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ca-gip/kubi/pkg/types"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/rest"
	podSecurity "k8s.io/pod-security-admission/api"
)

var Config *types.Config

// Convenience function to default to a fallback string if the env var is not set
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Build and validates the configuration from the environment variables
// Todo: Split the makeconfig in two: One for the api+webhook, one for the operator.
func MakeConfig() (*types.Config, error) {

	// Check cluster deployment
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, rest.ErrNotInCluster
	}

	kubeToken, errToken := os.ReadFile(TokenFile)
	if errToken != nil {
		return nil, fmt.Errorf("cannot read token file %s", TokenFile)
	}

	kubeCA, errCA := os.ReadFile(TlsCaFile)
	if errCA != nil {
		return nil, fmt.Errorf("cannot read CA file %s", TlsCaFile)
	}

	// LDAP validation
	ldapUserBase := os.Getenv("LDAP_USERBASE")
	switch {
	case ldapUserBase == "":
		return nil, errors.New("userBase is required")
	case len(ldapUserBase) < 2 || len(ldapUserBase) > 200:
		return nil, fmt.Errorf("length for LDAP_USERBASE must be between 2 and 200 characters, got %v of len %v", ldapUserBase, len(ldapUserBase))
	}

	ldapGroupBase := os.Getenv("LDAP_GROUPBASE")
	switch {
	case ldapGroupBase == "":
		return nil, errors.New("groupBase is required")
	case len(ldapGroupBase) < 2 || len(ldapGroupBase) > 200:
		return nil, fmt.Errorf("length for LDAP_GROUPBASE must be between 2 and 200 characters, got %v of len %v", ldapGroupBase, len(ldapGroupBase))
	}

	ldapAllGroupsBase := os.Getenv("LDAP_ALLGROUPSBASE")
	switch {
	case ldapAllGroupsBase == "":
		return nil, errors.New("groupBase is required")
	case len(ldapAllGroupsBase) < 2 || len(ldapAllGroupsBase) > 200:
		return nil, fmt.Errorf("length for LDAP_ALLGROUPBASE must be between 2 and 200 characters, got %v of len %v", ldapAllGroupsBase, len(ldapAllGroupsBase))
	}

	concatenatedAllowList := os.Getenv("LDAP_ALLOWED_GROUPS_REGEXPS")
	if concatenatedAllowList == "" {
		return nil, errors.New("LDAP_ALLOWED_GROUPS_REGEXPS env var is mandatory")
	}
	ldapAllowedGroupRegexps := strings.Split(concatenatedAllowList, "~")

	ldapServer := os.Getenv("LDAP_SERVER")
	if ldapServer == "" {
		return nil, errors.New("host is required")
	}

	ldapBindDN := os.Getenv("LDAP_BINDDN")
	if ldapBindDN == "" {
		return nil, errors.New("BindDN is required")
	}
	if len(ldapBindDN) < 2 || len(ldapBindDN) > 200 {
		return nil, fmt.Errorf("length for LDAP_BINDDN must be between 2 and 200 characters, got %v of len %v", ldapBindDN, len(ldapBindDN))
	}

	ldapBindPassword := os.Getenv("LDAP_PASSWD")
	if ldapBindPassword == "" {
		return nil, errors.New("BindPassword is required")
	}
	if len(ldapBindPassword) < 2 || len(ldapBindPassword) > 200 {
		return nil, fmt.Errorf("length for LDAP_PASSWD must be between 2 and 200 characters, got len %v", len(ldapBindPassword))
	}

	ldapUserFilter := getEnv("LDAP_USERFILTER", "(cn=%s)")

	ldapPageSizeEnv := getEnv("LDAP_PAGE_SIZE", "1000")
	ldapPageSize, errLdapPageSize := strconv.Atoi(ldapPageSizeEnv)
	if errLdapPageSize != nil {
		return nil, fmt.Errorf("invalid LDAP_PAGE_SIZE %s, must be an integer", errLdapPageSize)
	}

	useSSL, errLdapSSL := strconv.ParseBool(getEnv("LDAP_USE_SSL", "false"))
	if errLdapSSL != nil {
		return nil, fmt.Errorf("invalid LDAP_USE_SSL %s, must be a boolean", errLdapSSL)
	}

	skipTLSVerification, errSkipTLS := strconv.ParseBool(getEnv("LDAP_SKIP_TLS_VERIFICATION", "true"))
	if errSkipTLS != nil {
		return nil, fmt.Errorf("invalid LDAP_SKIP_TLS_VERIFICATION %s, must be a boolean", errSkipTLS)
	}

	startTLS, errStartTLS := strconv.ParseBool(getEnv("LDAP_START_TLS", "false"))
	if errStartTLS != nil {
		return nil, fmt.Errorf("invalid LDAP_START_TLS %s, must be a boolean", errStartTLS)
	}

	ldapPortEnv := getEnv("LDAP_PORT", "389")
	ldapPort, err := strconv.Atoi(ldapPortEnv)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP_PORT %s, must be an integer", err)
	}
	if ldapPort == 389 && os.Getenv("LDAP_SKIP_TLS") == "false" {
		skipTLSVerification = false
	}
	if ldapPort == 636 && os.Getenv("LDAP_SKIP_TLS") == "false" {
		skipTLSVerification = false
		useSSL = true
	}

	// feature validation and parsing
	whitelist, errWhitelist := strconv.ParseBool(getEnv("WHITELIST", "false"))
	if errWhitelist != nil {
		return nil, fmt.Errorf("invalid WHITELIST %s, must be a boolean", errWhitelist)
	}

	networkpolicyEnabled, errNetpol := strconv.ParseBool(getEnv("PROVISIONING_NETWORK_POLICIES", "true"))
	if errNetpol != nil {
		return nil, fmt.Errorf("invalid PROVISIONING_NETWORK_POLICIES %s, must be a boolean", errNetpol)
	}

	customLabels := parseCustomLabels(getEnv("CUSTOM_LABELS", ""))

	tenant := strings.ToLower(getEnv("TENANT", KubiTenantUndeterminable))

	// No need to state a default or crash, because kubernetes defaults to restricted.
	podSecurityAdmissionEnforcement, errPodSecurityAdmissionEnforcement := podSecurity.ParseLevel(strings.ToLower(getEnv("PODSECURITYADMISSION_ENFORCEMENT", string(podSecurity.LevelRestricted))))

	if errPodSecurityAdmissionEnforcement != nil {
		return nil, fmt.Errorf("level for PODSECURITYADMISSION_ENFORCEMENT is incorrect. %v", errPodSecurityAdmissionEnforcement)
	}

	// No need to state a default or crash, because kubernetes defaults to restricted.
	podSecurityAdmissionWarning, errPodSecurityAdmissionWarning := podSecurity.ParseLevel(strings.ToLower(getEnv("PODSECURITYADMISSION_WARNING", string(podSecurity.LevelRestricted))))

	if errPodSecurityAdmissionWarning != nil {
		return nil, fmt.Errorf("level for PODSECURITYADMISSION_WARNING is incorrect. %v", errPodSecurityAdmissionWarning)
	}

	// No need to state a default or crash, because kubernetes defaults to restricted.
	podSecurityAdmissionAudit, errPodSecurityAdmissionAudit := podSecurity.ParseLevel(strings.ToLower(getEnv("PODSECURITYADMISSION_AUDIT", string(podSecurity.LevelRestricted))))

	if errPodSecurityAdmissionAudit != nil {
		return nil, fmt.Errorf("level for PODSECURITYADMISSION_AUDIT is incorrect. %v", errPodSecurityAdmissionAudit)
	}

	publicApiServerURL := os.Getenv("PUBLIC_APISERVER_URL")
	if publicApiServerURL == "" {
		return nil, errors.New("publicApiServerURL is required")
	}
	if _, err := url.ParseRequestURI(publicApiServerURL); err != nil {
		return nil, fmt.Errorf("publicApiServerURL must be a valid URL, got %v", err)
	}

	caEncoded := base64.StdEncoding.EncodeToString(kubeCA)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve system cert pool, exiting for security reason")
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if ok := rootCAs.AppendCertsFromPEM(kubeCA); !ok {
		return nil, fmt.Errorf("cannot add Kubernetes CA, exiting for security reason")
	}

	return &types.Config{
		Tenant:                          tenant,
		PodSecurityAdmissionEnforcement: podSecurityAdmissionEnforcement,
		PodSecurityAdmissionWarning:     podSecurityAdmissionWarning,
		PodSecurityAdmissionAudit:       podSecurityAdmissionAudit,
		Ldap: types.LdapConfig{
			UserBase:             ldapUserBase,
			AllGroupsBase:        ldapAllGroupsBase,
			AllowedGroupRegexps:  ldapAllowedGroupRegexps,
			GroupBase:            ldapGroupBase,
			AppMasterGroupBase:   getEnv("LDAP_APP_GROUPBASE", ""),
			CustomerOpsGroupBase: getEnv("LDAP_CUSTOMER_OPS_GROUPBASE", ""),
			ServiceGroupBase:     getEnv("LDAP_SERVICE_GROUPBASE", ""),
			OpsMasterGroupBase:   getEnv("LDAP_OPS_GROUPBASE", ""),
			AdminUserBase:        getEnv("LDAP_ADMIN_USERBASE", ""),
			AdminGroupBase:       getEnv("LDAP_ADMIN_GROUPBASE", ""),
			ViewerGroupBase:      getEnv("LDAP_VIEWER_GROUPBASE", ""),
			PageSize:             uint32(ldapPageSize),
			Host:                 ldapServer,
			Port:                 ldapPort,
			UseSSL:               useSSL,
			StartTLS:             startTLS,
			SkipTLSVerification:  skipTLSVerification,
			BindDN:               ldapBindDN,
			BindPassword:         ldapBindPassword,
			UserFilter:           ldapUserFilter,
			GroupFilter:          "(member=%s)",
			Attributes:           []string{"givenName", "sn", "mail", "uid", "cn", "userPrincipalName"},
		},
		KubeCa:             caEncoded,
		KubeCaText:         string(kubeCA),
		KubeToken:          string(kubeToken),
		PublicApiServerURL: publicApiServerURL,
		ApiServerTLSConfig: tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            rootCAs,
		},
		TokenLifeTime:           getEnv("TOKEN_LIFETIME", "4h"),
		ExtraTokenLifeTime:      getEnv("EXTRA_TOKEN_LIFETIME", "720h"),
		Locator:                 getEnv("LOCATOR", KubiLocatorIntranet),
		NetworkPolicy:           networkpolicyEnabled,
		CustomLabels:            customLabels,
		DefaultPermission:       getEnv("DEFAULT_PERMISSION", ""),
		PrivilegedNamespaces:    strings.Split(getEnv("PRIVILEGED_NAMESPACES", ""), ","),
		Blacklist:               strings.Split(getEnv("BLACKLIST", ""), ","),
		Whitelist:               whitelist,
		BlackWhitelistNamespace: getEnv("BLACK_WHITELIST_NAMESPACE", "default"),
	}, nil
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
