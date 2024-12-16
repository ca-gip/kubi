package types

import (
	"crypto/tls"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	podSecurity "k8s.io/pod-security-admission/api"
)

type LdapConfig struct {
	UserBase             string
	GroupBase            string
	AppMasterGroupBase   string
	CustomerOpsGroupBase string
	ServiceGroupBase     string
	OpsMasterGroupBase   string
	ViewerGroupBase      string
	AdminUserBase        string
	AdminGroupBase       string
	Host                 string
	Port                 int
	PageSize             uint32
	UseSSL               bool
	StartTLS             bool
	SkipTLSVerification  bool
	BindDN               string
	BindPassword         string
	UserFilter           string
	GroupFilter          string
	Attributes           []string
}

type Config struct {
	PodSecurityAdmissionEnforcement podSecurity.Level
	PodSecurityAdmissionWarning     podSecurity.Level
	PodSecurityAdmissionAudit       podSecurity.Level
	Tenant                          string
	Ldap                            LdapConfig
	PublicApiServerURL              string
	KubeCa                          string
	KubeCaText                      string
	KubeToken                       string
	ApiServerTLSConfig              tls.Config
	TokenLifeTime                   string
	ExtraTokenLifeTime              string
	Locator                         string
	NetworkPolicy                   bool
	CustomLabels                    map[string]string
	DefaultPermission               string
	PrivilegedNamespaces            []string
	Blacklist                       []string
	BlackWhitelistNamespace         string
	Whitelist                       bool
}

// Note: struct fields must be public in order for unmarshal to
// correctly populate the data.
type KubeConfig struct {
	ApiVersion     string              `yaml:"apiVersion"`
	Clusters       []KubeConfigCluster `yaml:"clusters"`
	Contexts       []KubeConfigContext `yaml:"contexts"`
	CurrentContext string              `yaml:"current-context"`
	Kind           string              `yaml:"kind"`
	Users          []KubeConfigUser    `yaml:"users"`
}

type KubeConfigCluster struct {
	Cluster KubeConfigClusterData `yaml:"cluster"`
	Name    string                `yaml:"name"`
}

type KubeConfigClusterData struct {
	CertificateData string `yaml:"certificate-authority-data"`
	Server          string `yaml:"server"`
}

type KubeConfigContext struct {
	Context KubeConfigContextData `yaml:"context"`
	Name    string                `yaml:"name"`
}

type KubeConfigContextData struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type KubeConfigUser struct {
	Name string              `yaml:"name"`
	User KubeConfigUserToken `yaml:"user"`
}

type KubeConfigUserToken struct {
	Token string `yaml:"token"`
}

type AuthJWTClaims struct {
	Auths             []*Project `json:"auths"`
	User              string     `json:"user"`
	Contact           string     `json:"email"`
	AdminAccess       bool       `json:"adminAccess"`
	ApplicationAccess bool       `json:"appAccess"`
	OpsAccess         bool       `json:"opsAccess"`
	ViewerAccess      bool       `json:"viewerAccess"`
	ServiceAccess     bool       `json:"serviceAccess"`
	Locator           string     `json:"locator"`
	Endpoint          string     `json:"endPoint"`
	Tenant            string     `json:"tenant"`
	Scopes            string     `json:"scopes"`
	jwt.StandardClaims
}

type Project struct {
	Project     string `json:"project"`
	Role        string `json:"role"`
	Source      string `json:"-"`
	Environment string `json:"environment"`
	Contact     string `json:"-"`
}

func (project *Project) Namespace() (ns string) {
	if len(project.Environment) > 0 {
		ns = fmt.Sprintf("%s-%s", project.Project, project.Environment)
	} else {
		ns = project.Project
	}
	return
}

type ResponseError struct {
	metav1.TypeMeta
	metav1.Status
}

type Auth struct {
	Username string
	Password string
}

type BlackWhitelist struct {
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
}
