package types

import (
	"crypto/tls"
	"github.com/dgrijalva/jwt-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LdapConfig struct {
	UserBase            string
	GroupBase           string
	AdminUserBase       string
	AdminGroupBase      string
	Host                string
	Port                int
	UseSSL              bool
	StartTLS            bool
	SkipTLSVerification bool
	BindDN              string
	BindPassword        string
	UserFilter          string
	GroupFilter         string
	Attributes          []string
}

type Config struct {
	Tenant             string
	Ldap               LdapConfig
	PublicApiServerURL string
	KubeCa             string
	KubeCaText         string
	KubeToken          string
	ApiServerTLSConfig tls.Config
	TokenLifeTime      string
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
	Auths       []*NamespaceAndRole `json:"auths"`
	User        string              `json:"user"`
	AdminAccess bool                `json:"adminAccess"`
	jwt.StandardClaims
}

type NamespaceAndRole struct {
	Namespace string `json:"namespace"`
	Role      string `json:"role""`
}

type ResponseError struct {
	metav1.TypeMeta
	metav1.Status
}

type Auth struct {
	Username string
	Password string
}
