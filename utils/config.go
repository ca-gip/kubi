package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"intomy.land/kubi/types"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var Config *types.Config = makeConfig()

var ApiPrefix = []string{
	"/api", "/apis", "/metrics", "/resetMetrics", "/logs", "/debug", "/healthz", "/swagger-ui", "/swaggerapi", "/ui", "/version", "/openapi", "swagger-2.0.0.pb-v1",
}

// Build the configuration from environment variable
// and validate that is consistent. If false, the program exit
// with validation message. The validation is not error safe but
// it limit misconfiguration ( lack of parameter ).
func makeConfig() *types.Config {

	// TODO, aller chercher dans le kubeconfig si pas accès au /var/run/secrets
	kubeToken, errToken := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	kubeCA, errCA := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	caEncoded := base64.StdEncoding.EncodeToString(kubeCA)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if errCA != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", kubeCA, errCA)
	}

	if ok := rootCAs.AppendCertsFromPEM(kubeCA); !ok {
		log.Println("No certs appended, using system certs only")
	}
	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	//

	if errToken != nil {
		log.Fatal(errToken)
		os.Exit(1)
	}

	if errCA != nil {
		log.Fatal(errCA)
		os.Exit(1)
	}

	kubeApiServerUrl := os.Getenv("APISERVER_URL")
	if len(kubeApiServerUrl) == 0 {
		kubeApiServerUrl = "10.96.0.1:443"
	}

	// FIXME use SkipTLS true for non local
	ldapConfig := types.LdapConfig{
		UserBase:     os.Getenv("LDAP_USERBASE"),
		GroupBase:    os.Getenv("LDAP_GROUPBASE"),
		Host:         os.Getenv("LDAP_SERVER"),
		Port:         os.Getenv("LDAP_PORT"),
		UseSSL:       false,
		SkipTLS:      true,
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
		ApiServerURL:       os.Getenv("APISERVER_URL"),
		ApiServerTLSConfig: *tlsConfig,
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
		validation.Field(&ldapConfig.Port, validation.Required, is.Port),
		validation.Field(&ldapConfig.BindDN, validation.Required, validation.Length(2, 200)),
		validation.Field(&ldapConfig.BindPassword, validation.Required, validation.Length(2, 200)),
	)

	fmt.Println(err)
	if errLdap != nil {
		fmt.Println(strings.Replace(errLdap.Error(), "; ", "\n", -1))
	}

	if err != nil || errLdap != nil {
		os.Exit(1)
	}
	return config
}
