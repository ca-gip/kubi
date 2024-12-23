package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

// Query LDAP with default credentials and paging parameters
func ldapQuery(request ldap.SearchRequest) (*ldap.SearchResult, error) {
	conn, err := ldapConnectAndBind(utils.Config.Ldap.BindDN, utils.Config.Ldap.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	results, err := conn.SearchWithPaging(&request, utils.Config.Ldap.PageSize)
	if err != nil {
		return nil, fmt.Errorf("error searching in LDAP with request %v, %v", request, err)
	}
	return results, nil

}

// Connect to LDAP and bind with given credentials
func ldapConnectAndBind(login string, password string) (*ldap.Conn, error) {
	var (
		err  error
		conn *ldap.Conn
	)
	tlsConfig := &tls.Config{
		ServerName:         utils.Config.Ldap.Host,
		InsecureSkipVerify: utils.Config.Ldap.SkipTLSVerification,
	}

	if utils.Config.Ldap.UseSSL {
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port), tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port))
	}

	if utils.Config.Ldap.StartTLS {
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to setup TLS connection")
		}
	}

	if err != nil {
		return nil, errors.Wrapf(err, "unable to create ldap connector for %s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port)
	}

	// Bind with BindAccount
	err = conn.Bind(login, password)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, nil
}
