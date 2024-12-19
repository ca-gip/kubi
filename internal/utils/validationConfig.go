package utils

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"

	"github.com/ca-gip/kubi/pkg/types"
)

func validateBase64(s string) error {
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return errors.New("must be a valid base64 string")
	}
	return nil
}

func validateURL(s string) error {
	if _, err := url.ParseRequestURI(s); err != nil {
		return errors.New("must be a valid URL")
	}
	return nil
}
func validateLength(field string, min int, max int) error {
	length := len(field)
	if length < min || length > max {
		return errors.New("length must be between " + strconv.Itoa(min) + " and " + strconv.Itoa(max) + " characters")
	}
	return nil
}

func validateLdapConfig(ldapConfig *types.LdapConfig) error {
	if ldapConfig.UserBase == "" {
		return errors.New("userBase is required")
	}
	if err := validateLength(ldapConfig.UserBase, 2, 200); err != nil {
		return err
	}
	if ldapConfig.GroupBase == "" {
		return errors.New("groupBase is required")
	}
	if err := validateLength(ldapConfig.GroupBase, 2, 200); err != nil {
		return err
	}
	if ldapConfig.Host == "" {
		return errors.New("host is required")
	}
	if err := validateURL(ldapConfig.Host); err != nil {
		return err
	}
	if ldapConfig.BindDN == "" {
		return errors.New("BindDN is required")
	}
	if err := validateLength(ldapConfig.BindDN, 2, 200); err != nil {
		return err
	}
	if ldapConfig.BindPassword == "" {
		return errors.New("BindPassword is required")
	}
	if err := validateLength(ldapConfig.BindPassword, 2, 200); err != nil {
		return err
	}
	return nil
}

func validateConfig(config *types.Config) error {
	if config.KubeToken == "" {
		return errors.New("KubeToken is required")
	}
	if config.KubeCa == "" {
		return errors.New("KubeCa is required")
	}
	if err := validateBase64(config.KubeCa); err != nil {
		return err
	}
	if config.PublicApiServerURL == "" {
		return errors.New("PublicApiServerURL is required")
	}
	if err := validateURL(config.PublicApiServerURL); err != nil {
		return err
	}
	return nil
}
