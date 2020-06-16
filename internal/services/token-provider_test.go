package services_test

import (
	"crypto/ecdsa"
	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestECDSA(t *testing.T) {
	ecdsaPem, err := ioutil.ReadFile("./../../test/ecdsa-key.pem")
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := ioutil.ReadFile("./../../test/ecdsa-pub.pem")
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA public key: %v", err)
	}
	var ecdsaKey *ecdsa.PrivateKey
	var ecdsaPub *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(ecdsaPem); err != nil {
		utils.Log.Fatal().Msgf("Unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPub, err = jwt.ParseECPublicKeyFromPEM(ecdsaPubPem); err != nil {
		utils.Log.Fatal().Msgf("Unable to parse ECDSA public key: %v", err)
	}

	issuer := services.TokenIssuer{
		EcdsaPrivate:  ecdsaKey,
		EcdsaPublic:   ecdsaPub,
		TokenDuration: "4h",
		Locator:       utils.KubiLocatorIntranet,
	}

}
