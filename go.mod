module github.com/ca-gip/kubi

go 1.16

require (
	github.com/asaskevich/govalidator v0.0.0-20200108200545-475eaeb16496 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible
	github.com/gorilla/mux v1.7.4
	github.com/mitchellh/mapstructure v1.1.2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.1
	github.com/rs/zerolog v1.18.0
	github.com/stretchr/testify v1.7.0
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
	k8s.io/code-generator v0.20.4
)

replace k8s.io/code-generator => github.com/efortin/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20210602081514-49be077fdae8
