# Kubi

[![Build Status](https://travis-ci.org/ca-gip/kubi.svg?branch=master)](https://travis-ci.org/ca-gip/kubi)


Kubi is the missing tool for Active Directory or LDAP driven company. It handle OpenLDAP or Active Directory LDS authentication for Kubernetes clusters. It acts as a Kubernetes IAM proxy to authenticate user through LDAP, AD LDS and assigns permissions dynamically using a predefined naming convention (LDAP Group).

Namespaces and Rolebindings are automaticaly created by Kubi.

For example:
- a ldap group named: `GROUP_DEMO_ADMIN` give ADMIN `role binding`  permissions to the existing namespace `DEMO`.

The `_` is used to split Role and Namespace, the pattern is `<whatever>_<namespace>_<role>`. Namespace must be DNS1123 compatible and can´t exceed 63 characters ( kubernetes constraint ).

## Parameters

| Name                  | Description                           | Example                       | Mandatory | Default     |
| :--------------       | :-----------------------------:       | ----------------------------: | ---------:| ----------: |
|  **LDAP_USERBASE**        |  *BaseDn for user base search      *    | `ou=People,dc=example,dc=org   ` | `yes  `     | -           |
|  **LDAP_GROUPBASE**       |  *BaseDn for group base search     *    | `ou=CONTAINER,dc=example,dc=org` | `yes  `     | -           |
|  **LDAP_SERVER**          |  *LDAP server ip address           *    | `"192.168.2.1"                 ` | `yes  `     | -           |
|  **LDAP_PORT**            |  *LDAP server port 389, 636...     *    | `389                           ` | `no   `     | `389  `     |
|  **LDAP_USE_SSL**         |  *Use SSL or no                    *    | `true                          ` | `no   `     | `false`     |
|  **LDAP_SKIP_TLS**        |  *Use StartTLS ( use with 389 port)*    | `true                          ` | `false`     | `false`     |
|  **LDAP_PORT**            |  *LDAP server port 389, 636...     *    | `389                           ` | `no   `     | `389  `     |
|  **LDAP_BINDDN**          |  *LDAP bind account DN             *    | `"CN=admin,DC=example,DC=ORG"  ` | `yes  `     | -           |
|  **LDAP_PASSWD**          |  *LDAP bind account password       *    | `"password"                    ` | `yes  `     | -           |
|  **APISERVER_URL**        |  *Internal kubernetes svc ip       *    | `"10.96.0.1:443"               ` | `no   `     | -           |
|  **TOKEN_LIFETIME**       |  *Duration for the JWT token       *    | `"4h"                          ` | `no   `     | 4h          |

# Launching Applications

## Deploy on kubernetes

### Create a certificate with kubernetes CA

**Prerequisites:**
- You need to have admin access to an existing kubernetes cluster
- You need to have `cfssl` installed: https://github.com/cloudflare/cfssl
- A coffee

#### Create a crt signed by Kubernetes CA

  > Change `api.devops.managed.kvm` to an existing kubernetes node ip, vip, or fqdn
  that point to an existing Kubernetes Cluster node.
  **Eg: 10.56.221.4, kubernetes.<my_domain>...**

```bash
cat <<EOF | cfssl genkey - | cfssljson -bare server
{
  "hosts": [
    "api.devops.managed.kvm",
    "kubi-svc.kube-system.svc.cluster.local"
  ],
  "CN": "kubi-svc.kube-system.svc.cluster.local",
  "key": {
    "algo": "ecdsa",
    "size": 256
  }
}
EOF
```

#### Create the signing request

```bash
cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: kubi-svc.kube-system
spec:
  groups:
  - system:authenticated
  request: $(cat server.csr | base64 | tr -d '\n')
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF
```

#### Approve the csr
```bash
kubectl certificate approve kubi-svc.kube-system
```

#### Retrieve the crt
```bash
kubectl get csr kubi-svc.kube-system -o jsonpath='{.status.certificate}'     | base64 --decode > server.crt
```

#### Create a secret for the deployment
```bash
kubectl -n kube-system create secret tls kubi --key server-key.pem --cert server.crt
```
### Deploy the the application

#### Create a secret for LDAP Bind password

//TODO check uppercase
```bash
kubectl -n kube-system create secret generic kubi-secret \
  --from-literal ldap_passwd='changethispasswordnow!'
```

#### Deploy the config map

** YOU MUST CHANGE VALUE WITH YOUR OWN **
```bash
cat <<EOF | kubectl -n kube-system create -f -
apiVersion: v1
kind: ConfigMap
data:
  LDAP_USERBASE: "ou=People,dc=example,dc=org"
  LDAP_GROUPBASE: "ou=CONTAINER,dc=example,dc=org"
  LDAP_SERVER: "192.168.2.1"
  LDAP_PORT: "389"
  LDAP_BINDDN: "CN=admin,DC=example,DC=ORG"
  APISERVER_URL: "10.96.0.1:443"
metadata:
  name: kubi-config
EOF
```
#### Deploy the manifest

```bash
kubectl -n kube-system apply -f kube.yml
```

## Connect to Kubi server


### Using `kubi` cli for serious guy, [download here](https://github.com/ca-gip/kubi/releases/download/v1.0/kubi)

#### Install the kubi cli
```bash
sudo wget https://github.com/ca-gip/kubi/releases/download/v1.0/kubi -P /usr/local/bin
sudo chmod a+x /usr/local/bin/kubi
```
#### Connect to the cluster
```bash
kubi --kubi-url <kubi-server-fqdn-or-ip>:30003 --generate-config --username <user_cn>
```

### Using `curl`

```bash
curl -v -k --user <user_cn> https://<kubi-server-fqdn-or-ip>:30003/config
```

> It is not recommanded to use curl, because it is used with -k parameter ( insecure mode).

# Roadmap

The following features should be available soon.

- Allow usage of static mapping ( a json file mapping with LDAP group and Kubernetes namspaces)
- Expose /metrics


## Additionnals

### Local LDAP Server

The server need to have memberof overlay
```bash
docker run -d -p 389:389 \
  --hostname localhost -e SLAPD_PASSWORD=password  \
  -e SLAPD_DOMAIN=example.org  \
  -e SLAPD_ADDITIONAL_MODULES=memberof  \
  -e SLAPD_CONFIG_PASSWORD=config \
  --hostname localhost \
  dinkel/openldap
```
