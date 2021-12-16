
<p align=center  style="background-color:#333333 !important;">
  <img align="center" src="/docs/logo.png" width="200px">
</p>

# Kubi
![build](https://github.com/ca-gip/kubi/workflows/build/badge.svg)
![release](https://github.com/ca-gip/kubi/workflows/release/badge.svg)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/ca-gip/kubi)
[![Go Report Card](https://goreportcard.com/badge/github.com/ca-gip/kubi)](https://goreportcard.com/report/github.com/ca-gip/kubi)
![Docker Pulls](https://img.shields.io/docker/pulls/cagip/kubi-operator)

Kubi is the missing tool for Active Directory or LDAP driven company. It handles OpenLDAP or Active Directory LDS authentication for Kubernetes clusters. It acts as a Kubernetes Token Server, authenticating user through LDAP, AD LDS and assigns permissions dynamically using a predefined naming convention (LDAP Group).

Kubi is a webhook for the server part and has a cli for linux and windows users.


<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Index

- [General](#general)
  - [Parameters](#parameters)
- [Client](#client)
  - [For Windows users](#for-windows-users)
  - [For Linux](#for-linux)
    - [With kubi cli](#with-kubi-cli)
      - [For Linux](#for-linux-1)
      - [For Mac](#for-mac)
      - [Connection](#connection)
    - [With `curl`](#with-curl)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Create a crt signed by Kubernetes CA](#create-a-crt-signed-by-kubernetes-ca)
  - [Create the signing request](#create-the-signing-request)
  - [Approve the csr](#approve-the-csr)
  - [Retrieve the crt](#retrieve-the-crt)
  - [Create a secret for the deployment](#create-a-secret-for-the-deployment)
  - [Create a secret for LDAP Bind password](#create-a-secret-for-ldap-bind-password)
  - [Deploy the config map](#deploy-the-config-map)
  - [Deploy the Custom Resource Definitions](#deploy-the-custom-resource-definitions)
  - [Deploy the prerequisites](#deploy-the-prerequisites)
  - [Deploy Kubi](#deploy-kubi)
  - [Customize the default network policy](#customize-the-default-network-policy)
  - [Basic Webhook configuration](#basic-webhook-configuration)
  - [Advanced Webhook configuration](#advanced-webhook-configuration)
- [Roadmap](#roadmap)
- [Development environment](#development-environment)
  - [Deploy the local config](#deploy-the-local-config)
  - [Copy the secret from you Kubernetes cluster](#copy-the-secret-from-you-kubernetes-cluster)
  - [Running](#running)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# General

Namespaces and Rolebindings are automatically created and managed by Kubi. Kubi parse the LDAP group and find the `namespace` and the `role`.
The first part (from the right) is the role, and the second is the namespace.

The `_` is used to split Role and Namespace, the pattern is `<whatever>_<namespace>_<role>`. Namespace must be DNS1123 compatible and can´t exceed 63 characters ( kubernetes constraint ).

For example:
- a ldap group named: `WHATYOUWANT_DEMO_ADMIN` give cluster `role binding` admin permissions to the namespace `DEMO`.
- a ldap group named: `WHATYOUWANT_PROJECT-IN-PRODUCTION_ADMIN` give cluster `role binding` admin permissions to the namespace `PROJECT-IN-PRODUCTION`.

If the namespace is missing, it will be automatically created at startup. You can refresh it by calling `/refresh`. Some namespace are protected: `kube-system, kube-public, default`. Kubi can generate `NetworkPolicy` if `PROVISIONING_NETWORK_POLICIES` flag is enabled. In this case, it create a `Networpolicy` that create something like a bubble.

The network policy works like this principle:
- Every pods can communicate inside the namespace
- Pods cannot communicate with external resources ( outside cluster )
- Dns is not filtered

You can customize `PROVISIONING_EGRESS_ALLOWED_PORTS`, `PROVISIONING_EGRESS_ALLOWED_CIDR`, `PROVISIONING_INGRESS_ALLOWED_NAMESPACES` to add default rules.
For specific exceptions, add another network policy.

## Parameters

| Name                               | Description                          | Example                          | Mandatory   | Default     |
| :--------------                    | :-----------------------------:      | ----------------------------:    | ---------:  | ----------: |
|  **PUBLIC_APISERVER_URL**          |  *Api server url (public)*           | `https://k8s.macompany.com`      | `yes  `     | -           |
|  **LDAP_USERBASE**                 |  *BaseDn for user base search*       | `ou=People,dc=example,dc=org   ` | `yes  `     | -           |
|  **LDAP_GROUPBASE**                |  *BaseDn for group base search*      | `ou=CONTAINER,dc=example,dc=org` | `yes  `     | -           |
|  **LDAP_APP_GROUPBASE**            |  *BaseDn for group base search*      | `ou=CONTAINER,dc=example,dc=org` | `no  `      | -           |
|  **LDAP_OPS_GROUPBASE**            |  *BaseDn for group base search*      | `ou=CONTAINER,dc=example,dc=org` | `no  `      | -           |
|  **LDAP_CUSTOMER_OPS_GROUPBASE**   |  *BaseDn for customer group base *   | `ou=CONTAINER,dc=example,dc=org` | `no  `      | -           |
|  **LDAP_ADMIN_USERBASE**           |  *BaseDn for admin base search*      | `ou=Admin,dc=example,dc=org   `  | `yes  `     | -           |
|  **LDAP_ADMIN_GROUPBASE**          |  *BaseDn for admin group base search*| `ou=AdminGroup,dc=example,dc=org`| `yes  `     | -           |
|  **LDAP_VIEWER_GROUPBASE**         |  *BaseDn for viewer group base search*| `ou=ViewerGroup,dc=example,dc=org`| `no  `     | -           |
|  **LDAP_SERVICE_GROUPBASE**        |  *BaseDn for service group base search*| `ou=ServiceGroup,dc=example,dc=org`| `no  `     | -           |
|  **LDAP_SERVER**                   |  *LDAP server ip address*            | `"192.168.2.1"                 ` | `yes  `     | -           |
|  **LDAP_PORT**                     |  *LDAP server port 389, 636...*      | `389                           ` | `no   `     | `389  `     |
|  **LDAP_USE_SSL**                  |  *Use SSL or no*                     | `true                          ` | `no   `     | `false`     |
|  **LDAP_START_TLS**                |  *Use StartTLS ( use with 389 port)* | `true                          ` | `false`     | `false`     |
|  **LDAP_SKIP_TLS_VERIFICATION**    |  *Skip TLS verification*             | `true                          ` | `false`     | `true`      |
|  **LDAP_BINDDN**                   |  *LDAP bind account DN*              | `"CN=admin,DC=example,DC=ORG"  ` | `yes  `     | -           |
|  **LDAP_PASSWD**                   |  *LDAP bind account password*        | `"password"                    ` | `yes  `     | -           |
|  **LDAP_USERFILTER**               |  *LDAP filter for user search*       | `"(userPrincipalName=%s)"      ` | `no   `     | `(cn=%s)`   |
|  **TOKEN_LIFETIME**                |  *Duration for the JWT token*        | `"4h"                          ` | `no   `     | 4h          |
|  **LOCATOR**                       |  *Locator: must be internet or extranet*  | `"intranet"             `   | `no   `     | intranet    |
|  **PROVISIONING_NETWORK_POLICIES** |  *Enable or disable NetPol Mgmt*     | `true                           `   | `no   `     | yes         |
|  **CUSTOM_LABELS**                 | *Add custom labels to namespaces*    | `quota=managed,monitoring=true`  | `no   `     | -           |
|  **DEFAULT_PERMISSION**            | *ClusterRole associated with default service account*    | `view`       | `no   `     | -           |
|  **BLACKLIST**                     | *Ignore Project*                     | `my-project-dev`                 | `no   `     | -           |

# Client



## For Windows users

1. Download the cli: [download here](https://github.com/ca-gip/kubi/releases/download/v1.8.5/kubi.exe)
2. Open Cmd
```bash
# Get help
.\kubi.exe --help
# Connect and generate config file
.\kubi.exe --kubi-url <kubi-server-fqdn-or-ip>:30003 --generate-config --username <user_cn>
# Connect with your password and generate config file
.\kubi.exe --kubi-url <kubi-server-fqdn-or-ip>:30003 --generate-config --username <user_cn> --password your_pwd
```

## For Linux

### With kubi cli

#### For Linux
```bash
# Install the kubi cli
sudo wget https://github.com/ca-gip/kubi/releases/download/v1.8.5/kubi -P /usr/local/bin
sudo chmod a+x /usr/local/bin/kubi

# Connect to the cluster
kubi config --kubi-url <kubi-server-fqdn-or-ip>:30003 --username <user_cn>
# Connect with your password and generate config file
kubi config --kubi-url <kubi-server-fqdn-or-ip>:30003 --username <user_cn> --password your_pwd
```
#### For Mac

```bash
# Install wget with brew
brew install wget

# Install the kubi cli
sudo wget https://github.com/ca-gip/kubi/releases/download/v1.8.5/kubi-darwin -O /usr/local/bin/kubi
sudo chmod a+x /usr/local/bin/kubi

```

#### Connection
```bash

# Connect to the cluster
kubi config --kubi-url <kubi-server-fqdn-or-ip>:30003 --username <user_cn>
# Connect with your password and generate config file
kubi config --kubi-url <kubi-server-fqdn-or-ip>:30003 --username <user_cn> --password your_pwd

# Explain your token
kubi explain # for your current context token
kubi explain <another_token> for explaining another token
```
### With `curl`

```bash
  curl -v -k --user <user_cn> https://<kubi-server-fqdn-or-ip>:30003/config
```

> It is not recommended to use curl, because it is used with -k parameter ( insecure mode).

# Installation

## Prerequisites

- You need to have admin access to an existing Kubernetes cluster
- You need to have `cfssl` installed: https://github.com/cloudflare/cfssl
- Time

## Create a crt signed by Kubernetes CA

  > Change `kubi.devops.managed.kvm` to an existing kubernetes node ip, vip, or fqdn
  that point to an existing Kubernetes Cluster node.
  **Eg: 10.56.221.4, kubernetes.<my_domain>...**

```bash
cat <<EOF | cfssl genkey - | cfssljson -bare server
{
  "hosts": [
    "kubi.devops.managed.kvm",
    "kubi-svc",
    "kubi-svc.kube-system",
    "kubi-svc.kube-system.svc",
    "kubi-svc.kube-system.svc.cluster.local",
    "kubi.devops.managed.kvm"
  ],
  "CN": "kubi-svc.kube-system.svc.cluster.local",
  "key": {
    "algo": "ecdsa",
    "size": 256
  }
}
EOF
```

## Create the signing request

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

## Approve the csr
```bash
kubectl certificate approve kubi-svc.kube-system
```

## Retrieve the crt
```bash
kubectl get csr kubi-svc.kube-system -o jsonpath='{.status.certificate}'     | base64 --decode > server.crt
```

## Create a secret for the deployment
```bash
kubectl -n kube-system create secret tls kubi --key server-key.pem --cert server.crt
```

## Create a secret for LDAP Bind password

```bash
kubectl -n kube-system create secret generic kubi-secret \
  --from-literal ldap_passwd='changethispasswordnow!'
```

## Deploy the config map

** YOU MUST CHANGE VALUE WITH YOUR OWN **
```bash
cat <<EOF | kubectl -n kube-system create -f -
apiVersion: v1
kind: ConfigMap
data:
  LDAP_USERBASE: "ou=People,dc=kubi,dc=fr"
  LDAP_GROUPBASE: "ou=local_platform,ou=Groups,dc=kubi,dc=fr"
  LDAP_SERVER: "192.168.2.1"
  LDAP_PORT: "389"
  LDAP_BINDDN: "cn=admin,dc=kubi,dc=fr"
  LDAP_ADMIN_USERBASE: "ou=People,dc=kubi,dc=fr"
  LDAP_ADMIN_GROUPBASE: "ou=Administrators,ou=Groups,dc=kubi,dc=fr"
  PUBLIC_APISERVER_URL: https://api.devops.managed.kvm
metadata:
  name: kubi-config
EOF
```
## Deploy the Custom Resource Definitions

```bash
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-crds.yml
```

## Deploy the prerequisites

```bash
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-prerequisites.yml
```


## Deploy Kubi

```bash
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-deployment.yml
```

## Customize the default network policy

You can customize the default network policy named `kubi-default`, for example:

```yaml
apiVersion: "ca-gip.github.com/v1"
kind: NetworkPolicyConfig
metadata:
  name: kubi-default
spec:
  egress:
    # ports allowed for egress
    ports:
      - 636
      - 389
      - 123
      - 53
    # cidrs allowed for egress
    # for ipvs, add the network used by calico, for kubernetes svc in default ns
    cidrs:
      - 192.168.2.0/24
      - 172.10.0.0/24
  ingress:
    # namespaces allowed for ingress rules ( here only nginx )
    namespaces:
      - ingress-nginx
```

** Deploy the example : **
```bash
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-example-netpolconf.yml
```

## Basic Webhook configuration

Kubi is installed as a Kubernetes webhook.
> For more information about webhook: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication

1. **On each master node in /etc/kubernetes/pki/webhook**


```yaml
# Kubernetes API version
apiVersion: v1
# kind of the API object
kind: Config
# clusters refers to the remote service.
clusters:
  - name: kubi
    cluster:
      certificate-authority: /etc/kubernetes/pki/ca.crt
      server: https://kube-svc:8001/authenticate   
users:
  - name: apiserver
    user:
      client-certificate: /etc/kubernetes/pki/apiserver.crt
      client-key: /etc/kubernetes/pki/apiserver.key
current-context: kubi
contexts:
- context:
    cluster:  kubi
    user: apiserver
  name: webhook
```

```bash
# vim /etc/kubernetes/manifests/kube-apiserver.yaml
- --authentication-token-webhook-config-file=/etc/kubernetes/pki/webhook.yml
```

> Api servers reboot automatically, check logs `kubectl logs -f kube-apiserver-master-01 -n kube-system`.

## Advanced Webhook configuration

You could change apiserver mount and create an aditionnal folder.
Here we use /etc/kubernetes/pki which is automatically mounted.

1. Add these params to kubeadm config in `ClusterConfiguration`:

  ```bash
  # Before, create the additionnals folder in all master nodes
  mkdir /etc/kubernetes/additionnals
  ```

2. And edit your `kubeadm-config.yml` file with the following values:

  ```yaml
  extraArgs:
    authentication-token-webhook-config-file: /etc/kubernetes/additionnals/webhook.yml
  extraVolumes:
    - name: additionnals
      hostPath: /etc/kubernetes/additionnals
      mountPath: /etc/kubernetes/additionnals
  ```

3. Copy the webhook file to `/etc/kubernetes/additionnals` folder.

# Roadmap

The following features should be available soon.

- Allow usage of static mapping ( a json file mapping with LDAP group and Kubernetes namespaces)
- Expose /metrics


# Development environment

You can easily contribute to this project by using a development environment, follow the installation step from [Installation](#installation) until the [Deploy the prerequisites](#deploy-the-prerequisites).

## Deploy the local config

```bash
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-local-config.yml
```

## Copy the secret from you Kubernetes cluster

Create secret dirs on your local machine

```bash
mkdir -p /var/run/secrets/{certs,ecdsa,kubernetes.io}
```

The mapping between the secret:key and file path

| Secret Name | Secret Key | Local Path |
|-------------|------------|------------|
| kubi-user-<hash> | ca.crt | /var/run/secrets/kubernetes.io/serviceaccount/ca.crt |
| kubi-user-<hash> | token | /var/run/secrets/kubernetes.io/serviceaccount/token |
| kubi | tls.crt |/var/run/secrets/certs/tls.crt |
| kubi | tls.key | /var/run/secrets/certs/tls.key |
| kubi-encryption-secret | ecdsa-key.pem | /var/run/secrets/ecdsa/ecdsa-key.pem |
| kubi-encryption-secret | ecdsa-public.pem | /var/run/secrets/ecdsa/ecdsa-public.pem |

You can execute the following commands to gather all the required secrets then decode and save them
```bash
kubectl -n kube-system get secrets $(kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['ca\.crt']}" | base64 -d > /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
kubectl -n kube-system get secrets $(kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['token']}" | base64 -d > /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.crt']}" | base64 -d > /var/run/secrets/certs/tls.crt
kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.key']}" | base64 -d > /var/run/secrets/certs/tls.key
kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-key\.pem']}" | base64 -d > /var/run/secrets/ecdsa/ecdsa-key.pem
kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-public\.pem']}" | base64 -d > /var/run/secrets/ecdsa/ecdsa-public.pem
```


## Running

At the base of this project execute the go run with the required variable

```bash
LDAP_ADMIN_GROUPBASE="cn=DL_ADMIN_TEAM,OU=GLOBAL,ou=Groups,dc=kubi,dc=ca-gip,dc=github,dc=com" \
LDAP_ADMIN_USERBASE="dc=kubi,dc=ca-gip,dc=github,dc=com"  \
LDAP_BINDDN="cn=admin,dc=kubi,dc=ca-gip,dc=github,dc=com"   \
LDAP_GROUPBASE="ou=LOCAL,ou=Groups,dc=kubi,dc=ca-gip,dc=github,dc=com"  \
LDAP_PORT="389"   \
LDAP_SERVER="kube-ldap.kube-system.svc.cluster.local"  \
LDAP_USE_SSL="false"   \
LDAP_USERBASE="ou=People,dc=kubi,dc=ca-gip,dc=github,dc=com"   \
LDAP_USERFILTER="(cn=%s)"   \
LOCATOR="local"   \
PUBLIC_APISERVER_URL="https://kubernetes.default.svc.cluster.local"  \
TENANT="cagip" \
KUBERNETES_SERVICE_HOST="kubernetes.default.svc.cluster.local" \
KUBERNETES_SERVICE_PORT="443" \
LDAP_PASSWD="password" \
go run cmd/main.go
```

 <hr/>
<p align=center  style="background-color:#333333 !important;">
  Developed with
  <br/>
  <img align="center" src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.png" alt="drawing" width="100"/>
</p>
