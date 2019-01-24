# Kubi

Kubi is a Kubernetes IAM authentication proxy to authenticate user through
LDAP, AD LDS and assign permission dynamically using a predefined naming convention (LDAP Group).

For example:
- a ldap group named: GROUP-NAMESPACE-DEMO_ADMIN give ADMIN `role binding`  permissions to the existing namespace `NAMESPACE-DEMO`.

The `_` is used to split Role and Namespace, the pattern is `XXX_NAMESPACE-NAME_ROLE`.

> In this version, you need to create Role binding manually to grant permission.
It will be automatically create in the next release.

# Launching Applications

## Deploy on kubernetes

### Create a certificate with kubernetes CA

**Prerequisites:**
- You need to have admin access to an existing kubernetes cluster
- You need to have cfssl installed

#### Create a private key signed by Kubernetes CA

1. Kube Api Server Url
  > Change `api.devops.managed.kvm` to an existing kubernetes node ip, vip, or fqdn
  that point to an existing Kubernetes Cluster node.
  **Eg: 10.56.221.4, kubernetes.<my_domain>...**

  ```bash
  cat <<EOF | cfssl genkey - | cfssljson -bare server
  {
    "hosts": [
      "api.devops.managed.kvm"
      "kubi-svc.kube-system.svc.cluster.local",
    ],
    "CN": "kubi-svc.kube-system.svc.cluster.local",
    "key": {
      "algo": "ecdsa",
      "size": 256
    }
  }
  EOF
  ```

2. Create the signing request

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

3. Approve the csr
```bash
kubectl certificate approve kubi-svc.kube-system
```

4. retrieve the crt
```bash
kubectl get csr kubi-svc.kube-system -o jsonpath='{.status.certificate}'     | base64 --decode > server.crt
```

5. Create a secret for the deployment
```bash
kubectl -n kube-system create secret tls kubi --key server-key.pem --cert server.crt
```

6. Deploy the kubernetes.yaml file

**6.1. Change the ldap settings:**
- **LDAP_USERBASE**: (Mandatory) BaseDn for user base search
- **LDAP_GROUPBASE**: (Mandatory) BaseDn for group base search
- **LDAP_SERVER**: (Mandatory) LDAP server ip address
- **LDAP_PORT**: (Mandatory) LDAP server port 389, 636...
- **LDAP_BINDDN**: (Mandatory) LDAP bind account DN
- **LDAP_PASSWD**: (Mandatory) LDAP bind account password
- **APISERVER_URL**: (Optional) "10.96.0.1:443"

**6.2. Deploy the config map**
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
  LDAP_PASSWD: "password"
  APISERVER_URL: "10.96.0.1:443"
metadata:
  name: kubi-config
EOF
```

**6.2. Deploy the the application**
```bash
kubectl -n kube-system apply -f kube.yaml
```

**6.3. Deploy a role-binding for a namespace**

Below an example for a LDAP group named: `GROUP_DEMO_ADMIN`
An existing namespace named `demo` in lowercase must exists.

```bash
cat <<EOF | kubectl create -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: "demo-admin"
  namespace: "demo"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: "demo-admin"
EOF
```

## Connect to proxy

### Using `curl`

Use the server url defined at 1.1
```bash
curl -v -k --user <user_cn> https://<Kube Api Server Url>:30003/config
```

### Using `kubi` cli ( go to release )
```bash
kubi --kubi-url <Kube Api Server Url> --generate-config --username <user_cn>
```

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
