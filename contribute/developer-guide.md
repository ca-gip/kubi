<!-- omit in toc -->
# Developer guide

This guide helps you get started developing kubi

Make sure you have the following dependencies installed before setting up your developer environment:

 - Git
 - Go
 - In this context we will use a kind cluster for the local deployment of Kubi : cluster kind {1.23 or 124}

## Deploy kubi  

 - Get the source code https://github.com/ca-gip/kubi
  
 - install go  https://go.dev/
    
 - Create kind cluster with version 1.24-1.26 https://kind.sigs.k8s.io/docs/user/quick-start/
  
 - kubi private key
 ```
   openssl ecparam -genkey -name secp521r1 -noout -out /tmp/ecdsa-key.pem
 ```
  
 - kubi public key
 ```
  openssl ec -in /tmp/ecdsa-key.pem -pubout -out /tmp/ecdsa-public.pem
 ```
  
 - install CFSSL tools
 ```
   VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
   VNUMBER=${VERSION#"v"}
   wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssljson_${VNUMBER}_linux_amd64 -O cfssljson
   chmod +x cfssljson
   mv cfssljson /usr/local/bin
   cfssljson -version
  
   VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
   VNUMBER=${VERSION#"v"}
   wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssl_${VNUMBER}_linux_amd64 -O cfssl
   chmod +x cfssl
   mv cfssl /usr/local/bin
 ```
    
 - create certificat
 > Change `kubi.devops.managed.kvm` to an existing kubernetes node ip, vip, or fqdn
   that point to an existing Kubernetes Cluster node.
   **Eg: 10.56.221.4, kubernetes.<my_domain>...**

 ```
     cat <<EOF | cfssl genkey - | cfssljson -bare server
      {
        "hosts": [
        "kubi.devops.managed.kvm",
        "kubi-svc",
        "kubi-svc.kube-system",
        "kubi-svc.kube-system.svc",
        "kubi-svc.kube-system.svc.cluster.local"
  
         ],
       "CN": "kubi-svc.kube-system.svc.cluster.local",
       "key": {
       "algo": "ecdsa",
       "size": 256
         }
     }
    EOF
 
 
     cat <<EOF | kubectl create -f -
      apiVersion: certificates.k8s.io/v1
      kind: CertificateSigningRequest
      metadata:
        name: kubi-svc.kube-system
      spec:
      groups:
      - system:authenticated
      request: $(cat server.csr | base64 | tr -d '\n')
      signerName: kubernetes.io/kube-apiserver-client
      usages:
      - digital signature
      - key encipherment
      - server auth
      EOF
  ```
  
  - Approving the certificate signing request
  ```
    kubectl certificate approve kubi-svc.kube-system
    kubectl get csr
  ```
 
  - Create a Certificate Authority
  ```
    cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca
      {
       "CN": "kube-kubi",
       "key": {
       "algo": "rsa",
       "size": 2048
        }
      }
      EOF
 
     echo '{
       "signing": {
          "default": {
             "usages": [
                "digital signature",
                "key encipherment",
                "server auth"
            ],
            "expiry": "876000h",
            "ca_constraint": {
                "is_ca": false
             }
         }
      }
    }' > server-signing-config.json 

  ```
  - Use a server-signing-config.json signing configuration and the certificate authority key file and certificate to sign the certificate request:
  ```
    kubectl get csr kubi-svc.kube-system -o jsonpath='{.spec.request}' | \
    base64 --decode | \
    cfssl sign -ca ca.pem -ca-key ca-key.pem -config server-signing-config.json - | \
    cfssljson -bare ca-signed-server
  ```

  - Upload the signed certificate
  ```
    kubectl get csr kubi-svc.kube-system -o json | \
    jq '.status.certificate = "'$(base64 ca-signed-server.pem | tr -d '\n')'"' | \
    kubectl replace --raw /apis/certificates.k8s.io/v1/certificatesigningrequests/kubi-svc.kube-system/status -f -
  ```

  - Download the certificate and use it
  ```
    kubectl get csr kubi-svc.kube-system -o jsonpath='{.status.certificate}' \
    | base64 --decode > server.crt
    cat server.crt  
  ```

  - Create a secret for the deployment
  ``` 
    kubectl -n kube-system create secret tls kubi --key server-key.pem --cert server.crt
    kubectl -n kube-system create secret generic kubi-encryption-secret --from-file=/tmp/ecdsa-key.pem --from-file=/tmp/ecdsa-public.pem
    kubectl -n kube-system create secret generic kubi-secret  --from-literal ldap_passwd='password'
  ```

  - Deploy manifest (CRD, prerequisites,local-config) of kubi
  ```
    kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-deployment.yml
    kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-crds.yml
    kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-prerequisites.yml
    kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-local-config.yml
  ```
  

 Copy the secret from you Kubernetes cluster
 
- Create secret dirs on your local machine
 ```
 mkdir -p /var/run/secrets/{certs,ecdsa,kubernetes.io}
 ```
- The mapping between the secret:key anf file path 

| Secret Name | Secret Key | Local Path |
|-------------|------------|------------|
| kubi-user-<hash> | ca.crt | /var/run/secrets/kubernetes.io/serviceaccount/ca.crt |
| kubi-user-<hash> | token | /var/run/secrets/kubernetes.io/serviceaccount/token |
| kubi | tls.crt |/var/run/secrets/certs/tls.crt |
| kubi | tls.key | /var/run/secrets/certs/tls.key |
| kubi-encryption-secret | ecdsa-key.pem | /var/run/secrets/ecdsa/ecdsa-key.pem |
| kubi-encryption-secret | ecdsa-public.pem | /var/run/secrets/ecdsa/ecdsa-public.pem |                           

You can execute the following commands to gather all the required secrets then decode and save them

  ```
    kubectl -n kube-system get secrets $(kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['ca\.crt']}" | base64 -d > /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    kubectl -n kube-system get secrets $(kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['token']}" | base64 -d > /var/run/secrets/kubernetes.io  /serviceaccount/token
    kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.crt']}" | base64 -d > /var/run/secrets/certs/tls.crt
    kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.key']}" | base64 -d > /var/run/secrets/certs/tls.key
    kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-key\.pem']}" | base64 -d > /var/run/secrets/ecdsa/ecdsa-key.pem
    kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-public\.pem']}" | base64 -d > /var/run/secrets/ecdsa/ecdsa-public.pem
  ```
   
  - Customize the default network policy

   You can customize the default network policy named `kubi-default`, for example:
 
  ```yaml
apiVersion: "cagip.github.com/v1"
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


  - Run kubi
  ```
    API_URL=$(kubectl config view --minify --output 'jsonpath={.clusters[].cluster.server}')
    API_PORT=${API_URL##*:}
    echo "API port: $API_PORT"
    echo "API URL: $API_URL"
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
    KUBERNETES_SERVICE_PORT="API_PORT" \
    LDAP_PASSWD="password" \
    go run ./cmd/api//main.go &
  ```
