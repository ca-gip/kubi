<!-- omit in toc -->
# Developer guide

This guide helps you get started developing kubi

Make sure you have the following dependencies installed before setting up your developer environment:

 - Git
 - Docker
 - Jq
 - Wget
 - curl
 - Go
 - Openssl
 - In this context we will use a kind cluster for the local deployment of Kubi : cluster kind {1.30 or 1.31}

## Deploy kubi  

 - Get the source code https://github.com/ca-gip/kubi
  
 - install go  https://go.dev/
    
 - Create kind cluster with version 1.24-1.26 https://kind.sigs.k8s.io/docs/user/quick-start/
  
 - Generate kubi private/public key
 ```
 cd scripts
 chmod +x generate_ecdsa_keys.sh
 ./generate_ecdsa_keys.sh
 ```
  
 - install CFSSL tools
 ```
cd scripts
chmod +x install_cfssl.sh
./install_cfssl.sh
 ```
    
 - create certificate
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
  cd kubi
  kubectl apply -f deployments/kube-deployment.yml
  kubectl apply -f deployments/kube-crds.yml
  kubectl apply -f deployments/kube-prerequisites.yml
  kubectl apply -f deployments/kube-local-config.yml
  ```
  

 Copy the secret from you Kubernetes cluster
 
- Create secret dirs on your local machine
 ```
 TEMP_DIR=$(mktemp -d) && mkdir -p "$TEMP_DIR"/{certs,ecdsa,kubernetes.io} && echo "Secret directories created at: $TEMP_DIR"
 ```
- The mapping between the secret:key anf file path 

| Secret Name | Secret Key | Local Path |
|-------------|------------|------------|
| kubi-user-<hash> | ca.crt |  $TEMP_DIR/kubernetes.io/serviceaccount/ca.crt |
| kubi-user-<hash> | token |  $TEMP_DIR/kubernetes.io/serviceaccount/token |
| kubi | tls.crt | $TEMP_DIR/certs/tls.crt |
| kubi | tls.key |  $TEMP_DIR/certs/tls.key |
| kubi-encryption-secret | ecdsa-key.pem |  $TEMP_DIR/ecdsa/ecdsa-key.pem |
| kubi-encryption-secret | ecdsa-public.pem |  $TEMP_DIR/ecdsa/ecdsa-public.pem |                           

You can execute the following commands to gather all the required secrets then decode and save them

  ```
  kubectl -n kube-system get secrets $(kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['ca\.crt']}" | base64 -d > / $TEMP_DIR/kubernetes.io/serviceaccount/ca.crt
  kubectl -n kube-system get secrets $(kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['token']}" | base64 -d > /$TEMP_DIR/kubernetes.io  /serviceaccount/token
  kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.crt']}" | base64 -d > /$TEMP_DIR/certs/tls.crt
  kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.key']}" | base64 -d > /$TEMP_DIR/certs/tls.key
  kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-key\.pem']}" | base64 -d > /$TEMP_DIR/ecdsa/ecdsa-key.pem
  kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-public\.pem']}" | base64 -d > /$TEMP_DIR/ecdsa/ecdsa-public.pem
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
kubectl apply -f deployments/kube-example-netpolconf.yml
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


<!-- omit in toc -->
# Contributing to kubi

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of Contents](#table-of-contents) for different ways to help and details about how this project handles them. Please make sure to read the relevant section before making your contribution. It will make it a lot easier for us maintainers and smooth out the experience for all involved. The community looks forward to your contributions. 🎉

> And if you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support the project and show your appreciation,   which we would also be very happy about:
> - Star the project
> - Tweet about it
> - Refer this project in your project's readme
> - Mention the project at local meetups and tell your friends/colleagues

<!-- omit in toc -->
## Table of Contents

- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)


## I Have a Question

> If you want to ask a question, we assume that you have reviewed the available [Documentation](https://github.com/ca-gip/kubi).


> Before asking, it is advisable to check existing Issues [Issues](https://github.com/ca-gip/kubi/issues) that may address your query. If you find a relevant issue but still require clarification, please post your question within that issue. Additionally, searching the internet for answers can often be helpful.

> Should you still need to ask a question after following these steps, we recommend:

- Sending an email to the mailing list CAGIP_DEVOPS_CONTAINER <cagip_devops_container@ca-gip.fr>.
- Providing as much context as possible regarding the issue you are encountering.
- Including relevant project and platform versions (e.g., Kubernetes, Golang) as applicable.
  
This approach ensures that your question reaches the right audience and is more likely to receive a prompt response.

Before you ask a question, it is best to search for existing  that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.


## I Want To Contribute

> ### Legal Notice <!-- omit in toc -->
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute may be provided under the project license.

### Reporting Bugs

#### Before Submitting a Bug Report

A good bug report shouldn't leave others needing to chase you up for more information. Therefore, we ask you to investigate carefully, collect information and describe the issue in detail in your report. Please complete the following steps in advance to help us fix any potential bug as fast as possible.

- Make sure that you are using the latest version.
- Determine if your bug is really a bug and not an error on your side e.g. using incompatible environment components/versions (Make sure that you have read the [documentation](https://github.com/ca-gip/kubi). If you are looking for support, you might want to check [this section](#i-have-a-question)).
- To see if other users have experienced (and potentially already solved) the same issue you are having, check if there is not already a bug report existing for your bug or error.
- Collect information about the bug:
  - Stack trace (Traceback)
  - OS, Platform and Version (Windows, Linux, macOS, x86, ARM)
  - Version of the interpreter, compiler, SDK, runtime environment, package manager, depending on what seems relevant.
  - Possibly your input and the output
  - What did you have as result, and what did you expect ?
  - Can you reliably reproduce the issue? And can you also reproduce it with older versions?
  - Give everything we need to reproduce the issue (a test if possible)

<!-- omit in toc -->

Once it's filed:

- A team member will try to reproduce the issue with your provided steps and then we will contact you back.
- If the team is able to reproduce the issue, it will be marked `needs-fix`, as well as possibly other tags (such as `critical`), and the issue will be left to be [implemented by someone](#your-first-code-contribution).

<!-- You might want to create an issue template for bugs and errors that can be used as a guide and that defines the structure of the information to be included. If you do so, reference it here in the description. -->


### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for kubi, **including completely new features and minor improvements to existing functionality**. Following these guidelines will help maintainers and the community to understand your suggestion and find related suggestions.

<!-- omit in toc -->
#### How Do I Submit a Good Enhancement Suggestion?

To submit an enhancement suggestion, please propose a pull request (PR) and contact us for review.

