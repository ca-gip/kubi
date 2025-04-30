#!/bin/bash
# this script could be enhanced:
# - better handling of errors.
# - where it is called, in e2e_suite_test.go, exiting if one of the commands fail. This would ensure that the tests don't execute if the fixtures didn't go well.
# - at the beginning of the scripts, check the prerequisites are present: make docker kubectl HTTP_PROXY=${PROXY_URL} HTTPS_PROXY=${PROXY_URL} http_proxy=${PROXY_URL} https_proxy=${PROXY_URL} no_proxy=${NO_PROXY} NO_PROXY=${NO_PROXY} kind helm helm-images sleep cfssl openssl golang goreleaser
PROXY_URL=http://10.245.146.98:8089
export NO_PROXY="127.0.0.1,127.0.0.1:38300,scm.saas.cagip.group.gca,docker-remote.registry.saas.cagip.group.gca"
export no_proxy="127.0.0.1,127.0.0.1:38300,scm.saas.cagip.group.gca,docker-remote.registry.saas.cagip.group.gca"
export HTTP_PROXY=${PROXY_URL}
export HTTPS_PROXY=${PROXY_URL}
export http_proxy=${PROXY_URL}
export https_proxy=${PROXY_URL}

# KIND CLUSTER CREATION
kind delete cluster --name test-e2e-kubi
kind create cluster --name test-e2e-kubi --config test/e2e/conf/kind/cluster-kind.yaml

# OPENLDAP PREREQUISITES AND DEPLOY 
helm repo add helm-openldap https://jp-gouin.github.io/helm-openldap/

# Create configmap containing ldif file
kubectl -n kube-system apply -f test/e2e/conf/openldap/config.yaml
helm upgrade --install openldap helm-openldap/openldap-stack-ha  -f test/e2e/conf/openldap/myvalues.yaml --namespace kube-system
# We wait 30s for Openldap to pop otherwise, Kubi tries to connect to it directly, 
# fails to open a connection and waits for a new reconciliation loop to occur, 
# which makes the fail test, due to 30s timeout (in e2e_test.go file.)

sleep 60

# COMMAND TO CHECK THAT OPENLDAP IS DEPLOYED AND HAS GOOD CONF
# <<<<ldapsearch -x -H ldap://openldap.kube-system.svc.cluster.local -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w Not@SecurePassw0rd>>>>

# KUBI OPERATOR DEPLOY 
# kubi-encryption-secret -> the PKI which signs the tokens
# kubi -> i think it's the authn cert to api server. Unsure

kubectl -n kube-system create secret generic kubi-secret  --from-literal ldap_passwd='Not@SecurePassw0rd'
./scripts/generate_ecdsa_keys.sh
kubectl -n kube-system create secret generic kubi-encryption-secret --from-file=/tmp/kubi/ecdsa/ecdsa-key.pem --from-file=/tmp/kubi/ecdsa/ecdsa-public.pem


# chmod +x scripts/install_cfssl.sh
# ./scripts/install_cfssl.sh
cat <<EOF | cfssl genkey - | cfssljson -bare server
      {
        "hosts": [
        "kubi.devops.managed.kvm",
        "kubi-svc",
        "kubi-svc.kube-system",
        "kubi-svc.kube-system.svc",
        "kubi-svc.kube-system.svc.cluster.local",
        "10.96.0.2"
         ],
       "CN": "system:node:kubi-svc.kube-system.svc.cluster.local",
       "key": {
       "algo": "ecdsa",
       "size": 256
         },
      "names": [
        {
            "O": "system:nodes"
        }
      ]
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
   signerName: kubernetes.io/kubelet-serving
   usages:
     - digital signature
     - key encipherment
     - server auth
EOF

# Set deployments images
COMMIT_SHA="$(git rev-parse --short HEAD)"
IMG_VERSION="${COMMIT_SHA}-amd64"
IMG_REPO="ghcr.io/ca-gip"

ORG=ca-gip goreleaser release --clean --snapshot
kind load docker-image ${IMG_REPO}/kubi-operator:${IMG_VERSION} --name test-e2e-kubi
kind load docker-image ${IMG_REPO}/kubi-api:${IMG_VERSION} --name test-e2e-kubi
kind load docker-image ${IMG_REPO}/kubi-webhook:${IMG_VERSION} --name test-e2e-kubi
OPERATOR_DEPLOY_YAML=/tmp/updated-operator-deployment.yaml
API_WEBHOOK_DEPLOY_YAML=/tmp/updated-api-webhook-deployment.yaml
sed "s|<kubi-operator-image>|${IMG_REPO}/kubi-operator:${IMG_VERSION}|" test/e2e/conf/kubi/kubi-operator-deployment.yaml > ${OPERATOR_DEPLOY_YAML}
sed "s|<kubi-webhook-image>|${IMG_REPO}/kubi-webhook:${IMG_VERSION}|" test/e2e/conf/kubi/kubi-api-and-authn-webhook-deployment.yaml > ${API_WEBHOOK_DEPLOY_YAML}
sed -i "s|<kubi-api-image>|${IMG_REPO}/kubi-api:${IMG_VERSION}|" ${API_WEBHOOK_DEPLOY_YAML}

# resign the cert and replace in CSR as said in doc -> wrong

kubectl certificate approve kubi-svc.kube-system
kubectl get csr kubi-svc.kube-system -o jsonpath='{.status.certificate}' | base64 --decode > server.crt
kubectl -n kube-system create secret tls kubi   --key server-key.pem   --cert server.crt
#create configmap kubi-config with all openldap info
kubectl apply -f test/e2e/conf/kubi/configmap.yaml
kubectl apply -f deployments/kube-crds.yml
kubectl apply -f test/e2e/conf/kubi/kube-prerequisites.yml
kubectl apply -f test/e2e/conf/kubi/black-white-list-cm.yaml
kubectl apply -f ${OPERATOR_DEPLOY_YAML}
kubectl apply -f ${API_WEBHOOK_DEPLOY_YAML}
kubectl apply -f test/e2e/conf/kubi/rbac.yaml
kubectl apply -f test/e2e/conf/kubi/kubi-netpol-config.yaml
kubectl apply -f test/e2e/conf/kubi/services.yaml
