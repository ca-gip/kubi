#!/bin/bash

mkdir dev
cd dev

# recuperer les adresses ip des nodes

kubectl get nodes -o=jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'

# ip du control plane

PUBLIC_APISERVER_URL=$(kubectl config view --minify | grep server | cut -f 2- -d ":" | tr -d " ")

#creation du certificat pour  faire la demande de signature par kube CA

cat <<EOF | cfssl genkey - | cfssljson -bare server
{
  "hosts": [
    "$PUBLIC_APISERVER_URL",
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

# creation de la demande de signature 

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

# approuver la demande d esignature

kubectl certificate approve kubi-svc.kube-system


#creation de le CA
cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca
{
  "CN": "kube-chaos",
  "key": {
    "algo": "rsa",
    "size": 2048
  }
}
EOF


# fichier de configuration pour le CA

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
}' >


#signature du certificat 

kubectl get csr kubi-svc.kube-system -o jsonpath='{.spec.request}' | \
  base64 --decode | \
  cfssl sign -ca ca.pem -ca-key ca-key.pem -config server-signing-config.json - | \
  cfssljson -bare ca-signed-server

#upload le certificat signé

kubectl get csr kubi-svc.kube-system -o json | \
  jq '.status.certificate = "'$(base64 ca-signed-server.pem | tr -d '\n')'"' | \
  kubectl replace --raw /apis/certificates.k8s.io/v1/certificatesigningrequests/kubi-svc.kube-system/status -f -


kubectl get csr my-svc.my-namespace -o jsonpath='{.status.certificate}' \
    | base64 --decode > server.crt




