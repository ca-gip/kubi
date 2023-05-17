#!/bin/bash


# kubi public key
openssl ec -in $tmp_dir/ecdsa-key.pem -pubout -out $tmp_dir/ecdsa-public.pem

# recuperer les adresses ip des nodes
ls $tmp_dir
sudo openssl ec -in $tmp_dir/ecdsa-key.pem -pubout -out $tmp_dir/ecdsa-public.pem

#  Nodes IPs 

kubectl get nodes -o=jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'

# control plane IP

PUBLIC_APISERVER_URL=$(kubectl config view --minify | grep server | cut -f 2- -d ":" | tr -d " ")

# install CFSSL tools
VERSION_T=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
VNUMBER=${VERSION_T#"v"}
wget https://github.com/cloudflare/cfssl/releases/download/${VERSION_T}/cfssljson_${VNUMBER}_linux_amd64 -O cfssljson
chmod +x cfssljson
sudo mv cfssljson /usr/local/bin

cfssljson -version
VERSION_J=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
VNUMBER=${VERSION_J#"v"}
wget https://github.com/cloudflare/cfssl/releases/download/${VERSION_J}/cfssl_${VNUMBER}_linux_amd64 -O cfssl
chmod +x cfssl
sudo mv cfssl /usr/local/bin

# create certificat 
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


kubectl certificate approve kubi-svc.kube-system



cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca
{
  "CN": "kube-chaos",
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




kubectl get csr kubi-svc.kube-system -o jsonpath='{.spec.request}' | \
  base64 --decode | \
  cfssl sign -ca ca.pem -ca-key ca-key.pem -config server-signing-config.json - | \
  cfssljson -bare ca-signed-server



kubectl get csr kubi-svc.kube-system -o json | \
  jq '.status.certificate = "'$(base64 ca-signed-server.pem | tr -d '\n')'"' | \
  kubectl replace --raw /apis/certificates.k8s.io/v1/certificatesigningrequests/kubi-svc.kube-system/status -f -


kubectl get csr kubi-svc.kube-system -o jsonpath='{.status.certificate}' \
    | base64 --decode > server.crt
    
cat server.crt

kubectl -n kube-system create secret tls kubi --key server-key.pem --cert server.crt

kubectl -n kube-system create secret generic kubi-encryption-secret --from-file=./test/ecdsa-key.pem --from-file=./test/ecdsa-public.pem
kubectl -n kube-system create secret generic kubi-secret  --from-literal ldap_passwd='password'

# set up dev-kubi env 
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-deployment.yml
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-crds.yml
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-prerequisites.yml
kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-local-config.yml


kubectl -n kube-system get secrets $( kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['ca\.crt']}" | base64 -d > ca.crt
kubectl -n kube-system get secrets $( kubectl -n kube-system get sa kubi-user -o "jsonpath={.secrets[0].name}") -o "jsonpath={.data['token']}" | base64 -d > token
kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.crt']}" | base64 -d > tls.crt
kubectl -n kube-system get secrets kubi -o "jsonpath={.data['tls\.key']}" | base64 -d > tls.key
kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-key\.pem']}" | base64 -d > ecdsa-key.pem
kubectl -n kube-system get secrets kubi-encryption-secret -o "jsonpath={.data['ecdsa-public\.pem']}" | base64 -d > ecdsa-public.pem

sudo mkdir -p  /var/run/secrets/{certs,ecdsa,kubernetes.io}
sudo mkdir  /var/run/secrets/kubernetes.io/serviceaccount
sudo mv ca.crt  /var/run/secrets/kubernetes.io/serviceaccount/
sudo mv token  /var/run/secrets/kubernetes.io/serviceaccount/
sudo mv tls.crt  /var/run/secrets/certs/
sudo mv tls.key  /var/run/secrets/certs/
sudo mv ecdsa-public.pem /var/run/secrets/ecdsa/
sudo mv ecdsa-key.pem /var/run/secrets/ecdsa/
sudo ls /var/run/secrets/kubernetes.io/serviceaccount/
sudo ls /var/run/secrets/ecdsa/ 
sudo ls /var/run/secrets/certs/

