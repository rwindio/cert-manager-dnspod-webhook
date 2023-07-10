# Tencent Cloud DNS ACME webhook

This is a Webhook implementation used by Cert Manager in conjunction with Tencent Cloud DNS.

For more detailed information about webhook, please refer to the certificate manager documentation: https://certificate manager.io/docs/concepts/webhook/
## Docker usage
### Update Mirror
``` bash
docker pull reodwind/dnspod-webhook:latest
```
or
``` bash
docker pull ghcr.io/reodwind/dnspod-webhook:latest
```
## Helm Usage
### Installation
``` bash
helm repo add dnspod-webhook https://reodwind.github.io/cert-manager-dnspod-webhook
helm repo update
helm install dnspod-webhook dnspod-webhook/dnspod-webhook --namespace cert-manager
```
Create a key for Tencent credentials:
``` yaml
apiVersion: v1
kind: Secret
metadata:
  name: dnspod-secret
data:
  access-token: token
  secret-key: key
```
or
``` bash
kubectl create secret generic dnspod-secret --from-literal="access-token=yourtoken" --from-literal="secret-key=yoursecretkey"
```
### Create an issuer
The name of solver to use is ```alidns-solver```. You can create an issuer as below :
``` yam
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    email: admin@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt
    solvers:
    - dns01:
        webhook:
            config:
              secretIdSecretRef:
                key: access-token
                name: dnspod-secret
              secretKeySecretRef:
                key: secret-key
                name: dnspod-secret
            groupName: acme.dnspod.ca
            solverName: dnspod-solver
```
### Create the certification
create an certification using ClusterIssuer as below :
``` yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-tls
  namespace: cert-manager
spec:
  secretName: example-tls
  dnsNames:
  - example.io
  - "*.example.io"
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
```