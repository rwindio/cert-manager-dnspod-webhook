# Tencent Cloud DNS ACME webhook

This is a Webhook implementation used by Cert Manager in conjunction with Tencent Cloud DNS.

For more detailed information about webhook, please refer to the certificate manager documentation: https://certificate manager.io/docs/concepts/webhook/

## Usage
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
Please note:
Test environment use: ```https://acme-staging-v02.api.letsencrypt.org/directory```
Production environment use: ```https://acme-v02.api.letsencrypt.org/directory```
The name of solver to use is ```dnspod-solver```. You can create an issuer as below :
``` yaml
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
### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

An example Go test file has been provided in [main_test.go](https://github.com/cert-manager/webhook-example/blob/master/main_test.go).

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com. make test
```

The example file has a number of areas you must fill in and replace with your
own options in order for tests to pass.
