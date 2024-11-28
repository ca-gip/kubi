
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

- [Kubi](#kubi)
  - [Index](#index)
- [General](#general)
  - [Parameters](#parameters)
  - [Versioning](#versioning)
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
|  **LDAP_PAGE_SIZE**                |  *LDAP page size, 1000...*           | `1000                           `| `no   `     | `1000  `    |
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
|  **PODSECURITYADMISSION_ENFORCEMENT**                     | *PodSecurityAdmission  Enforcement*                     | `restricted`                 | `no   `     | `restricted  `           |
|  **PODSECURITYADMISSION_WARNING**                     | *PodSecurityAdmission Warning*                     | `restricted`                 | `no   `     | `restricted  `           |
|  **PODSECURITYADMISSION_AUDIT**                     | *PodSecurityAdmission Audit*                     | `restricted`                 | `no   `     | `restricted  `           |
|  **PRIVILEGED_NAMESPACES**                     | *Namespaces allowed to use privileged annotation*                     | `native-development`                 | `no   `     | -           |
## Versioning
 
Since version v1.24.0, we have decided to modify the naming of versions for ease of reading and understanding.
Example: v1.24.0 means that the operator was developed for Kubernetes version 1.24 and that the last 0 corresponds to the various patches we have made to the operator.
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

# Contributing

- [Contributing to kubi](https://github.com/ca-gip/kubi/blob/master/CONTRIBUTING.md).
 


 <hr/>
<p align=center  style="background-color:#333333 !important;">
  <a href="https://www.jetbrains.com/">
  Developed with
  <br/>
  <img align="center" src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.png" alt="drawing" width="100"/>
  </a>
</p>
