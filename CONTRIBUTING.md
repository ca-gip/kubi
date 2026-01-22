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

  - Deploy manifest (CRD, prerequisites,local-config) of kubi
  ```
  cd kubi
  kubectl apply -f deployments/kube-deployment.yml
  kubectl apply -f deployments/kube-crds.yml
  kubectl apply -f deployments/kube-prerequisites.yml
  kubectl apply -f deployments/kube-local-config.yml
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

## Test your code 
The repository contains unit tests, lint tests and an E2E test, which can run in local and runs on each commit, on the CI. 
```
make test // executes the non-E2E tests (unit tests, linting, etc)
make test-e2E // executes the E2E test. For it to run, some prerequisites are needed
```

Prerequisites for E2E test: 
- in the CI, they are installed by some github actions, or by a run command. 
- in local, dependencies today have to be managed manually. *TODO : could be nice to add them in a Makefile target*

List of dependencies: 
- kind: follow docs https://kind.sigs.k8s.io/docs/user/quick-start/
- docker: follow docs https://docs.docker.com/engine/install/ubuntu/
- kubectl: follow docs https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
- helm: `snap install helm`
- helm plugin helm-images: `helm plugin install https://github.com/nikhilsbhat/helm-images`
- sleep: present in Ubuntu
- cfssl and cfssljson: `./scripts/install-cfssl.sh`
- go: `sudo snap install go --classic`
- goreleaser: `go install github.com/goreleaser/goreleaser/v2@latest`
- openssl: `sudo apt install openssl`

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

