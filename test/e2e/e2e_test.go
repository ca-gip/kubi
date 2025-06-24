/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//lint:file-ignore U1000 Ignore all unused code, it's generated

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ca-gip/kubi/internal/services"
	kubiv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	kubiclientset "github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/ca-gip/kubi/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1Types "k8s.io/api/core/v1"

	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// namespace where the project is deployed in
const namespace = "kube-system"
const testProjectName = "projet-toto-development"

// serviceAccountName created for the project
const serviceAccountName = "test-kubebuilder-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "test-kubebuilder-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "test-kubebuilder-metrics-binding"

var clientset *kubernetes.Clientset
var kubiclient *kubiclientset.Clientset
var kubiConfig *corev1Types.ConfigMap
var testProject kubiv1.Project
var testKubeConfigPath string
var clusterConfig *rest.Config
var tokenIssuer *services.TokenIssuer
var _ = Describe("Manager", Ordered, func() {
	//var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// installing CRDs, and deploying the controller.
	BeforeAll(func() {

		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				panic(err.Error())
			}
			kubeconfig = filepath.Join(homeDir, ".kube", "config")
		}
		//fmt.Printf("KUBECONFIG PATH: %s\n", kubeconfig)
		// use the current context in kubeconfig
		var err error
		clusterConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err.Error())
		}

		// create the clientset
		clientset, err = kubernetes.NewForConfig(clusterConfig)
		if err != nil {
			panic(err.Error())
		}
		kubiConfig, err = clientset.CoreV1().ConfigMaps("kube-system").Get(context.TODO(), "kubi-config", v1.GetOptions{})

		if err != nil {
			panic(err.Error())
		}

		kubiclient, err = kubiclientset.NewForConfig(clusterConfig)
		if err != nil {
			panic(err.Error())
		}
		currDir, _ := os.Getwd()
		testKubeConfigPath = filepath.Join(currDir, "generated-kubeconfig")

		ecdsaPem, err := os.ReadFile("/tmp/kubi/ecdsa/ecdsa-key.pem")
		fmt.Printf("ecdsaPemErr: %s\n", err)
		ecdsaPubPem, _ := os.ReadFile("/tmp/kubi/ecdsa/ecdsa-public.pem")
		fmt.Printf("ecdsaPubErr: %s\n", err)
		tokenIssuer, err = services.NewTokenIssuer(
			ecdsaPem,
			ecdsaPubPem,
			"4h",
			"720h", // This had to be included in refactor. TODO: Check side effects
			"intranet",
			"https://kubernetes.default.svc.cluster.local",
			"cagip",
		)
		if err != nil {
			panic(err.Error())
		}
		// By("creating manager namespace")
		// cmd := exec.Command("kubectl", "create", "ns", namespace)
		// _, err := utils.Run(cmd)
		// Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		// By("installing CRDs")
		// cmd = exec.Command("make", "install")
		// _, err = utils.Run(cmd)
		// Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		// By("deploying the controller-manager")
		// cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		// _, err = utils.Run(cmd)
		// Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		// By("cleaning up the curl pod for metrics")
		// cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		// _, _ = utils.Run(cmd)

		// By("undeploying the controller-manager")
		// cmd = exec.Command("make", "undeploy")
		// _, _ = utils.Run(cmd)

		// By("uninstalling CRDs")
		// cmd = exec.Command("make", "uninstall")
		// _, _ = utils.Run(cmd)

		// By("removing manager namespace")
		// cmd = exec.Command("kubectl", "delete", "ns", namespace)
		// _, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		// specReport := CurrentSpecReport()
		// if specReport.Failed() {
		// 	By("Fetching controller manager pod logs")
		// 	cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
		// 	controllerLogs, err := utils.Run(cmd)
		// 	if err == nil {
		// 		_, _ = fmt.Fprintf(GinkgoWriter, fmt.Sprintf("Controller logs:\n %s", controllerLogs))
		// 	} else {
		// 		_, _ = fmt.Fprintf(GinkgoWriter, fmt.Sprintf("Failed to get Controller logs: %s", err))
		// 	}

		// 	By("Fetching Kubernetes events")
		// 	cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
		// 	eventsOutput, err := utils.Run(cmd)
		// 	if err == nil {
		// 		_, _ = fmt.Fprintf(GinkgoWriter, fmt.Sprintf("Kubernetes events:\n%s", eventsOutput))
		// 	} else {
		// 		_, _ = fmt.Fprintf(GinkgoWriter, fmt.Sprintf("Failed to get Kubernetes events: %s", err))
		// 	}

		// 	By("Fetching curl-metrics logs")
		// 	cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
		// 	metricsOutput, err := utils.Run(cmd)
		// 	if err == nil {
		// 		_, _ = fmt.Fprintf(GinkgoWriter, fmt.Sprintf("Metrics logs:\n %s", metricsOutput))
		// 	} else {
		// 		_, _ = fmt.Fprintf(GinkgoWriter, fmt.Sprintf("Failed to get curl-metrics logs: %s", err))
		// 	}

		// 	By("Fetching controller manager pod description")
		// 	cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
		// 	podDescription, err := utils.Run(cmd)
		// 	if err == nil {
		// 		fmt.Println("Pod description:\n", podDescription)
		// 	} else {
		// 		fmt.Println("Failed to describe controller pod")
		// 	}
		// }
	})

	SetDefaultEventuallyTimeout(30 * time.Second) // 2 * time.Minute
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Kubi operator", func() {
		It("should run successfully", func() {
			By("validating that the kubi operator pod is running as expected")
			verifyKubiOperatorUp := func(g Gomega) {
				operatorPods, err := clientset.CoreV1().Pods("kube-system").List(context.TODO(),
					v1.ListOptions{
						LabelSelector: "app=kubi-operator",
					})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve Kubi operator pod information")
				g.Expect(operatorPods.Items).To(HaveLen(1), "There should only be one pod in the kubi operator deployment")
				pod := operatorPods.Items[0]
				g.Expect(pod.Status.Phase).To(Equal(corev1Types.PodRunning), "The kubi-operator pod should be in Running state")
			}
			Eventually(verifyKubiOperatorUp).Should(Succeed())
		})

		It("should have created all appropriate objects (project, namespace, service account, rolebinding, network policies)", func() {
			By("validating that the kubi project has been created by kubi-operator")
			verifyTestKubiProjectHasBeenCreated := func(g Gomega) {
				projects, err := kubiclient.CagipV1().Projects().List(context.TODO(), v1.ListOptions{
					LabelSelector: "creator=kubi",
				})

				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve projects")
				g.Expect(projects.Items).To(HaveLen(1), "expected 1 Kubi project")
				testProject = projects.Items[0]
				g.Expect(testProject.Name).To(Equal(testProjectName))
				g.Expect(testProject.Spec.Environment).To(Equal("development"), "the spec environment is not equal to development")
				g.Expect(testProject.Spec.Project).To(Equal("projet-toto"), "the spec project is not equal to projet-toto")
				g.Expect(testProject.Spec.SourceEntity).To(Equal("DL_KUB_CAGIPHP_PROJET-TOTO-DEV_ADMIN"), "the spec sourceEntity is not equal to DL_KUB_CAGIPHP_PROJET-TOTO-DEV_ADMIN")
				g.Expect(testProject.Spec.Stages).To(Equal([]string{"scratch", "staging", "stable"}), "the spec stages is not equal to [\"scratch\",\"staging\",\"stable\"]")
				g.Expect(testProject.Spec.Tenant).To(Equal("cagip"), "the spec tenant is not equal to cagip")
			}

			By("validating that the test namespace has been created by kubi-operator")
			verifyTestNamespaceHasBeenCreated := func(g Gomega) {
				// Get the name of the kubi pod
				namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), v1.ListOptions{
					LabelSelector: "creator=kubi",
				})

				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve namespaces")
				g.Expect(namespaces.Items).To(HaveLen(1), "expected 1 Kubi namespace")
				ns := namespaces.Items[0]
				g.Expect(ns.Name).To(Equal(testProjectName))
				g.Expect(ns.Labels["environment"]).To(Equal("development"), "the label environment is not equal to development")
				g.Expect(ns.Labels["pod-security.kubernetes.io/audit"]).To(Equal("restricted"), "the label pod-security.kubernetes.io/audit is not equal to restricted")
				g.Expect(ns.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("baseline"), "the label pod-security.kubernetes.io/enforce is not equal to baseline")
				g.Expect(ns.Labels["pod-security.kubernetes.io/warn"]).To(Equal("restricted"), "the label pod-security.kubernetes.io/warn is not equal to restricted")
				g.Expect(ns.Labels["quota"]).To(Equal("managed"), "the label quota is not equal to managed")
				g.Expect(ns.Labels["type"]).To(Equal("customer"), "the label type is not equal to customer")
			}

			By("validating that the service account has been created by kubi-operator")
			verifyTestServiceAccountHasBeenCreated := func(g Gomega) {
				sas, err := clientset.CoreV1().ServiceAccounts(testProjectName).List(context.TODO(), v1.ListOptions{
					LabelSelector: "creator=kubi",
				})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve service accounts")
				g.Expect(sas.Items).To(HaveLen(1), "expected 1 sa created by kubi operator")
				sa := sas.Items[0]
				g.Expect(sa.Name).To(Equal("service"))
			}

			By("validating that the rolebindings have been created by kubi-operator")
			verifyTestRolebindingsHaveBeenCreated := func(g Gomega) {
				rbs, err := clientset.RbacV1().RoleBindings(testProjectName).List(context.TODO(), v1.ListOptions{
					LabelSelector: "creator=kubi",
				})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve role bindings")
				g.Expect(rbs.Items).To(HaveLen(4), "expected 4 rolebindings created by kubi operator")
				var defaultSa, nsAdminSa, nsServiceBindingSa, viewSa *rbacv1.RoleBinding
				for _, s := range rbs.Items {
					switch s.Name {
					case "default-sa":
						defaultSa = &s
					case "namespaced-admin":
						nsAdminSa = &s
					case "namespaced-service-binding":
						nsServiceBindingSa = &s
					case "view":
						viewSa = &s
					}
				}
				g.Expect(nsAdminSa).NotTo(Equal(nil))
				g.Expect(nsServiceBindingSa).NotTo(Equal(nil))
				g.Expect(viewSa).NotTo(Equal(nil))

				g.Expect(defaultSa.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}), "for rb default-sa, expected binding the clusterRole pod-reader")
				g.Expect(defaultSa.Subjects).To(Equal([]rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: testProjectName}}))

				g.Expect(nsAdminSa.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "namespaced-admin"}), "for rb namespaced-admin, expected binding the clusterRole namespaced-admin")

				nsAdminSaSubjects := []rbacv1.Subject{
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "projet-toto-development-admin"},
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "application:masters"},
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "ops:masters"},

					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: testProject.Spec.SourceEntity},
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: strings.ToUpper(kubiConfig.Data["LDAP_APP_GROUPBASE"])},
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: strings.ToUpper(kubiConfig.Data["LDAP_CUSTOMER_OPS_GROUPBASE"])},
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: strings.ToUpper(kubiConfig.Data["LDAP_OPS_GROUPBASE"])},
				}
				g.Expect(nsAdminSa.Subjects).To(Equal(nsAdminSaSubjects), "for rb namespaced-admin, expected binding to groups projet-toto-development:admin application:master and ops:masters  - TODO")

				g.Expect(nsServiceBindingSa.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "namespaced-service"}), "for rb namespaced-service, expected binding the clusterRole namespaced-service")

				nsServiceBindingSaSubjects := []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "service", Namespace: testProjectName},
				}
				g.Expect(nsServiceBindingSa.Subjects).To(Equal(nsServiceBindingSaSubjects), "for rb namespaced-service, expected binding to the service account service")

				g.Expect(viewSa.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"}), "for rb view, expected binding the clusterRole view")

				viewSaSubjects := []rbacv1.Subject{
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "application:view"},
					{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: strings.ToUpper(kubiConfig.Data["LDAP_VIEWER_GROUPBASE"])},
				}
				g.Expect(viewSa.Subjects).To(Equal(viewSaSubjects), "for rb view, expected binding to the group application:view - TODO")
			}
			Eventually(verifyTestKubiProjectHasBeenCreated).Should(Succeed())
			Eventually(verifyTestNamespaceHasBeenCreated).Should(Succeed())
			Eventually(verifyTestServiceAccountHasBeenCreated).Should(Succeed())
			Eventually(verifyTestRolebindingsHaveBeenCreated).Should(Succeed())
		})

		It("should watch the network policy config objects and create the network policies", func() {
			By("validating that kubi operator has created the default network policy in the test namespace")
			verifyNetworkPoliciesHaveBeenCreated := func(g Gomega) {
				netpol, err := clientset.NetworkingV1().NetworkPolicies(testProjectName).Get(context.TODO(), "kubi-default", v1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve network policy kubi-default")

				udpProtocol := corev1Types.ProtocolUDP
				tcpProtocol := corev1Types.ProtocolTCP
				port636 := intstr.FromInt(636)
				port389 := intstr.FromInt(389)
				port123 := intstr.FromInt(123)
				port53 := intstr.FromInt(53)
				egressRules := []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{Protocol: &udpProtocol, Port: &port636},
							{Protocol: &tcpProtocol, Port: &port636},
							{Protocol: &udpProtocol, Port: &port389},
							{Protocol: &tcpProtocol, Port: &port389},
							{Protocol: &udpProtocol, Port: &port123},
							{Protocol: &tcpProtocol, Port: &port123},
							{Protocol: &udpProtocol, Port: &port53},
							{Protocol: &tcpProtocol, Port: &port53},
							{Protocol: &udpProtocol, Port: &port53},
						},
					},
					{
						To: []netv1.NetworkPolicyPeer{
							{
								PodSelector: &v1.LabelSelector{},
							},
							{
								NamespaceSelector: &v1.LabelSelector{
									MatchLabels: map[string]string{
										"name": "kube-system",
									},
								},
								PodSelector: &v1.LabelSelector{
									MatchLabels: map[string]string{
										"component": "kube-apiserver",
										"tier":      "control-plane",
									},
								},
							},
							{
								IPBlock: &netv1.IPBlock{
									CIDR: "172.20.0.0/16",
								},
							},
						},
					},
				}
				g.Expect(netpol.Spec.Egress).To(Equal(egressRules))

				ingressRules := []netv1.NetworkPolicyIngressRule{
					{
						From: []netv1.NetworkPolicyPeer{
							{
								PodSelector: &v1.LabelSelector{},
							},
							{
								NamespaceSelector: &v1.LabelSelector{
									MatchLabels: map[string]string{
										"name": "ingress-nginx",
									},
								},
								PodSelector: &v1.LabelSelector{},
							},
							{
								NamespaceSelector: &v1.LabelSelector{
									MatchLabels: map[string]string{
										"name": "monitoring",
									},
								},
								PodSelector: &v1.LabelSelector{},
							},
						},
					},
				}
				g.Expect(netpol.Spec.Ingress).To(Equal(ingressRules))
				g.Expect(netpol.Spec.PodSelector).To(Equal(v1.LabelSelector{}))
				g.Expect(netpol.Spec.PolicyTypes).To(Equal([]netv1.PolicyType{
					"Ingress", "Egress",
				}))
			}
			Eventually(verifyNetworkPoliciesHaveBeenCreated).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	Context("kubi api", func() {
		It("kubi api and kubi authentication webhook should run successfully", func() {
			By("validating that the kubi API + Authn webhook pod is running as expected")
			verifyKubiAPIAndAuthnWebhookUp := func(g Gomega) {
				// Get the name of the kubi pod
				apiWebhookPods, err := clientset.CoreV1().Pods("kube-system").List(context.TODO(),
					v1.ListOptions{
						LabelSelector: "app=kubi",
					})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve Kubi operator pod information")
				g.Expect(apiWebhookPods.Items).To(HaveLen(2), "expected 2 Kubi API + Authn Webhook pods running")
				pod1 := apiWebhookPods.Items[0]
				pod2 := apiWebhookPods.Items[1]
				g.Expect(pod1.Status.Phase).To(Equal(corev1Types.PodRunning), "Incorrect Kubi API + Authn Webhook pod status")
				g.Expect(pod2.Status.Phase).To(Equal(corev1Types.PodRunning), "Incorrect Kubi API + Authn Webhook pod status")
			}
			Eventually(verifyKubiAPIAndAuthnWebhookUp).Should(Succeed())
		})

		It("should generate a kubeconfig which gives appropriate rights", func() {
			By("validating that kubi api has generated a kubeconfig")
			verifyKubeconfigFileHasBeenGenerated := func(g Gomega) {
				// Get the name of the kubi pod
				/*cmd := exec.Command("kubectl", "-n", "kube-system", "exec", "curl-pod", "--",
					"curl", "-u", "developer1:somepass", "-X", "GET", "https://kubi-api.kube-system.svc.cluster.local:8000/config", "-k", "-s",
				)*/
				cmd := exec.Command("curl", "-u", "developer1:somepass", "-k", "-s", "https://localhost:30003/config")

				//currentDir, _ := os.Getwd()
				//fmt.Printf("CURRENT_DIR:%s\n", currentDir)
				kubeconfig, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to generate kubeconfig")

				//testKubeConfigPath := "generated-kubeconfig"
				// We need to patch the server url
				//patched := regexp.MustCompile(`^(\s*server:\s*)(.*)$`).ReplaceAllString(kubeconfig, `$1 serverUrl`)
				//patched := regexp.MustCompile(`server: (.*)`).ReplaceAllString(kubeconfig, `serverUrl`)
				patched := regexp.MustCompile(`(\s*server:\s*)(.*)`).ReplaceAllString(kubeconfig, fmt.Sprintf(`${1}%s`, clusterConfig.Host))
				//os.WriteFile("toto.txt", []byte(patched), 0644)
				err = os.WriteFile(testKubeConfigPath, []byte(patched), 0644)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to save the generated kubeconfig file in local")
				fmt.Printf("Generated kubeconfig file in %s", testKubeConfigPath)
				time.Sleep(2 * time.Second) // Wait a bit for the change to take effect
			}

			By("validating that the generated kubeconfig allows authentication of the user")
			verifyKubeconfigFileAllowsAuthentication := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "po", "-n", "projet-toto-development")
				env := []string{fmt.Sprintf("KUBECONFIG=%s", testKubeConfigPath)}

				cmdOutput, err := utils.Run(cmd, env)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to execute command inside kubectl test pod")
				// Typical messages when you present a bad token or the API server cannot authenticate you. We verify that it does not contain such stuff.
				// kubectl auth can-i get pod -n projet-toto-development
				// error: You must be logged in to the server (Unauthorized)
				// kubectl get po -n projet-toto-development
				// error: You must be logged in to the server (Unauthorized)
				// Unable to connect to the server: tls: failed to verify certificate: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")

				//		g.Expect(cmdOutput).NotTo(ContainSubstring("error: You must be logged in to the server (Unauthorized)", "Unauthorized", "failed to verify certificate", "Unable to connect to the server", "failed", "signed by unknown authority"), "Failed to authenticate the command with generated kubeconfig")

				g.Expect(cmdOutput).NotTo(ContainSubstring("error: You must be logged in to the server (Unauthorized)"), "Failed to authenticate the command with generated kubeconfig")
				g.Expect(cmdOutput).NotTo(ContainSubstring("Unauthorized"), "Failed to authenticate the command with generated kubeconfig")
				g.Expect(cmdOutput).NotTo(ContainSubstring("failed to verify certificate", "Unable to connect to the server", "failed", "signed by unknown authority"), "Failed to authenticate the command with generated kubeconfig")
				g.Expect(cmdOutput).NotTo(ContainSubstring("failed"), "Failed to authenticate the command with generated kubeconfig")
				g.Expect(cmdOutput).NotTo(ContainSubstring("signed by unknown authority"), "Failed to authenticate the command with generated kubeconfig")

			}

			Eventually(verifyKubeconfigFileHasBeenGenerated).Should(Succeed())
			Eventually(verifyKubeconfigFileAllowsAuthentication).Should(Succeed())
		})
		It("should generate tokens with appropriate contents (auths, and groups)", func() {
			By("generating an appropriate token for admin user")
			verifyAdminUsersHaveAppropriateRights := func(g Gomega) {
				cmd := exec.Command("curl", "-u", "admin-kube1:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")
				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeTrue())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("ADMIN_KUBERNETES"))
			}
			By("generating an appropriate token for ops user")
			verifyOpsUsersHaveAppropriateRights := func(g Gomega) {
				cmd := exec.Command("curl", "-u", "cloudops-kube2:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeTrue())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("CLOUDOPS_KUBERNETES"))
			}
			By("generating an appropriate token for service account user")
			verifyServiceAccountsHaveAppropriateRights := func(g Gomega) {
				cmd := exec.Command("curl", "-u", "service-account-kubernetes-team:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeTrue())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("DL_KUB_TRANSVERSAL_SERVICE"))
			}
			By("generating an appropriate token for cluster viewer user")
			verifyViewerUsersHaveAppropriateRights := func(g Gomega) {
				cmd := exec.Command("curl", "-u", "product-owner2:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeTrue())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("DL_KUB_CAGIPHP_VIEW"))
				fmt.Printf("Decoded token: %+v\n", *decoded)
			}
			By("generating an appropriate token for appops user")
			verifyClusterAppopsHaveAppropriateRights := func(g Gomega) {
				cmd := exec.Command("curl", "-u", "developer1:somepass", "-k", "-s", "https://localhost:30003/token")
				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeTrue())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf(
					"CAGIP_MEMBERS",
					"DL_KUB_CAGIPHP_PROJET-TOTO-DEV_ADMIN",
					"DL_KUB_CAGIPHP_OPS",
				))
			}
			By("generating an appropriate token for project admin user")
			verifyProjectUsersHaveAppropriateRights := func(g Gomega) {
				cmd := exec.Command("curl", "-u", "developer4:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(HaveExactElements(&types.Project{
					Project:     "projet-toto",
					Role:        "admin",
					Source:      "",
					Environment: "development",
					Contact:     "",
				}))
				g.Expect(decoded.Groups).To(ConsistOf("DL_KUB_CAGIPHP_PROJET-TOTO-DEV_ADMIN"))
				fmt.Printf("Decoded token: %+v\n", *decoded)
			}
			By("generating an appropriate token for user from eligible group 1")
			verifyRandomEligibleUser1HaveAppropriateRights := func(g Gomega) {
				// network-dev1 is only a member of a group with
				// eligible parents("TEAMS" in this case) specified in config
				cmd := exec.Command("curl", "-u", "network-dev1:somepass", "-k", "-s", "https://localhost:30003/token")
				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("NETWORK"))
			}
			By("generating an appropriate token for user from eligible group 2")
			verifyRandomEligibleUser2HaveAppropriateRights := func(g Gomega) {
				// platform-dev1 is only a member of a group with
				// eligible parents("CONTAINER" in this case) specified in config
				cmd := exec.Command("curl", "-u", "platform-dev1:somepass", "-k", "-s", "https://localhost:30003/token")
				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("PLATFORM"))
			}
			By("generating an appropriate token for user with no access")
			verifyRandomUsersHaveAppropriateRights := func(g Gomega) {
				// random-user is not a member of any interesting groups:
				// cluster-wide (admin, viewer, appops, cloudops..),
				// project groups (DL_KUB...) or groups with eligible parents specified in config
				cmd := exec.Command("curl", "-u", "random-user:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				_, err = tokenIssuer.VerifyToken(token)
				g.Expect(err).To(HaveOccurred(), "The token to verify should be invalid")
				g.Expect(token).To(Equal("Unauthorized\n"))
			}
			By("generating an appropriate token for user with no access")
			verifyRandomAlmostEligibleUsersHaveAppropriateRights := func(g Gomega) {
				// division4-user1 is a member of a group that shares the same CN (CLOUDOPS_KUBERNETES)
				// with an eligible group: He should not have ops-access (or any other special access)
				// to the cluster but since its group belong to an eligible parent (OU=TEAMS,OU=GROUPS,DC=EXAMPLE,DC=ORG)
				// he receives a token

				cmd := exec.Command("curl", "-u", "division4-user1:somepass", "-k", "-s", "https://localhost:30003/token")

				token, err := utils.Run(cmd, nil)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to get token")

				decoded, err := tokenIssuer.VerifyToken(token)

				g.Expect(err).NotTo(HaveOccurred(), "Failed to verify the token")
				g.Expect(decoded.AdminAccess).To(BeFalse())
				g.Expect(decoded.ApplicationAccess).To(BeFalse())
				g.Expect(decoded.OpsAccess).To(BeFalse())
				g.Expect(decoded.ServiceAccess).To(BeFalse())
				g.Expect(decoded.ViewerAccess).To(BeFalse())
				g.Expect(decoded.Auths).To(BeEmpty())
				g.Expect(decoded.Groups).To(ConsistOf("CLOUDOPS_KUBERNETES"))

			}

			Eventually(verifyAdminUsersHaveAppropriateRights).Should(Succeed())
			Eventually(verifyOpsUsersHaveAppropriateRights).Should(Succeed())
			Eventually(verifyServiceAccountsHaveAppropriateRights).Should(Succeed())
			Eventually(verifyViewerUsersHaveAppropriateRights).Should(Succeed())
			Eventually(verifyClusterAppopsHaveAppropriateRights).Should(Succeed())
			Eventually(verifyProjectUsersHaveAppropriateRights).Should(Succeed())
			Eventually(verifyRandomEligibleUser1HaveAppropriateRights).Should(Succeed())
			Eventually(verifyRandomEligibleUser2HaveAppropriateRights).Should(Succeed())
			Eventually(verifyRandomUsersHaveAppropriateRights).Should(Succeed())
			Eventually(verifyRandomAlmostEligibleUsersHaveAppropriateRights).Should(Succeed())
		})
	})

	Context("kubi authentication webhook and K8S+Kubi RBAC", func() {

		// We already tested that the authentication webhook (called by api server : refer to scheme in https://kubernetes.io/docs/concepts/security/controlling-access/)
		// authenticates a legit user. It's almost impossible to split the tests between kubi-api and kubi-authentication-webhook
		// as they are highly correlated. Kubi authentication webhook determines if the token has been signed by the private CA generated.
		// We will test if we are authenticated authorized to do some stuff, when legit, and not authorized/authenticated when non-legit.

		It("should authenticate/authorize or not depending if the user is legit and if RBAC permits it", func() {
			By("validating that legit user gets authenticated and is authorized to perform legit action")
			verifyLegitUserGetsAuthenticatedAndIsAuthorizedWhenLegitAction := func(g Gomega) {
				cmd := exec.Command("kubectl", "auth", "can-i", "get", "pod", "-n", "projet-toto-development")

				env := []string{fmt.Sprintf("KUBECONFIG=%s", testKubeConfigPath)}

				cmdOutput, err := utils.Run(cmd, env)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to execute 'kubectl auth can-i' command to determine if action possible")
				g.Expect(cmdOutput).To(Equal("yes\n"), "Failed to validate that legit user is authorized to perform legit action")

			}

			By("validating that legit user gets authenticated and is not authorized to perform non-legit action")
			verifyLegitUserGetsAuthenticatedAndIsNotAuthorizedWhenNonLegitAction := func(g Gomega) {

				env := []string{fmt.Sprintf("KUBECONFIG=%s", testKubeConfigPath)}
				cmd := exec.Command("kubectl", "auth", "can-i", "get", "pod", "-n", "projet-titi-development")

				cmdOutput, _ := utils.Run(cmd, env)
				g.Expect(cmdOutput).To(Equal("no\n"), "Failed to validate that legit user is not authorized to perform non-legit action")
			}

			By("validating that legit user gets authenticated and is not authorized to perform non-legit action")
			verifyNonLegitUserDoesNotGetAuthenticated := func(g Gomega) {
				// Fixtures : we change the kubeconfig file to use a non-legit token
				cmd := exec.Command("kubectl", "config", "set", "users.developer1_https://kubernetes.default.svc.cluster.local.token",
					"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdXRocyI6W10sInVzZXIiOiJkZXZlbG9wZXIxIiwiZW1haWwiOiIiLCJhZG1pbkFjY2VzcyI6ZmFsc2UsImFwcEFjY2VzcyI6dHJ1ZSwib3BzQWNjZXNzIjpmYWxzZSwidmlld2VyQWNjZXNzIjpmYWxzZSwic2VydmljZUFjY2VzcyI6ZmFsc2UsImxvY2F0b3IiOiJpbnRyYW5ldCIsImVuZFBvaW50Ijoia3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwidGVuYW50IjoiY2FnaXAiLCJzY29wZXMiOiIiLCJleHAiOjE3NDE4MDE5NzMsImlzcyI6Ikt1YmkgU2VydmVyIn0.ATHtSzFUsiF0k2OACGefUCvJ57t9uKKk_u7CsXbF3sCYC7h4tr6di63aiXKWi6ssp_tX4amp96a6JvKG6AwAd1f8AVsyip9WcPVjjABM6hdhT5KiLM2n9qtVHZ97IImYeZq86LDUjioOAoNO1jYHP0eRxOmV2YM84FmRRYbVwwUf12ul",
				)

				env := []string{fmt.Sprintf("KUBECONFIG=%s", testKubeConfigPath)}
				out, err := utils.Run(cmd, env)
				fmt.Printf("Config_Update: %s\n", out)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to change the kubeconfig to use a non-legit token")

				cmd = exec.Command("kubectl", "auth", "can-i", "get", "pod", "-n", "projet-toto-development")

				cmdOutput, err := utils.Run(cmd, env)
				g.Expect(err).To(HaveOccurred(), "The command 'kubectl auth can-i' to determine if action possible should have failed")
				// Typical messages when you present a bad token or the API server cannot authenticate you. We verify that it does not contain such stuff.
				// kubectl auth can-i get pod -n projet-toto-development
				// error: You must be logged in to the server (Unauthorized)
				// kubectl get po -n projet-toto-development
				// error: You must be logged in to the server (Unauthorized)
				// Unable to connect to the server: tls: failed to verify certificate: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")
				g.Expect(cmdOutput).To(ContainSubstring("error: You must be logged in to the server (Unauthorized)"), "Failed to deny access to non-legit user/token")
				g.Expect(cmdOutput).To(ContainSubstring("Unauthorized"), "Failed to deny access to non-legit user/token")
			}

			Eventually(verifyLegitUserGetsAuthenticatedAndIsAuthorizedWhenLegitAction).Should(Succeed())
			Eventually(verifyLegitUserGetsAuthenticatedAndIsNotAuthorizedWhenNonLegitAction).Should(Succeed())
			Eventually(verifyNonLegitUserDoesNotGetAuthenticated).Should(Succeed())

		})

	})

})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal([]byte(output), &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd, nil)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
