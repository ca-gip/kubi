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
	"strings"
	"time"

	kubiv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	kubiclientset "github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
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
		fmt.Printf("ecdsaPubErr: %s\n", err)
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
	// Add this test context after the existing tests

	// Remove the kerrors import and replace the checks

	Context("Project deletion", func() {
		It("should delete all project resources when project is deleted", func() {
			By("verifying that all resources exist before deletion")
			verifyAllResourcesExist := func(g Gomega) {
				// Check namespace exists
				_, err := clientset.CoreV1().Namespaces().Get(context.TODO(), testProjectName, v1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Namespace should exist before deletion")

				// Check service account exists
				_, err = clientset.CoreV1().ServiceAccounts(testProjectName).Get(context.TODO(), "service", v1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Service account should exist before deletion")

				// Check role bindings exist
				rbs, err := clientset.RbacV1().RoleBindings(testProjectName).List(context.TODO(), v1.ListOptions{
					LabelSelector: "creator=kubi",
				})
				g.Expect(err).NotTo(HaveOccurred(), "Should be able to list role bindings")
				g.Expect(len(rbs.Items)).To(BeNumerically(">", 0), "Role bindings should exist before deletion")

				// Check network policy exists (if network policy is enabled)
				_, err = clientset.NetworkingV1().NetworkPolicies(testProjectName).Get(context.TODO(), "kubi-default", v1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Network policy should exist before deletion")
			}

			By("deleting the project")
			deleteProject := func(g Gomega) {
				err := kubiclient.CagipV1().Projects().Delete(context.TODO(), testProjectName, v1.DeleteOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to delete project")
			}

			By("verifying that all resources are cleaned up after project deletion")
			verifyAllResourcesDeleted := func(g Gomega) {
				// Check namespace is deleted
				_, err := clientset.CoreV1().Namespaces().Get(context.TODO(), testProjectName, v1.GetOptions{})
				g.Expect(err).To(HaveOccurred(), "Namespace should be deleted")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Namespace should return not found error")

				// Check service account is deleted
				_, err = clientset.CoreV1().ServiceAccounts(testProjectName).Get(context.TODO(), "service", v1.GetOptions{})
				g.Expect(err).To(HaveOccurred(), "Service account should be deleted")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Service account should return not found error")

				// Check network policy is deleted
				_, err = clientset.NetworkingV1().NetworkPolicies(testProjectName).Get(context.TODO(), "kubi-default", v1.GetOptions{})
				g.Expect(err).To(HaveOccurred(), "Network policy should be deleted")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Network policy should return not found error")
				//Check role bindings are deleted
				rbs, err := clientset.RbacV1().RoleBindings(testProjectName).List(context.TODO(), v1.ListOptions{
					LabelSelector: "creator=kubi",
				})
				g.Expect(err).NotTo(HaveOccurred(), "Should be able to list role bindings after deletion")
				g.Expect(len(rbs.Items)).To(Equal(0), "Role bindings should be deleted")
			}

			By("verifying project is removed from Kubernetes")
			verifyProjectDeleted := func(g Gomega) {
				_, err := kubiclient.CagipV1().Projects().Get(context.TODO(), testProjectName, v1.GetOptions{})
				g.Expect(err).To(HaveOccurred(), "Project should be deleted from Kubernetes")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Project should return not found error")
			}

			Eventually(verifyAllResourcesExist).Should(Succeed())
			Eventually(deleteProject).Should(Succeed())
			Eventually(verifyAllResourcesDeleted).Should(Succeed())
			Eventually(verifyProjectDeleted).Should(Succeed())
		})

		It("should handle deletion of non-existent project gracefully", func() {
			By("attempting to delete a non-existent project")
			deleteNonExistentProject := func(g Gomega) {
				err := kubiclient.CagipV1().Projects().Delete(context.TODO(), "non-existent-project", v1.DeleteOptions{})
				g.Expect(err).To(HaveOccurred(), "Deleting non-existent project should return error")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Deleting non-existent project should return NotFound error")
			}

			Eventually(deleteNonExistentProject).Should(Succeed())
		})

		It("should handle partial deletion failures gracefully", func() {
			By("creating a test project for deletion testing")
			createTestProject := func(g Gomega) {
				testProject := &kubiv1.Project{
					ObjectMeta: v1.ObjectMeta{
						Name: "test-deletion-project",
						Labels: map[string]string{
							"creator": "kubi",
						},
					},
					Spec: kubiv1.ProjectSpec{
						Environment:  "development",
						Project:      "test-deletion",
						SourceEntity: "TEST_GROUP",
						Stages:       []string{"scratch"},
						Tenant:       "cagip",
					},
				}

				_, err := kubiclient.CagipV1().Projects().Create(context.TODO(), testProject, v1.CreateOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create test project")
			}

			By("waiting for resources to be created")
			waitForResourceCreation := func(g Gomega) {
				// Wait for namespace to be created
				_, err := clientset.CoreV1().Namespaces().Get(context.TODO(), "test-deletion-project", v1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Test namespace should be created")

				// Wait for service account to be created
				_, err = clientset.CoreV1().ServiceAccounts("test-deletion-project").Get(context.TODO(), "service", v1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Test service account should be created")
			}

			By("manually deleting some resources to simulate partial deletion")
			simulatePartialDeletion := func(g Gomega) {
				// Delete the service account manually to simulate a scenario where not all resources can be deleted
				err := clientset.CoreV1().ServiceAccounts("test-deletion-project").Delete(context.TODO(), "service", v1.DeleteOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Should be able to manually delete service account")
			}

			By("deleting the project and verifying graceful handling")
			deleteProjectGracefully := func(g Gomega) {
				err := kubiclient.CagipV1().Projects().Delete(context.TODO(), "test-deletion-project", v1.DeleteOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "Should be able to delete project even with missing resources")
			}

			By("verifying cleanup completes despite missing resources")
			verifyGracefulCleanup := func(g Gomega) {
				// The namespace should still be deleted
				_, err := clientset.CoreV1().Namespaces().Get(context.TODO(), "test-deletion-project", v1.GetOptions{})
				g.Expect(err).To(HaveOccurred(), "Namespace should be deleted despite partial failures")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Namespace should return not found error")

				// Project should be removed
				_, err = kubiclient.CagipV1().Projects().Get(context.TODO(), "test-deletion-project", v1.GetOptions{})
				g.Expect(err).To(HaveOccurred(), "Project should be deleted")
				g.Expect(err.Error()).To(ContainSubstring("not found"), "Project should return not found error")
			}

			Eventually(createTestProject).Should(Succeed())
			Eventually(waitForResourceCreation).Should(Succeed())
			Eventually(simulatePartialDeletion).Should(Succeed())
			Eventually(deleteProjectGracefully).Should(Succeed())
			Eventually(verifyGracefulCleanup).Should(Succeed())
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
