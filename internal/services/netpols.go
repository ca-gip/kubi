package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ca-gip/kubi/internal/utils"
	cagipv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// todo: remove namespace (high cardinality, no value)
var NetworkPolicyCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_network_policy_creation",
	Help: "Number of network policy created",
}, []string{"status", "target_namespace", "name"})

// Generate a NetworkPolicy based on NetworkPolicyConfig
// If exists, the existing netpol is updated else it is created
func generateNetworkPolicy(namespace string, networkPolicyConfig *cagipv1.NetworkPolicyConfig) error {

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in cluster config %v", err)
	}

	if networkPolicyConfig == nil {
		extendedClientSet, err := versioned.NewForConfig(kconfig)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes clientset %v", err)
		}
		existingNetworkPolicyConfig, err := extendedClientSet.CagipV1().NetworkPolicyConfigs().Get(context.TODO(), utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("no default network policy config found, cannot create/update namespace security %v", err)
		}
		networkPolicyConfig = existingNetworkPolicyConfig
	}

	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes clientset %v", err)
	}

	api := clientSet.NetworkingV1()
	_, errNetpol := api.NetworkPolicies(namespace).Get(context.TODO(), utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})

	UDP := corev1.ProtocolUDP
	TCP := corev1.ProtocolTCP

	var ingressRules []networkingv1.NetworkPolicyPeer

	// Add default intra namespace communication
	ingressRules = append(ingressRules, networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{MatchLabels: nil},
	})

	// Add default whitelisted namespace ingress rules
	for _, namespace := range networkPolicyConfig.Spec.Ingress.Namespaces {
		ingressRules = append(ingressRules, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": namespace}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: nil},
		})
	}

	var netpolPorts []networkingv1.NetworkPolicyPort

	if len(networkPolicyConfig.Spec.Egress.Ports) > 0 {
		for _, port := range networkPolicyConfig.Spec.Egress.Ports {
			netpolPorts = append(netpolPorts, networkingv1.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port)}, Protocol: &UDP})
			netpolPorts = append(netpolPorts, networkingv1.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port)}, Protocol: &TCP})
		}
	}
	netpolPorts = append(netpolPorts, networkingv1.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: 53}, Protocol: &UDP})

	policyPeers := []networkingv1.NetworkPolicyPeer{
		{PodSelector: &metav1.LabelSelector{MatchLabels: nil}},
		{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "kube-system"}},
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"component": "kube-apiserver",
					"tier":      "control-plane",
				},
			},
		},
	}

	// Add default whitelisted namespace egress rules
	for _, namespace := range networkPolicyConfig.Spec.Egress.Namespaces {
		policyPeers = append(policyPeers, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": namespace}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: nil},
		})
	}

	for _, cidr := range networkPolicyConfig.Spec.Egress.Cidrs {
		policyPeers = append(policyPeers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}})
	}

	networkpolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.KubiDefaultNetworkPolicyName,
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: nil,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: ingressRules,
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: netpolPorts,
				},
				{
					To: policyPeers,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress,
			},
		},
	}

	switch {
	case errNetpol != nil && kerror.IsNotFound(errNetpol):
		slog.Debug("creating netpol", "namespace", namespace)
		_, err := api.NetworkPolicies(namespace).Create(context.TODO(), networkpolicy, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create network policy in ns %v: %v", namespace, err)
		}
	case errNetpol != nil:
		return fmt.Errorf("failed to create network policy in ns %v: %v", namespace, errNetpol)
	default:
		slog.Debug("updating netpol", "namespace", namespace)
		_, err := api.NetworkPolicies(namespace).Update(context.TODO(), networkpolicy, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update network policy in ns %v: %v", namespace, err)
		}
	}
	return nil
}
