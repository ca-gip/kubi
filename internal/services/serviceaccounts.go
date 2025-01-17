package services

import (
	"context"
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// todo: remove the namespace name (high cardinality, no value)
var ServiceAccountCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_service_account_creation",
	Help: "Number of service account created",
}, []string{"status", "target_namespace", "name"})

// Generate
func GenerateAppServiceAccount(namespace string) error {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	_, err := api.ServiceAccounts(namespace).Get(context.TODO(), utils.KubiServiceAccountAppName, metav1.GetOptions{})

	newServiceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.KubiServiceAccountAppName,
			Namespace: namespace,
			Labels: map[string]string{
				"name":    utils.KubiServiceAccountAppName,
				"creator": "kubi",
				"version": "v3",
			},
		},
	}

	if err != nil {
		_, err := api.ServiceAccounts(namespace).Create(context.TODO(), &newServiceAccount, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("could not create service account %v, %v, %v", namespace, newServiceAccount.ObjectMeta.Name, err)
		}
		return nil
	}
	return nil
}
