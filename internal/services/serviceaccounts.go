package services

import (
	"context"

	"github.com/ca-gip/kubi/internal/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Generate
func GenerateAppServiceAccount(namespace string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	_, errRB := api.ServiceAccounts(namespace).Get(context.TODO(), utils.KubiServiceAccountAppName, metav1.GetOptions{})

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

	if errRB != nil {
		_, err := api.ServiceAccounts(namespace).Create(context.TODO(), &newServiceAccount, metav1.CreateOptions{})
		if err != nil {
			utils.Log.Error().Msg(err.Error())
			utils.ServiceAccountCreation.WithLabelValues("error", namespace, utils.KubiServiceAccountAppName).Inc()
			return
		}
		utils.Log.Info().Msgf("Service Account %v has been created for namespace %v", utils.KubiServiceAccountAppName, namespace)
		utils.ServiceAccountCreation.WithLabelValues("created", namespace, utils.KubiServiceAccountAppName).Inc()
		return
	}
	utils.ServiceAccountCreation.WithLabelValues("ok", namespace, utils.KubiServiceAccountAppName).Inc()
}
