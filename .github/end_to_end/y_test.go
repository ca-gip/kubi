package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// creating kube client
func NewClientSet(kubeconfig string) (*kubernetes.Clientset, error) {
	if kubeconfig == "" {
		kubeconfig = filepath.Join(homedir.HomeDir(), ".kube", "config")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// check existing namespace
func namespaceExists(clientset *kubernetes.Clientset, namespace string) (bool, error) {
	_, err := clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}


//  checking for kubi secret
func TestSecretkubi(t *testing.T) {

	clientset, err := NewClientSet("")
	if err != nil {
		panic(err)
	}

	namespace := "kube-system"
	secretNames := []string{"kubi-encryption-secret", "kubi", "kubi-secret"}

	for _, secretName := range secretNames {
		_, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
		assert.NoError(t, err, " Failed to get secret %s in namespace %s", secretName, namespace)
	}

}

// check  for new ns created by kubi
func TestNamespace(t *testing.T) {

	clientset, err := NewClientSet("")
	if err != nil {
		panic(err)
	}

	Namespace := "team-1-development"
	exists, err := namespaceExists(clientset, Namespace)

	assert.NoError(t, err, "Error checking namespace existence")
	assert.True(t, exists, "Expected namespace %q to exist, but it does not", Namespace)

}
