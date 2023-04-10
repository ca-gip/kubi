package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// function to check existing namespace
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

func TestNamespace(t *testing.T) {

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		t.Fatalf("error building config from flags: %v", err)
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("error creating clientset: %v", err)
	}

	//existing ns
	namespace := "chaos-development"
	exists, err := namespaceExists(clientset, namespace)

	assert.NoError(t, err, "Error checking namespace existence")
	assert.True(t, exists, "Expected namespace %q to exist, but it does not", namespace)

}

// Check if each secret exists in the namespace
func TestSecretkubi(t *testing.T) {

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		t.Fatalf("error building config from flags: %v", err)
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("error creating clientset: %v", err)
	}

	namespace := "kube-system"
	secretNames := []string{"kubi-encyption-secret", "kubi", "kubi-secret"}

	for _, secretName := range secretNames {
		_, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
		assert.NoError(t, err, "Failed to get secret %s in namespace %s", secretName, namespace)
	}

}

//adding new group to Openldap
