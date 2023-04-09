package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func TestMain(t *testing.T) {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

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
	// Check if each secret exists in the namespace
	namespace := "kube-system"
	secretNames := []string{"kubi-encryption-secret", "kubi", "kubi-secret"}

	for _, secretName := range secretNames {
		_, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("Failed to get secret %s in namespace %s: %v", secretName, namespace, err)
		} else {
			t.Logf("Secret %s in namespace %s exists\n", secretName, namespace)
		}
	}

	//adding new group to Openldap

	// existing ns
	nsName := "chaos-development"
	_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), nsName, metav1.GetOptions{})
	if err != nil {
		if os.IsNotExist(err) {
			t.Errorf("expected namespace %q to exist, but it does not", nsName)
		} else {
			t.Errorf("error checking namespace existence: %v", err)
		}
	} else {
		t.Logf("Namespace %q exists\n", nsName)
	}

}
