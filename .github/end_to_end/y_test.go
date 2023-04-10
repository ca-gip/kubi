package main

import (
	"context"
	"os"
	"os/exec"
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

// vérifier les secrets
func TestSecretkubi(t *testing.T) {

	clientset, err := NewClientSet("")
	if err != nil {
		panic(err)
	}

	namespace := "kube-system"
	secretNames := []string{"kubi-encryption-secret", "kubi", "kubi-secret"}

	for _, secretName := range secretNames {
		_, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
		assert.NoError(t, err, "Failed to get secret %s in namespace %s", secretName, namespace)
	}

}

// test d'ajour d'un group à notre openldap
func TestAddGroupToOpenLDAP(t *testing.T) {
	// Exécuter la commande `kubectl wait` pour attendre que le pod soit prêt
	waitCmd := exec.Command("kubectl", "wait", "--for=condition=Ready", "pod", "-n", "kube-system", "-l", "app=kubi-ldap")
	if err := waitCmd.Run(); err != nil {
		t.Fatalf("Failed to wait for pod: %v", err)
	}

	// Exécuter la commande `kubectl exec` pour ajouter le groupe
	addcmd := exec.Command("kubectl", "exec", "-n", "kube-system",
		"$(kubectl", "get", "pods", "-n", "kube-system", "-l", "app=kubi-ldap", "-o", "jsonpath='{.items[0].metadata.name}')", "--", "su", "-c",
		"apt-get update && apt-get install -y ldap-utils && ldapadd -x -D cn=admin,dc=kubi,dc=ca-gip,dc=github,dc=com -w password <<EOF "+
			"dn: cn=DL_KUB_CHAOS-DEV_ADMIN,ou=LOCAL,ou=Groups,dc=kubi,dc=ca-gip,dc=github,dc=com "+
			"objectClass: top "+
			"objectClass: groupOfNames "+
			"cn: DL_KUB_CHAOS-DEV_ADMIN "+
			"member: cn=mario,ou=People,dc=kubi,dc=ca-gip,dc=github,dc=com "+
			"member: cn=luigi,ou=People,dc=kubi,dc=ca-gip,dc=github,dc=com "+
			"EOF")
	if err := addcmd.Run(); err != nil {
		t.Fatalf("Failed to add group to OpenLDAP: %v", err)
	}
	// Vérifier que le groupe a été ajouté en exécutant une commande de recherche LDAP
	searchCmd := exec.Command("ldapsearch", "-x", "-b", "dc=kubi,dc=ca-gip,dc=github,dc=com", "-D", "cn=admin,dc=kubi,dc=ca-gip,dc=github,dc=com", "-w", "password", "cn=DL_KUB_CHAOS-DEV_ADMIN")
	output, err := searchCmd.Output()
	if err != nil {
		t.Fatalf("Failed to search for group in OpenLDAP: %v", err)
	}

	assert.Contains(t, string(output), "cn=DL_KUB_CHAOS-DEV_ADMIN", "Group not found in OpenLDAP")

}

// echecking for new ns created by kubi
func TestNamespace(t *testing.T) {

	clientset, err := NewClientSet("")
	if err != nil {
		panic(err)
	}

	namespace := "chaos-development"
	exists, err := namespaceExists(clientset, namespace)

	assert.NoError(t, err, "Error checking namespace existence")
	assert.True(t, exists, "Expected namespace %q to exist, but it does not", namespace)

}
