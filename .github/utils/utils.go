/* hey lm utils 

generate certifcate 
deploying kubi

here ;)


*/

package utils

import (
	
	

		"context"
		"flag"
                "path/filepath"
		"testing"
		"errors"
		"fmt"
		"os"
		"os/exec"
		"strings" 
	         metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	        "k8s.io/client-go/kubernetes"
	        "k8s.io/client-go/tools/clientcmd"
	        "k8s.io/client-go/util/homedir" 
		. "github.com/onsi/ginkgo/v2"
		. "github.com/onsi/gomega"
	
)

const (
	
  kubiDeploymentUrl = "kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-deployment.yml"
  kubiCrdUrl = "kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-crds.yml"
  kubiPrerequiesUrl ="kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-prerequisites.yml"
  kubiLocalConfigUrl ="kubectl apply -f https://raw.githubusercontent.com/ca-gip/kubi/master/deployments/kube-local-config.yml"
  
  
)

func warnError(err error){
  fmt.Fprint(GinKgoWriter, "warning: %v \n", err) 
  
}

func InstallKubiOperator() error {

  url := fmt.Sprintf(kubiDeploymentUrl)
  cmd := exec.Command("kubectl","apply","-f",url)
  -, err := Run(cmd)
  retunr err
}

func InstallKubiCrd() error {

  cmd := exec.Command("kubectl","apply","-f",kubiCrdUrl)
  -, err := Run(cmd)
  retunr err
}

func InstallKubilocalconfig() error {

 
  cmd := exec.Command("kubectl","apply","-f",kubiLocalConfigUrl)
  -, err := Run(cmd)
  retunr err
}

func InstallKubilocalconfig() error {

  cmd := exec.Command("kubectl","apply","-f",kubiPrerequiesUrl)
  -, err := Run(cmd)
  retunr err
}


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
	// install deps
	// configure cert
	// configur ldap
	// deplloy kubi
	
	// test

    // existing ns
    nsName := "chaos-development"
    _, err = clientset.CoreV1().Namespaces().Get(context.TODO(), nsName, metav1.GetOptions{}) 
    assert.NoError(t, err, "namespace should exist")
   
