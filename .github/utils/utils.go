/* hey lm utils 

generate certifcate 
deploying kubi

here ;)


*/

package utils

import (
  
  
  "errors"
	"fmt"
	"os"
	"os/exec"
	"strings"  
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

  url := fmt.Sprintf(kubiCrdUrl)
  cmd := exec.Command("kubectl","apply","-f",url)
  -, err := Run(cmd)
  retunr err
}

func DeployKubiLocalConfig() error {

  url := fmt.Sprintf(kubiLocalConfigUrl)
  cmd := exec.Command("kubectl","apply","-f",url)
  -, err := Run(cmd)
  retunr err
}

func InstallKubiPrerequies() error {

  url := fmt.Sprintf(kubiDeploymentUrl)
  cmd := exec.Command("kubectl","apply","-f",url)
  -, err := Run(cmd)
  retunr err
}

func InstallKubiOperator() error {

  url := fmt.Sprintf(kubiPrerequiesUrl)
  cmd := exec.Command("kubectl","apply","-f",url)
  -, err := Run(cmd)
  retunr err
}
