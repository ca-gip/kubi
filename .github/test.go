
package main

import (
        "context"
        "flag"
        "fmt"
        "path/filepath"
        "os"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
        "k8s.io/client-go/kubernetes"
        "k8s.io/client-go/tools/clientcmd"
        "k8s.io/client-go/util/homedir"
)

func main() {
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
                panic(err.Error())
        }

        // create the clientset
        clientset, err := kubernetes.NewForConfig(config)
        if err != nil {
                panic(err.Error())
        } 
        // existing ns 
                nsName := "chaos-development"
                _, err = clientset.CoreV1().Namespaces().Get(context.TODO(),nsName, metav1.GetOptions{})
                if err != nil {
                  if os.IsNotExist(err) {
                    fmt.Printf("Le namespace %q n'est  pas crée", nsName)
                  } else {
                          fmt.Printf("Erreur lors de la vérification du namespace: le namespace %q n'est pas crée !! ",nsName)
                 }
               } else {
              fmt.Printf("Le namespace %q existe \n", nsName)
    }
}
