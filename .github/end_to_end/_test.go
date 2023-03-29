package main

import (
    "context"
    "flag"
    "fmt"
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
        fmt.Printf("Namespace %q exists\n", nsName)
    }
}
