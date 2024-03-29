// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "github.com/ca-gip/kubi/pkg/generated/clientset/versioned/typed/cagip/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeCagipV1 struct {
	*testing.Fake
}

func (c *FakeCagipV1) NetworkPolicyConfigs() v1.NetworkPolicyConfigInterface {
	return &FakeNetworkPolicyConfigs{c}
}

func (c *FakeCagipV1) Projects() v1.ProjectInterface {
	return &FakeProjects{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeCagipV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
