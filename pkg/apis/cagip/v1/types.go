package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient:nonNamespaced

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
type NetworkPolicyConfig struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Status NetworkPolicyConfigSpecStatus `json:"status,omitempty"`
	// This is where you can define
	// your own custom spec
	Spec NetworkPolicyConfigSpec `json:"spec,omitempty"`
}

// custom spec
type NetworkPolicyConfigSpec struct {
	Egress  EgressType  `json:"egress,omitempty"`
	Ingress IngressType `json:"ingress,omitempty"`
}

type EgressType struct {
	Ports      []int    `json:"ports,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Cidrs      []string `json:"cidrs,omitempty"`
}

type IngressType struct {
	Namespaces []string `json:"namespaces,omitempty"`
}

// custom status
type NetworkPolicyConfigSpecStatus struct {
	Name string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NetworkPolicyConfigList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NetworkPolicyConfig `json:"items"`
}

// +genclient:nonNamespaced

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
type Project struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Status ProjectSpecStatus `json:"status,omitempty"`
	// This is where you can define
	// your own custom spec
	Spec ProjectSpec `json:"spec,omitempty"`
}

type ProjectSpec struct {
	Tenant       string   `json:"tenant,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	Project      string   `json:"project,omitempty"`
	SourceEntity string   `json:"sourceEntity,omitempty"`
	Stages       []string `json:"stages,omitempty"`
	Contact      string   `json:"contact,omitempty"`
	SourceDN     string   `json:"sourceDN,omitempty"`
}

const (
	ProjectStatusCreated = "created"
)

type ProjectSpecStatus struct {
	Name string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// no client needed for list as it's been created in above
type ProjectList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Project `json:"items"`
}
