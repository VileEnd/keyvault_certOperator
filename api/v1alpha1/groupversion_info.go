// Package v1alpha1 contains the API schema for the certsync.vileend.io group.
// +kubebuilder:object:generate=true
// +groupName=certsync.vileend.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// SchemeGroupVersion is the group version used to register these objects.
	SchemeGroupVersion = schema.GroupVersion{Group: "certsync.vileend.io", Version: "v1alpha1"}

	// GroupVersion is an alias for SchemeGroupVersion, kept for the conventional name.
	GroupVersion = SchemeGroupVersion

	// SchemeBuilder collects the functions that add these types to a Scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(func(s *runtime.Scheme) error {
		metav1.AddToGroupVersion(s, SchemeGroupVersion)
		return nil
	})

	// AddToScheme adds the types in this group version to a Scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// Resource takes an unqualified resource and returns a Group-qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
