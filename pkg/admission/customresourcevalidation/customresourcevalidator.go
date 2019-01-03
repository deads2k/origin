package customresourcevalidation

import (
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
)

func RequireNameCluster(name string, prefix bool) []string {
	if name != "cluster" {
		return []string{"must be cluster"}
	}
	return nil
}

type ValidateObjCreateFunc func(obj runtime.Object) field.ErrorList

type ValidateObjUpdateFunc func(obj runtime.Object, oldObj runtime.Object) field.ErrorList

type ValidateStatusUpdateFunc func(obj runtime.Object, oldObj runtime.Object) field.ErrorList

// ValidateCustomResource is an implementation of admission.Interface.
// It looks at all new pods and overrides each container's image pull policy to Always.
type validateCustomResource struct {
	*admission.Handler

	resource               schema.GroupResource
	validateObjCreateFn    ValidateObjCreateFunc
	validateObjUpdateFn    ValidateObjUpdateFunc
	validateStatusUpdateFn ValidateStatusUpdateFunc
}

func NewValidator(resource schema.GroupResource, validateObjCreateFn ValidateObjCreateFunc, validateObjUpdateFn ValidateObjUpdateFunc, validateStatusUpdateFn ValidateStatusUpdateFunc) (admission.Interface, error) {
	if validateObjCreateFn == nil {
		return nil, fmt.Errorf("createFn is required")
	}
	if validateObjUpdateFn == nil {
		return nil, fmt.Errorf("updateFn is required")
	}
	if validateStatusUpdateFn == nil {
		return nil, fmt.Errorf("updateFn is required")
	}

	return &validateCustomResource{
		Handler:                admission.NewHandler(admission.Create, admission.Update),
		resource:               resource,
		validateObjCreateFn:    validateObjCreateFn,
		validateObjUpdateFn:    validateObjUpdateFn,
		validateStatusUpdateFn: validateStatusUpdateFn,
	}, nil
}

var _ admission.ValidationInterface = &validateCustomResource{}

func (a *validateCustomResource) Validate(uncastAttributes admission.Attributes) error {
	attributes := &unstructuredUnpackingAttributes{Attributes: uncastAttributes}
	if a.shouldIgnore(attributes) {
		return nil
	}

	switch attributes.GetOperation() {
	case admission.Create:
		// creating subresources isn't something we understand, but we can be pretty sure we don't need to validate it
		if len(attributes.GetSubresource()) > 0 {
			return nil
		}
		errors := a.validateObjCreateFn(attributes.GetObject())
		if len(errors) == 0 {
			return nil
		}
		return apierrors.NewInvalid(attributes.GetKind().GroupKind(), attributes.GetName(), errors)

	case admission.Update:
		switch attributes.GetSubresource() {
		case "":
			errors := a.validateObjUpdateFn(attributes.GetObject(), attributes.GetOldObject())
			if len(errors) == 0 {
				return nil
			}
			return apierrors.NewInvalid(attributes.GetKind().GroupKind(), attributes.GetName(), errors)

		case "status":
			errors := a.validateStatusUpdateFn(attributes.GetObject(), attributes.GetOldObject())
			if len(errors) == 0 {
				return nil
			}
			return apierrors.NewInvalid(attributes.GetKind().GroupKind(), attributes.GetName(), errors)

		default:
			admission.NewForbidden(attributes, fmt.Errorf("unhandled subresource: %v", attributes.GetSubresource()))
		}

	default:
		admission.NewForbidden(attributes, fmt.Errorf("unhandled operation: %v", attributes.GetOperation()))
	}

	return nil
}

func (a *validateCustomResource) shouldIgnore(attributes admission.Attributes) bool {
	if attributes.GetResource().GroupResource() != a.resource {
		return true
	}
	// if a subresource is specified and it isn't status, skip it
	if len(attributes.GetSubresource()) > 0 && attributes.GetSubresource() != "status" {
		return true
	}

	return false
}
