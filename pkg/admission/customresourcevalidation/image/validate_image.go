package image

import (
	"fmt"
	"io"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/origin/pkg/admission/customresourcevalidation"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"k8s.io/apiserver/pkg/admission"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register("config.openshift.io/ValidateImage", func(config io.Reader) (admission.Interface, error) {
		return customresourcevalidation.NewValidator(configv1.Resource("images"), validateObjCreateFn, validateObjUpdateFn, validateObjStatusUpdateFn)
	})
}

func validateObjCreateFn(uncastObj runtime.Object) field.ErrorList {
	allErrs := field.ErrorList{}
	var obj *configv1.Image
	var ok bool

	obj, ok = uncastObj.(*configv1.Image)
	if !ok {
		return append(allErrs,
			field.NotSupported(field.NewPath("kind"), fmt.Sprintf("%T", uncastObj), []string{"Image"}),
			field.NotSupported(field.NewPath("apiVersion"), fmt.Sprintf("%T", uncastObj), []string{"config.openshift.io/v1"}))
	}

	// TODO validate the obj
	allErrs = append(allErrs, validation.ValidateObjectMeta(&obj.ObjectMeta, false, customresourcevalidation.RequireNameCluster, field.NewPath("metadata"))...)

	return allErrs
}

func validateObjUpdateFn(uncastObj runtime.Object, uncastOldObj runtime.Object) field.ErrorList {
	allErrs := field.ErrorList{}
	var obj, oldObj *configv1.Image
	var ok bool

	obj, ok = uncastObj.(*configv1.Image)
	if !ok {
		return append(allErrs,
			field.NotSupported(field.NewPath("kind"), fmt.Sprintf("%T", uncastObj), []string{"Image"}),
			field.NotSupported(field.NewPath("apiVersion"), fmt.Sprintf("%T", uncastObj), []string{"config.openshift.io/v1"}))
	}
	if uncastOldObj != nil {
		oldObj, ok = uncastOldObj.(*configv1.Image)
		if !ok {
			return append(allErrs,
				field.NotSupported(field.NewPath("kind"), fmt.Sprintf("%T", uncastObj), []string{"Image"}),
				field.NotSupported(field.NewPath("apiVersion"), fmt.Sprintf("%T", uncastObj), []string{"config.openshift.io/v1"}))
		}
	}

	// TODO validate the obj
	allErrs = append(allErrs, validation.ValidateObjectMetaUpdate(&obj.ObjectMeta, &oldObj.ObjectMeta, field.NewPath("metadata"))...)

	return allErrs
}

func validateObjStatusUpdateFn(uncastObj runtime.Object, uncastOldObj runtime.Object) field.ErrorList {
	allErrs := field.ErrorList{}
	var obj, oldObj *configv1.Image
	var ok bool

	obj, ok = uncastObj.(*configv1.Image)
	if !ok {
		return append(allErrs,
			field.NotSupported(field.NewPath("kind"), fmt.Sprintf("%T", uncastObj), []string{"Image"}),
			field.NotSupported(field.NewPath("apiVersion"), fmt.Sprintf("%T", uncastObj), []string{"config.openshift.io/v1"}))
	}
	if uncastOldObj != nil {
		oldObj, ok = uncastOldObj.(*configv1.Image)
		if !ok {
			return append(allErrs,
				field.NotSupported(field.NewPath("kind"), fmt.Sprintf("%T", uncastObj), []string{"Image"}),
				field.NotSupported(field.NewPath("apiVersion"), fmt.Sprintf("%T", uncastObj), []string{"config.openshift.io/v1"}))
		}
	}

	// TODO validate the obj.  remember that status validation should *never* fail on spec validation errors.
	allErrs = append(allErrs, validation.ValidateObjectMetaUpdate(&obj.ObjectMeta, &oldObj.ObjectMeta, field.NewPath("metadata"))...)

	return allErrs
}
