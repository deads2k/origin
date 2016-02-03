package util

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/meta"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apimachinery/registered"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/runtime"
)

func DefaultSubCommandRun(out io.Writer) func(c *cobra.Command, args []string) {
	return func(c *cobra.Command, args []string) {
		c.SetOutput(out)

		if len(args) > 0 {
			kcmdutil.CheckErr(kcmdutil.UsageError(c, fmt.Sprintf(`unknown command "%s"`, strings.Join(args, " "))))
		}

		c.Help()
	}
}

// GetDisplayFilename returns the absolute path of the filename as long as there was no error, otherwise it returns the filename as-is
func GetDisplayFilename(filename string) string {
	if absName, err := filepath.Abs(filename); err == nil {
		return absName
	}

	return filename
}

// ResolveResource returns the resource type and name of the resourceString.
// If the resource string has no specified type, defaultResource will be returned.
func ResolveResource(defaultResource, resourceString string, mapper meta.RESTMapper) (string, string, error) {
	if mapper == nil {
		return "", "", errors.New("mapper cannot be nil")
	}

	var name string
	parts := strings.Split(resourceString, "/")
	switch len(parts) {
	case 1:
		name = parts[0]
	case 2:
		gvk, err := mapper.KindFor(unversioned.GroupVersionResource{Resource: parts[0]})
		if err != nil {
			return "", "", err
		}
		name = parts[1]
		resource, _ := meta.KindToResource(gvk, false)
		return resource.Resource, name, nil
	default:
		return "", "", fmt.Errorf("invalid resource format: %s", resourceString)
	}

	return defaultResource, name, nil
}

// ConvertItemsForDisplay returns a new list that contains parallel elements that have been converted to the most preferred external version
func ConvertItemsForDisplay(objs []runtime.Object, preferredVersions ...unversioned.GroupVersion) ([]runtime.Object, error) {
	ret := []runtime.Object{}

	for i := range objs {
		obj := objs[i]
		kind, err := kapi.Scheme.ObjectKind(obj)
		if err != nil {
			return nil, err
		}
		groupMeta, err := registered.Group(kind.Group)
		if err != nil {
			return nil, err
		}

		requestedVersion := unversioned.GroupVersion{}
		for _, preferredVersion := range preferredVersions {
			if preferredVersion.Group == kind.Group {
				requestedVersion = preferredVersion
				break
			}
		}

		actualOutputVersion := unversioned.GroupVersion{}
		for _, externalVersion := range groupMeta.GroupVersions {
			if externalVersion == requestedVersion {
				actualOutputVersion = externalVersion
				break
			}
			if actualOutputVersion.IsEmpty() {
				actualOutputVersion = externalVersion
			}
		}

		convertedObject, err := kapi.Scheme.ConvertToVersion(obj, actualOutputVersion.String())
		if err != nil {
			return nil, err
		}

		ret = append(ret, convertedObject)
	}

	return ret, nil
}
