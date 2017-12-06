package resource

import (
	"fmt"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/kubectl/resource"
)

// AsVersionedObject converts a list of infos into a single object - either a List containing
// the objects as children, or if only a single Object is present, as that object. The provided
// version will be preferred as the conversion target, but the Object's mapping version will be
// used if that version is not present.
func AsVersionedObject(infos []*resource.Info, forceList bool, version schema.GroupVersion, encoder runtime.Encoder) (runtime.Object, error) {
	objects, err := AsVersionedObjects(infos, version, encoder)
	if err != nil {
		return nil, err
	}

	var object runtime.Object
	if len(objects) == 1 && !forceList {
		object = objects[0]
	} else {
		object = &api.List{Items: objects}
		converted, err := TryConvert(api.Scheme, object, version, api.Registry.GroupOrDie(api.GroupName).GroupVersion)
		if err != nil {
			return nil, err
		}
		object = converted
	}

	actualVersion := object.GetObjectKind().GroupVersionKind()
	if actualVersion.Version != version.Version {
		defaultVersionInfo := ""
		if len(actualVersion.Version) > 0 {
			defaultVersionInfo = fmt.Sprintf("Defaulting to %q", actualVersion.Version)
		}
		glog.V(1).Infof("info: the output version specified is invalid. %s\n", defaultVersionInfo)
	}
	return object, nil
}

// AsVersionedObjects converts a list of infos into versioned objects. The provided
// version will be preferred as the conversion target, but the Object's mapping version will be
// used if that version is not present.
func AsVersionedObjects(infos []*resource.Info, version schema.GroupVersion, encoder runtime.Encoder) ([]runtime.Object, error) {
	objects := []runtime.Object{}
	for _, info := range infos {
		if info.Object == nil {
			continue
		}

		// objects that are not part of api.Scheme must be converted to JSON
		// TODO: convert to map[string]interface{}, attach to runtime.Unknown?
		if !version.Empty() {
			if _, _, err := api.Scheme.ObjectKinds(info.Object); runtime.IsNotRegisteredError(err) {
				// TODO: ideally this would encode to version, but we don't expose multiple codecs here.
				data, err := runtime.Encode(encoder, info.Object)
				if err != nil {
					return nil, err
				}
				// TODO: Set ContentEncoding and ContentType.
				objects = append(objects, &runtime.Unknown{Raw: data})
				continue
			}
		}

		converted, err := TryConvert(info.Mapping.ObjectConvertor, info.Object, version, info.Mapping.GroupVersionKind.GroupVersion())
		if err != nil {
			return nil, err
		}
		objects = append(objects, converted)
	}
	return objects, nil
}

// TryConvert attempts to convert the given object to the provided versions in order. This function assumes
// the object is in internal version.
func TryConvert(converter runtime.ObjectConvertor, object runtime.Object, versions ...schema.GroupVersion) (runtime.Object, error) {
	var last error
	for _, version := range versions {
		if version.Empty() {
			return object, nil
		}
		obj, err := converter.ConvertToVersion(object, version)
		if err != nil {
			last = err
			continue
		}
		return obj, nil
	}
	return nil, last
}
