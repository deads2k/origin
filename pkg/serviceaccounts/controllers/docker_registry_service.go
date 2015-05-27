package controllers

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/controller/framework"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/credentialprovider"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/runtime"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/watch"
	"github.com/golang/glog"
)

// DockerRegistryServiceControllerOptions contains options for the DockerRegistryServiceController
type DockerRegistryServiceControllerOptions struct {
	// Resync is the time.Duration at which to fully re-list service accounts.
	// If zero, re-list will be delayed as long as possible
	Resync time.Duration

	RegistryNamespace string

	RegistryServiceName string

	DockercfgController *DockercfgController
}

// NewDockerRegistryServiceController returns a new *DockerRegistryServiceController.
func NewDockerRegistryServiceController(cl client.Interface, options DockerRegistryServiceControllerOptions) *DockerRegistryServiceController {
	e := &DockerRegistryServiceController{
		client: cl,
	}

	_, e.serviceController = framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func() (runtime.Object, error) {
				return e.client.Services(options.RegistryNamespace).List(labels.Everything())
			},
			WatchFunc: func(rv string) (watch.Interface, error) {
				return e.client.Services(options.RegistryNamespace).Watch(labels.Everything(), fields.Everything(), rv)
			},
		},
		&api.Service{},
		options.Resync,
		framework.ResourceEventHandlerFuncs{
			AddFunc:    e.serviceAdded,
			UpdateFunc: e.serviceUpdated,
			DeleteFunc: e.serviceDeleted,
		},
	)
	e.registryServiceName = options.RegistryServiceName
	e.dockercfgController = options.DockercfgController

	return e
}

// DockerRegistryServiceController manages ServiceToken secrets for Service objects
type DockerRegistryServiceController struct {
	stopChan chan struct{}

	client client.Interface

	registryServiceName string

	dockercfgController *DockercfgController

	serviceController *framework.Controller
}

// Runs controller loops and returns immediately
func (e *DockerRegistryServiceController) Run() {
	if e.stopChan == nil {
		e.stopChan = make(chan struct{})
		go e.serviceController.Run(e.stopChan)
	}
}

// Stop gracefully shuts down this controller
func (e *DockerRegistryServiceController) Stop() {
	if e.stopChan != nil {
		close(e.stopChan)
		e.stopChan = nil
	}
}

// serviceAdded reacts to the creation of a docker-registry service by updating all service account dockercfg secrets and
// changing all interestedURLs
func (e *DockerRegistryServiceController) serviceAdded(obj interface{}) {
	service := obj.(*api.Service)
	if service.Name != e.registryServiceName {
		return
	}

	serviceLocation := service.Spec.PortalIP
	if len(serviceLocation) == 0 {
		serviceLocation = OpenshiftDockerURL
	}

	if err := e.handleLocationChange(serviceLocation); err != nil {
		glog.Error(err)
	}
}

// serviceUpdated reacts to the creation of a docker-registry service by updating all service account dockercfg secrets and
// changing all interestedURLs, if needed
func (e *DockerRegistryServiceController) serviceUpdated(oldObj interface{}, newObj interface{}) {
	oldService := oldObj.(*api.Service)
	newService := newObj.(*api.Service)
	if newService.Name != e.registryServiceName {
		return
	}
	if oldService.Spec.PortalIP == newService.Spec.PortalIP {
		return
	}

	serviceLocation := newService.Spec.PortalIP
	if len(serviceLocation) == 0 {
		serviceLocation = OpenshiftDockerURL
	}

	if err := e.handleLocationChange(serviceLocation); err != nil {
		glog.Error(err)
	}
}

// serviceDeleted reacts to a Service deletion by deleting all corresponding ServiceToken Secrets
func (e *DockerRegistryServiceController) serviceDeleted(obj interface{}) {
	service := obj.(*api.Service)
	if service.Name != e.registryServiceName {
		return
	}

	if err := e.handleLocationChange(OpenshiftDockerURL); err != nil {
		glog.Error(err)
	}
}

// createDockercfgSecretIfNeeded makes sure at least one ServiceToken secret exists, and is included in the service's Secrets list
func (e *DockerRegistryServiceController) handleLocationChange(serviceLocation string) error {
	e.dockercfgController.SetDockerURL(serviceLocation)

	dockercfgSecrets, err := e.listDockercfgSecrets()
	if err != nil {
		return err
	}

	for _, dockercfgSecret := range dockercfgSecrets {
		dockercfg := &credentialprovider.DockerConfig{}
		if err := json.Unmarshal(dockercfgSecret.Data[api.DockerConfigKey], dockercfg); err != nil {
			glog.Error(err)
			continue
		}

		dockercfgMap := map[string]credentialprovider.DockerConfigEntry(*dockercfg)
		keys := util.KeySet(reflect.ValueOf(dockercfgMap))
		if len(keys) != 1 {
			glog.Error(err)
			continue
		}
		oldKey := keys.List()[0]
		dockercfgMap[serviceLocation] = dockercfgMap[oldKey]
		delete(dockercfgMap, oldKey)
		t := credentialprovider.DockerConfig(dockercfgMap)
		dockercfg = &t

		dockercfgContent, err := json.Marshal(dockercfg)
		if err != nil {
			glog.Error(err)
			continue
		}
		dockercfgSecret.Data[api.DockerConfigKey] = dockercfgContent

		if _, err := e.client.Secrets(dockercfgSecret.Namespace).Update(dockercfgSecret); err != nil {
			glog.Error(err)
			continue
		}
	}

	return err
}

func (e *DockerRegistryServiceController) listDockercfgSecrets() ([]*api.Secret, error) {
	dockercfgSelector := fields.SelectorFromSet(map[string]string{client.SecretType: string(api.SecretTypeDockercfg)})
	potentialSecrets, err := e.client.Secrets(api.NamespaceAll).List(labels.Everything(), dockercfgSelector)
	if err != nil {
		return nil, err
	}

	dockercfgSecretsForThisSA := []*api.Secret{}
	for i, currSecret := range potentialSecrets.Items {
		if _, exists := currSecret.Annotations[ServiceAccountTokenSecretNameKey]; exists {
			dockercfgSecretsForThisSA = append(dockercfgSecretsForThisSA, &potentialSecrets.Items[i])
		}
	}

	return dockercfgSecretsForThisSA, nil
}
