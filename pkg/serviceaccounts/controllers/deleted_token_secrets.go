package controllers

import (
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/controller/framework"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/runtime"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/watch"
	"github.com/golang/glog"
)

// DockercfgTokenDeletedControllerOptions contains options for the DockercfgTokenDeletedController
type DockercfgTokenDeletedControllerOptions struct {
	// Resync is the time.Duration at which to fully re-list secrets.
	// If zero, re-list will be delayed as long as possible
	Resync time.Duration
}

// NewDockercfgTokenDeletedController returns a new *DockercfgTokenDeletedController.
func NewDockercfgTokenDeletedController(cl client.Interface, options DockercfgTokenDeletedControllerOptions) *DockercfgTokenDeletedController {
	e := &DockercfgTokenDeletedController{
		client: cl,
	}

	dockercfgSelector := fields.SelectorFromSet(map[string]string{client.SecretType: string(api.SecretTypeServiceAccountToken)})
	_, e.secretController = framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func() (runtime.Object, error) {
				return e.client.Secrets(api.NamespaceAll).List(labels.Everything(), dockercfgSelector)
			},
			WatchFunc: func(rv string) (watch.Interface, error) {
				return e.client.Secrets(api.NamespaceAll).Watch(labels.Everything(), dockercfgSelector, rv)
			},
		},
		&api.Secret{},
		options.Resync,
		framework.ResourceEventHandlerFuncs{
			DeleteFunc: e.secretDeleted,
		},
	)

	return e
}

// The DockercfgTokenDeletedController watches for service account tokens to be created or deleted.
// On create, it creates a corresponding dockercfg secret and attaches it to the service account
// as both an ImagePullSecret and as a MountableSecret.  On delete, it removes the secret
// and the references.  It does not watch for changes to the ServiceAccount.  If a user wishes to
// remove references to the ImagePullSecret, they may freely do so.
type DockercfgTokenDeletedController struct {
	stopChan chan struct{}

	client client.Interface

	secretController *framework.Controller
}

// Runs controller loops and returns immediately
func (e *DockercfgTokenDeletedController) Run() {
	if e.stopChan == nil {
		e.stopChan = make(chan struct{})
		go e.secretController.Run(e.stopChan)
	}
}

// Stop gracefully shuts down this controller
func (e *DockercfgTokenDeletedController) Stop() {
	if e.stopChan != nil {
		close(e.stopChan)
		e.stopChan = nil
	}
}

// secretDeleted reacts to a token secret being deleted by looking for a corresponding dockercfg secret and deleting it if it exists
func (e *DockercfgTokenDeletedController) secretDeleted(obj interface{}) {
	tokenSecret := obj.(*api.Secret)

	dockercfgSecret, err := e.findDockercfgSecret(tokenSecret)
	if err != nil {
		glog.Error(err)
		return
	}
	if dockercfgSecret == nil {
		return
	}

	// remove the reference token secret
	if err := e.client.Secrets(dockercfgSecret.Namespace).Delete(dockercfgSecret.Name); err != nil {
		glog.Error(err)
		return
	}
}

// findDockercfgSecret checks all the secrets in the namespace to see if the token secret has any existing dockercfg secrets that reference it
func (e *DockercfgTokenDeletedController) findDockercfgSecret(tokenSecret *api.Secret) (*api.Secret, error) {
	dockercfgSelector := fields.SelectorFromSet(map[string]string{client.SecretType: string(api.SecretTypeDockercfg)})
	potentialSecrets, err := e.client.Secrets(tokenSecret.Namespace).List(labels.Everything(), dockercfgSelector)
	if err != nil {
		return nil, err
	}

	for _, currSecret := range potentialSecrets.Items {
		if currSecret.Annotations[ServiceAccountTokenSecretNameKey] == tokenSecret.Name {
			return &currSecret, nil
		}
	}

	return nil, nil
}
