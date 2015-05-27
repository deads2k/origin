package controllers

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	kapierrors "github.com/GoogleCloudPlatform/kubernetes/pkg/api/errors"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/controller/framework"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/credentialprovider"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/registry/secret"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/runtime"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util/wait"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/watch"
	"github.com/golang/glog"
)

const ServiceAccountTokenSecretNameKey = "openshift.io/token-secret.name"
const OpenshiftDockerURL = "docker-registry.default.svc.cluster.local"

// DockercfgControllerOptions contains options for the DockercfgController
type DockercfgControllerOptions struct {
	// Resync is the time.Duration at which to fully re-list service accounts.
	// If zero, re-list will be delayed as long as possible
	Resync time.Duration
}

// NewDockercfgController returns a new *DockercfgController.
func NewDockercfgController(cl client.Interface, options DockercfgControllerOptions) *DockercfgController {
	e := &DockercfgController{
		client: cl,
	}

	_, e.serviceAccountController = framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func() (runtime.Object, error) {
				return e.client.ServiceAccounts(api.NamespaceAll).List(labels.Everything(), fields.Everything())
			},
			WatchFunc: func(rv string) (watch.Interface, error) {
				return e.client.ServiceAccounts(api.NamespaceAll).Watch(labels.Everything(), fields.Everything(), rv)
			},
		},
		&api.ServiceAccount{},
		options.Resync,
		framework.ResourceEventHandlerFuncs{
			AddFunc:    e.serviceAccountAdded,
			UpdateFunc: e.serviceAccountUpdated,
		},
	)

	e.dockerURL = OpenshiftDockerURL

	return e
}

// DockercfgController manages dockercfg secrets for ServiceAccount objects
type DockercfgController struct {
	stopChan chan struct{}

	client client.Interface

	dockerURL     string
	dockerURLLock sync.Mutex

	serviceAccountController *framework.Controller
}

// Runs controller loops and returns immediately
func (e *DockercfgController) Run() {
	if e.stopChan == nil {
		e.stopChan = make(chan struct{})
		go e.serviceAccountController.Run(e.stopChan)
	}
}

// Stop gracefully shuts down this controller
func (e *DockercfgController) Stop() {
	if e.stopChan != nil {
		close(e.stopChan)
		e.stopChan = nil
	}
}

func (e *DockercfgController) SetDockerURL(newDockerURL string) {
	e.dockerURLLock.Lock()
	defer e.dockerURLLock.Unlock()

	e.dockerURL = newDockerURL
}

// serviceAccountAdded reacts to a ServiceAccount creation by creating a corresponding ServiceAccountToken Secret
func (e *DockercfgController) serviceAccountAdded(obj interface{}) {
	serviceAccount := obj.(*api.ServiceAccount)

	if err := e.createDockercfgSecretIfNeeded(serviceAccount); err != nil {
		glog.Error(err)
	}
}

// serviceAccountUpdated reacts to a ServiceAccount update (or re-list) by ensuring a corresponding ServiceAccountToken Secret exists
func (e *DockercfgController) serviceAccountUpdated(oldObj interface{}, newObj interface{}) {
	newServiceAccount := newObj.(*api.ServiceAccount)

	if err := e.createDockercfgSecretIfNeeded(newServiceAccount); err != nil {
		glog.Error(err)
	}
}

const (
	dockercfgToken = "-dockercfg-"

	// These constants are here to create a name that is short enough to survive chopping by generate name
	maxNameLength               = 63
	randomLength                = 5
	maxServiceAccountNameLength = maxNameLength - randomLength - len(dockercfgToken)
)

func getUsableServiceAccountNamePrefix(serviceAccountName string) string {
	if len(serviceAccountName) > maxServiceAccountNameLength {
		serviceAccountName = serviceAccountName[:maxServiceAccountNameLength]
	}

	return serviceAccountName
}

func getDockercfgSecretNamePrefix(serviceAccount *api.ServiceAccount) string {
	return getUsableServiceAccountNamePrefix(serviceAccount.Name) + dockercfgToken
}
func getTokenSecretNamePrefix(serviceAccount *api.ServiceAccount) string {
	return getUsableServiceAccountNamePrefix(serviceAccount.Name) + "-token-"
}

// createDockercfgSecretIfNeeded makes sure at least one ServiceAccountToken secret exists, and is included in the serviceAccount's Secrets list
func (e *DockercfgController) createDockercfgSecretIfNeeded(serviceAccount *api.ServiceAccount) error {

	// look for an ImagePullSecret in the form
	dockercfgSecretName := ""
	foundDockercfgImagePullSecret := false
	for _, pullSecret := range serviceAccount.ImagePullSecrets {
		if strings.HasPrefix(pullSecret.Name, getDockercfgSecretNamePrefix(serviceAccount)) {
			foundDockercfgImagePullSecret = true
			dockercfgSecretName = pullSecret.Name
			break
		}
	}
	foundDockercfgMountableSecret := false
	for _, mountableSecret := range serviceAccount.Secrets {
		if strings.HasPrefix(mountableSecret.Name, getDockercfgSecretNamePrefix(serviceAccount)) {
			foundDockercfgMountableSecret = true
			dockercfgSecretName = mountableSecret.Name
			break
		}
	}

	switch {
	// if we already have a docker pull secret, simply return
	case foundDockercfgImagePullSecret && foundDockercfgMountableSecret:
		return nil

	case foundDockercfgImagePullSecret && !foundDockercfgMountableSecret, !foundDockercfgImagePullSecret && foundDockercfgMountableSecret:
		staleDecision, err := e.createDockerPullSecretReference(serviceAccount, dockercfgSecretName)
		if staleDecision || kapierrors.IsConflict(err) {
			// nothing to do.  Our choice was stale or we got a conflict.  Either way that means that the service account was updated.  We simply need to return because we'll get an update notification later
			return nil
		}

		return err

	}

	// if we get here, then we need to create a new dockercfg secret
	dockercfgSecret, err := e.createDockerPullSecret(serviceAccount)
	if err != nil {
		return err
	}

	staleDecision, err := e.createDockerPullSecretReference(serviceAccount, dockercfgSecret.Name)
	if staleDecision || kapierrors.IsConflict(err) {
		// nothing to do.  Our choice was stale or we got a conflict.  Either way that means that the service account was updated.  We simply need to return because we'll get an update notification later
		// we do need to clean up our dockercfgSecret.  token secrets are cleaned up by the controller handling service account dockercfg secret deletes
		if err := e.client.Secrets(dockercfgSecret.Namespace).Delete(dockercfgSecret.Name); err != nil {
			glog.Error(err)
		}
		return nil
	}

	return err
}

// createDockerPullSecretReference updates a service account to reference the dockercfgSecret as a Secret and an ImagePullSecret
func (e *DockercfgController) createDockerPullSecretReference(staleServiceAccount *api.ServiceAccount, dockercfgSecretName string) ( /*isStale*/ bool, error) {
	liveServiceAccount, err := e.client.ServiceAccounts(staleServiceAccount.Namespace).Get(staleServiceAccount.Name)
	if err != nil {
		return false, err
	}

	mountableSecrets, imagePullSecrets := getSecretNames(liveServiceAccount)
	staleMountableSecrets, staleImagePullSecrets := getSecretNames(staleServiceAccount)

	// if we're trying to create a reference based on stale data, let the caller know
	if !reflect.DeepEqual(staleMountableSecrets.List(), mountableSecrets.List()) || !reflect.DeepEqual(staleImagePullSecrets.List(), imagePullSecrets.List()) {
		return true, fmt.Errorf("cannot add reference based on stale data.  decision made for %v, but live version is %v", staleServiceAccount.ResourceVersion, liveServiceAccount.ResourceVersion)
	}

	changed := false
	if !mountableSecrets.Has(dockercfgSecretName) {
		liveServiceAccount.Secrets = append(liveServiceAccount.Secrets, api.ObjectReference{Name: dockercfgSecretName})
		changed = true
	}

	if !imagePullSecrets.Has(dockercfgSecretName) {
		liveServiceAccount.ImagePullSecrets = append(liveServiceAccount.ImagePullSecrets, api.LocalObjectReference{Name: dockercfgSecretName})
		changed = true
	}

	if changed {
		if _, err = e.client.ServiceAccounts(liveServiceAccount.Namespace).Update(liveServiceAccount); err != nil {
			return false, err
		}
	}
	return false, nil
}

const (
	tokenSecretWaitInterval = 100 * time.Millisecond
	tokenSecretWaitTimes    = 20
)

// createTokenSecret creates a token secret for a given service account.  Returns the name of the token
func (e *DockercfgController) createTokenSecret(serviceAccount *api.ServiceAccount) (*api.Secret, error) {
	tokenSecret := &api.Secret{
		ObjectMeta: api.ObjectMeta{
			Name:      secret.Strategy.GenerateName(getTokenSecretNamePrefix(serviceAccount)),
			Namespace: serviceAccount.Namespace,
			Annotations: map[string]string{
				api.ServiceAccountNameKey: serviceAccount.Name,
				api.ServiceAccountUIDKey:  string(serviceAccount.UID),
			},
		},
		Type: api.SecretTypeServiceAccountToken,
		Data: map[string][]byte{},
	}

	_, err := e.client.Secrets(tokenSecret.Namespace).Create(tokenSecret)
	if err != nil {
		return nil, err
	}

	// now we have to wait for the service account token controller to make this valid
	// TODO remove this once we have a create-token endpoint
	for i := 0; i <= tokenSecretWaitTimes; i++ {
		liveTokenSecret, err := e.client.Secrets(tokenSecret.Namespace).Get(tokenSecret.Name)
		if err != nil {
			return nil, err
		}

		if _, exists := liveTokenSecret.Data[api.ServiceAccountTokenKey]; exists {
			return liveTokenSecret, nil
		}

		time.Sleep(wait.Jitter(tokenSecretWaitInterval, 0.0))

	}

	// the token wasn't ever created, attempt deletion
	if err := e.client.Secrets(tokenSecret.Namespace).Delete(tokenSecret.Name); err != nil {
		glog.Error(err)
	}
	return nil, fmt.Errorf("token never generated for %s", tokenSecret.Name)
}

// createDockerPullSecret creates a dockercfg secret based on the token secret
func (e *DockercfgController) createDockerPullSecret(serviceAccount *api.ServiceAccount) (*api.Secret, error) {
	tokenSecret, err := e.createTokenSecret(serviceAccount)
	if err != nil {
		return nil, err
	}

	dockercfgSecret := &api.Secret{
		ObjectMeta: api.ObjectMeta{
			Name:      secret.Strategy.GenerateName(getDockercfgSecretNamePrefix(serviceAccount)),
			Namespace: tokenSecret.Namespace,
			Annotations: map[string]string{
				api.ServiceAccountNameKey:        serviceAccount.Name,
				api.ServiceAccountUIDKey:         string(serviceAccount.UID),
				ServiceAccountTokenSecretNameKey: string(tokenSecret.Name),
			},
		},
		Type: api.SecretTypeDockercfg,
		Data: map[string][]byte{},
	}

	// prevent updating the DockerURL until we've created the secret
	e.dockerURLLock.Lock()
	defer e.dockerURLLock.Unlock()

	dockercfg := &credentialprovider.DockerConfig{
		e.dockerURL: credentialprovider.DockerConfigEntry{
			Username: "serviceaccount",
			Password: string(tokenSecret.Data[api.ServiceAccountTokenKey]),
			Email:    "serviceaccount@example.org",
		},
	}
	dockercfgContent, err := json.Marshal(dockercfg)
	if err != nil {
		return nil, err
	}
	dockercfgSecret.Data[api.DockerConfigKey] = dockercfgContent

	// Save the secret
	createdSecret, err := e.client.Secrets(tokenSecret.Namespace).Create(dockercfgSecret)

	return createdSecret, err
}

func getSecretReferences(serviceAccount *api.ServiceAccount) util.StringSet {
	references := util.NewStringSet()
	for _, secret := range serviceAccount.Secrets {
		references.Insert(secret.Name)
	}
	return references
}

func getSecretNames(serviceAccount *api.ServiceAccount) (util.StringSet, util.StringSet) {
	mountableSecrets := util.StringSet{}
	imagePullSecrets := util.StringSet{}

	for _, s := range serviceAccount.Secrets {
		mountableSecrets.Insert(s.Name)
	}
	for _, s := range serviceAccount.ImagePullSecrets {
		imagePullSecrets.Insert(s.Name)
	}
	return mountableSecrets, imagePullSecrets
}
