package deploylog

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/errors"
	ktestclient "k8s.io/kubernetes/pkg/client/unversioned/testclient"
	kubeletclient "k8s.io/kubernetes/pkg/kubelet/client"
	genericrest "k8s.io/kubernetes/pkg/registry/generic/rest"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"

	"github.com/openshift/origin/pkg/client/testclient"
	"github.com/openshift/origin/pkg/deploy/api"
	deploytest "github.com/openshift/origin/pkg/deploy/api/test"
	deployutil "github.com/openshift/origin/pkg/deploy/util"
)

func makeDeployment(version int) kapi.ReplicationController {
	deployment, _ := deployutil.MakeDeployment(deploytest.OkDeploymentConfig(version), kapi.Codecs.LegacyCodec(api.SchemeGroupVersion))
	return *deployment
}

func makeDeploymentList(versions int) *kapi.ReplicationControllerList {
	list := &kapi.ReplicationControllerList{}
	for v := 1; v <= versions; v++ {
		list.Items = append(list.Items, makeDeployment(v))
	}
	return list
}

// Mock pod resource getter
type deployerPodGetter struct{}

func (p *deployerPodGetter) Get(ctx kapi.Context, name string) (runtime.Object, error) {
	return &kapi.Pod{
		ObjectMeta: kapi.ObjectMeta{
			Name:      name,
			Namespace: kapi.NamespaceDefault,
		},
		Spec: kapi.PodSpec{
			Containers: []kapi.Container{
				{
					Name: name + "-container",
				},
			},
			NodeName: name + "-host",
		},
	}, nil
}

// mockREST mocks a DeploymentLog REST
func mockREST(version, desired int, endStatus api.DeploymentStatus) *REST {
	connectionInfo := &kubeletclient.HTTPKubeletClient{Config: &kubeletclient.KubeletClientConfig{EnableHttps: true, Port: 12345}, Client: &http.Client{}}

	// Fake deploymentConfig
	config := deploytest.OkDeploymentConfig(version)
	fakeDn := testclient.NewSimpleFake(config)
	fakeDn.PrependReactor("get", "deploymentconfigs", func(action ktestclient.Action) (handled bool, ret runtime.Object, err error) {
		return true, config, nil
	})

	// Used for testing various cases prior to getting replication controllers
	// such as validation errors, wrong usage of -p, etc.
	if desired > version {
		return &REST{
			ConfigGetter:   fakeDn,
			PodGetter:      &deployerPodGetter{},
			ConnectionInfo: connectionInfo,
			Timeout:        defaultTimeout,
		}
	}

	// Fake deployments
	fakeDeployments := makeDeploymentList(version)
	fakeRn := ktestclient.NewSimpleFake(fakeDeployments)
	fakeRn.PrependReactor("get", "replicationcontrollers", func(action ktestclient.Action) (handled bool, ret runtime.Object, err error) {
		return true, &fakeDeployments.Items[desired-1], nil
	})

	// Fake watcher for deployments
	fakeWatch := watch.NewFake()
	fakeRn.PrependWatchReactor("replicationcontrollers", ktestclient.DefaultWatchReactor(fakeWatch, nil))
	obj := &fakeDeployments.Items[desired-1]
	obj.Annotations[api.DeploymentStatusAnnotation] = string(endStatus)
	go fakeWatch.Add(obj)

	return &REST{
		ConfigGetter:     fakeDn,
		DeploymentGetter: fakeRn,
		PodGetter:        &deployerPodGetter{},
		ConnectionInfo:   connectionInfo,
		Timeout:          defaultTimeout,
	}
}

func TestRESTGet(t *testing.T) {
	ctx := kapi.NewDefaultContext()

	tests := []struct {
		testName    string
		rest        *REST
		name        string
		opts        runtime.Object
		expected    runtime.Object
		expectedErr error
	}{
		{
			testName: "running deployment",
			rest:     mockREST(1, 1, api.DeploymentStatusRunning),
			name:     "config",
			opts:     &api.DeploymentLogOptions{Follow: true, Version: intp(1)},
			expected: &genericrest.LocationStreamer{
				Location: &url.URL{
					Scheme:   "https",
					Host:     "config-1-deploy-host:12345",
					Path:     "/containerLogs/default/config-1-deploy/config-1-deploy-container",
					RawQuery: "follow=true",
				},
				Transport:       nil,
				ContentType:     "text/plain",
				Flush:           true,
				ResponseChecker: genericrest.NewGenericHttpResponseChecker(kapi.Resource("Pod"), "config-1-deploy"),
			},
			expectedErr: nil,
		},
		{
			testName:    "complete deployment",
			rest:        mockREST(5, 5, api.DeploymentStatusComplete),
			name:        "config",
			opts:        &api.DeploymentLogOptions{Follow: true, Version: intp(5)},
			expected:    &genericrest.LocationStreamer{},
			expectedErr: nil,
		},
		{
			testName: "previous failed deployment",
			rest:     mockREST(3, 2, api.DeploymentStatusFailed),
			name:     "config",
			opts:     &api.DeploymentLogOptions{Follow: false, Version: intp(2)},
			expected: &genericrest.LocationStreamer{
				Location: &url.URL{
					Scheme: "https",
					Host:   "config-2-deploy-host:12345",
					Path:   "/containerLogs/default/config-2-deploy/config-2-deploy-container",
				},
				Transport:       nil,
				ContentType:     "text/plain",
				Flush:           false,
				ResponseChecker: genericrest.NewGenericHttpResponseChecker(kapi.Resource("Pod"), "config-2-deploy"),
			},
			expectedErr: nil,
		},
		{
			testName: "previous deployment",
			rest:     mockREST(3, 2, api.DeploymentStatusFailed),
			name:     "config",
			opts:     &api.DeploymentLogOptions{Follow: false, Previous: true},
			expected: &genericrest.LocationStreamer{
				Location: &url.URL{
					Scheme: "https",
					Host:   "config-2-deploy-host:12345",
					Path:   "/containerLogs/default/config-2-deploy/config-2-deploy-container",
				},
				Transport:       nil,
				ContentType:     "text/plain",
				Flush:           false,
				ResponseChecker: genericrest.NewGenericHttpResponseChecker(kapi.Resource("Pod"), "config-2-deploy"),
			},
			expectedErr: nil,
		},
		{
			testName:    "non-existent previous deployment",
			rest:        mockREST(1 /* won't be used */, 101, ""),
			name:        "config",
			opts:        &api.DeploymentLogOptions{Follow: false, Previous: true},
			expected:    nil,
			expectedErr: errors.NewBadRequest("no previous deployment exists for deploymentConfig \"config\""),
		},
	}

	for _, test := range tests {
		got, err := test.rest.Get(ctx, test.name, test.opts)
		if err != nil && test.expectedErr != nil && err.Error() != test.expectedErr.Error() {
			t.Errorf("%s: error mismatch: expected %v, got %v", test.testName, test.expectedErr, err)
			continue
		}
		if err != nil && test.expectedErr == nil {
			t.Errorf("%s: error mismatch: expected no error, got %v", test.testName, err)
			continue
		}
		if err == nil && test.expectedErr != nil {
			t.Errorf("%s: error mismatch: expected %v, got no error", test.testName, test.expectedErr)
			continue
		}
		if !reflect.DeepEqual(got, test.expected) {
			t.Errorf("%s: location streamer mismatch: expected\n%#v\ngot\n%#v\n", test.testName, test.expected, got)
			if testing.Verbose() {
				e := test.expected.(*genericrest.LocationStreamer)
				a := got.(*genericrest.LocationStreamer)
				t.Errorf("%s: expected url:\n%v\ngot:\n%v\n", test.testName, e.Location, a.Location)
			}
		}
	}
}

// TODO: These kind of functions seem to be used in lots of places
// We should move it in a common location
func intp(num int64) *int64 {
	return &num
}
