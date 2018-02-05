package kubelet

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/openshift/origin/pkg/oc/bootstrap/docker/run"
	"github.com/openshift/origin/pkg/oc/errors"
)

type NodeStartConfig struct {
	// ContainerBinds is a list of local/path:image/path pairs
	ContainerBinds []string
	// NodeImage is the docker image for openshift start node
	NodeImage string

	Args []string
}

func NewNodeStartConfig() *NodeStartConfig {
	return &NodeStartConfig{
		ContainerBinds: []string{},
	}

}

// Start starts the OpenShift master as a Docker container
// and returns a directory in the local file system where
// the OpenShift configuration has been copied
func (opt NodeStartConfig) MakeNodeConfig(imageRunHelper *run.Runner, out io.Writer) (string, error) {
	tempDir, err := ioutil.TempDir("", "oc-cluster-up-control-plane-node-")
	if err != nil {
		return "", err
	}

	binds := append(opt.ContainerBinds, fmt.Sprintf("%s:/var/lib/origin/openshift.local.config:z", tempDir))

	fmt.Fprintf(out, "Creating initial OpenShift node configuration\n")
	createConfigCmd := []string{
		"adm", "create-node-config",
		fmt.Sprintf("--node-dir=%s", "/var/lib/origin/openshift.local.config"),
	}
	createConfigCmd = append(createConfigCmd, opt.Args...)

	_, _, err = imageRunHelper.Image(opt.NodeImage).
		Privileged().
		DiscardContainer().
		HostNetwork().
		HostPid().
		Bind(binds...).
		Entrypoint("oc").
		Command(createConfigCmd...).Run()
	if err != nil {
		return "", errors.NewError("could not create OpenShift configuration: %v", err).WithCause(err)
	}

	return tempDir, nil
}
