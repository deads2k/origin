package kubelet

import (
	"fmt"
	"io"
	"os"

	"github.com/golang/glog"
	"github.com/openshift/origin/pkg/oc/bootstrap/docker/dockerhelper"
	"github.com/openshift/origin/pkg/oc/bootstrap/docker/run"
	"github.com/openshift/origin/pkg/oc/errors"
	"github.com/openshift/origin/pkg/oc/util/dir"
)

const (
	ComponentDirectoryName        = "oc-cluster-up-node"
	ComponentKubeDNSDirectoryName = "oc-cluster-up-kubedns"
)

type NodeStartConfig struct {
	// ContainerBinds is a list of local/path:image/path pairs
	ContainerBinds []string
	// NodeImage is the docker image for openshift start node
	NodeImage string

	Args []string

	HostDir string
}

func NewNodeStartConfig() *NodeStartConfig {
	return &NodeStartConfig{
		ContainerBinds: []string{},
	}

}

func (opt NodeStartConfig) MakeKubeDNSConfig(dockerClient dockerhelper.Interface, imageRunHelper *run.Runner, out io.Writer) (string, error) {
	return opt.makeConfig(dockerClient, imageRunHelper, out, ComponentKubeDNSDirectoryName)
}

func (opt NodeStartConfig) MakeNodeConfig(dockerClient dockerhelper.Interface, imageRunHelper *run.Runner, out io.Writer) (string, error) {
	return opt.makeConfig(dockerClient, imageRunHelper, out, ComponentDirectoryName)
}

// Start starts the OpenShift master as a Docker container
// and returns a directory in the local file system where
// the OpenShift configuration has been copied
func (opt NodeStartConfig) makeConfig(dockerClient dockerhelper.Interface, imageRunHelper *run.Runner, out io.Writer, componentName string) (string, error) {
	nodeConfigDir, err := dir.ConfigDir(opt.HostDir, componentName)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(out, "Creating initial OpenShift node configuration\n")
	createConfigCmd := []string{
		"adm", "create-node-config",
		fmt.Sprintf("--node-dir=%s", "/var/lib/origin/openshift.local.config"),
	}
	createConfigCmd = append(createConfigCmd, opt.Args...)

	containerId, _, err := imageRunHelper.Image(opt.NodeImage).
		Privileged().
		HostNetwork().
		HostPid().
		Bind(opt.ContainerBinds...).
		Entrypoint("oc").
		Command(createConfigCmd...).Run()
	if err != nil {
		return "", errors.NewError("could not create OpenShift configuration: %v", err).WithCause(err)
	}

	glog.V(1).Infof("Copying OpenShift node config to local directory %s", nodeConfigDir)
	if err = dockerhelper.DownloadDirFromContainer(dockerClient, containerId, "/var/lib/origin/openshift.local.config", nodeConfigDir); err != nil {
		if removeErr := os.RemoveAll(nodeConfigDir); removeErr != nil {
			glog.V(2).Infof("Error removing temporary config dir %s: %v", nodeConfigDir, removeErr)
		}
		return "", err
	}

	return nodeConfigDir, nil
}
