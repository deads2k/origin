package dir

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir provides directory creation for cluster up components. In case the hostDir is specified, it will use
// that directory as a base directory for all configs. In case the hostDir already exists, this will return true.
// In case it is not specified a temporary directory is created.
func ConfigDir(hostDir, component string) (string, error) {
	if len(hostDir) > 0 {
		dirName := filepath.Join(hostDir, component)
		return dirName, os.MkdirAll(dirName, os.ModePerm)
	}
	var tmpDirFn func() string
	switch runtime.GOOS {
	// OSX is special, because Docker For Mac only allow mounting files from "/tmp", but the
	// OSX users usually have private $TMPDIR (which is what os.TempDir use.
	case "darwin":
		tmpDirFn = func() string { return "/tmp" }
	default:
		tmpDirFn = os.TempDir
	}
	return ioutil.TempDir(tmpDirFn(), component+"-")
}
