package kernel

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/cpuset"
)

const (
	hwlatdetectThresholdusec = 7500
	oslatThresholdusec       = 7500
	cyclictestThresholdusec  = 7500
	rtevalThresholdusec      = 7500
)

func runPiStressFifo(oc *exutil.CLI) error {
	args := []string{rtPodName, "--", "pi_stress", "--duration=600", "--groups=1"}
	_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()

	return err
}

func runPiStressRR(oc *exutil.CLI) error {
	args := []string{rtPodName, "--", "pi_stress", "--duration=600", "--groups=1", "--rr"}
	_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()

	return err
}

func runDeadlineTest(oc *exutil.CLI) error {
	args := []string{rtPodName, "--", "deadline_test"}
	_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()

	return err
}

func runHwlatdetect(oc *exutil.CLI) error {
	args := []string{rtPodName, "--", "hwlatdetect", "--duration=600s", "--window=1s", "--width=500ms", fmt.Sprintf("--threshold=%dus", hwlatdetectThresholdusec)}
	_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		// An error here indicates thresholds were exceeded or an issue with the test
		return errors.Wrap(err, "error running hwlatdetect")
	}

	return nil
}

func runOslat(cpuCount int, oc *exutil.CLI) error {
	oslatReportFile := "/tmp/oslatresults.json"

	// Make sure there is enough hardware for this test
	if cpuCount <= 4 {
		return fmt.Errorf("more than 4 cores are required to run this oslat test. Found %d cores", cpuCount)
	}

	reservedCores, err := getReservedCores(oc)
	if err != nil {
		return errors.Wrap(err, "unable to get the reserved core configuration")
	}

	// Run the test
	args := []string{rtPodName, "--", "oslat", "--cpu-list", fmt.Sprintf("%d-%d", reservedCores+1, cpuCount-1), "--rtprio", "1", "--duration", "600", "--json", oslatReportFile}
	_, err = oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return errors.Wrap(err, "error running oslat")
	}

	// Get the results
	args = []string{rtPodName, "--", "cat", oslatReportFile}
	report, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return errors.Wrap(err, "error retrieving oslat results")
	}

	// Parse the results and return any errors detected
	if err = parseOslatResults(report, oslatThresholdusec); err != nil {
		return errors.Wrap(err, "error parsing oslat report")
	}

	return nil
}

func parseOslatResults(jsonReport string, maxThresholdusec int) error {
	var oslatReport struct {
		Threads map[string]struct {
			Cpu int `json:"cpu"`
			Max int `json:"max"`
		} `json:"thread"`
	}

	// Parse the data
	err := json.Unmarshal([]byte(jsonReport), &oslatReport)
	if err != nil {
		return errors.Wrap(err, "unable to decode oslat report json")
	}

	if len(oslatReport.Threads) == 0 {
		return fmt.Errorf("no thread reports found")
	}

	failedCPUs := make([]int, 0, len(oslatReport.Threads)) // Report all failed cores
	for _, thread := range oslatReport.Threads {
		if thread.Max > maxThresholdusec {
			failedCPUs = append(failedCPUs, thread.Cpu)
		}
	}

	if len(failedCPUs) > 0 {
		return fmt.Errorf("the following CPUs were over the max latency threshold: %v", failedCPUs)
	}

	return nil
}

func runCyclictest(cpuCount int, oc *exutil.CLI) error {
	cyclictestReportFile := "/tmp/cyclictestresults.json"
	// Make sure there is enough hardware for this test
	if cpuCount <= 4 {
		return fmt.Errorf("more than 4 cores are required to run this oslat test. Found %d cores", cpuCount)
	}

	// Run the test
	args := []string{rtPodName, "--", "cyclictest", "--duration=10m", "--priority=95", fmt.Sprintf("--threads=%d", cpuCount-5), fmt.Sprintf("--affinity=4-%d", cpuCount-1), "--interval=1000", fmt.Sprintf("--breaktrace=%d", cyclictestThresholdusec), "--mainaffinity=4", "-m", fmt.Sprintf("--json=%s", cyclictestReportFile)}
	_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return errors.Wrap(err, "error running cyclictest")
	}

	// Gather the results
	args = []string{rtPodName, "--", "cat", cyclictestReportFile}
	report, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return errors.Wrap(err, "error retrieving cyclictest results")
	}

	// Parse the results and return any errors detected
	if err = parseCyclictestResults(report, cyclictestThresholdusec); err != nil {
		return errors.Wrap(err, "error parsing cyclictest report")
	}

	return nil
}

func parseCyclictestResults(jsonReport string, maxThresholdusec int) error {
	var cyclictestReport struct {
		Threads map[string]struct {
			Cpu int `json:"cpu"`
			Max int `json:"max"`
		} `json:"thread"`
	}

	// Parse the data
	err := json.Unmarshal([]byte(jsonReport), &cyclictestReport)
	if err != nil {
		return errors.Wrap(err, "unable to decode cyclictest report json")
	}

	if len(cyclictestReport.Threads) == 0 {
		return fmt.Errorf("no thread reports found")
	}

	failedCPUs := make([]int, 0, len(cyclictestReport.Threads)) // Report all failed cores
	for _, thread := range cyclictestReport.Threads {
		if thread.Max > maxThresholdusec {
			failedCPUs = append(failedCPUs, thread.Cpu)
		}
	}

	if len(failedCPUs) > 0 {
		return fmt.Errorf("the following CPUs were over the max latency threshold: %v", failedCPUs)
	}

	return nil
}

func getProcessorCount(oc *exutil.CLI) (int, error) {
	args := []string{rtPodName, "--", "getconf", "_NPROCESSORS_ONLN"}
	num, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return 0, err
	}

	// Parse out the CPU count
	count, err := strconv.Atoi(num)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// getReservedCores will parse the performance profile (if it exists) and look for the reserved cpu configuration
// The expected configurations should start with core 0 and be in the form 0-X
func getReservedCores(oc *exutil.CLI) (int, error) {
	// Performance profiles dictate constrained CPUSets, we gather them here to compare.
	// Note: We're using a dynamic client here to avoid importing the PerformanceProfile
	// for a simple query and keep this code change small. If we end up needing more interaction
	// with PerformanceProfiles, then we should import the package and update this call.

	performanceProfiles, err := oc.AdminDynamicClient().
		Resource(schema.GroupVersionResource{
			Resource: "performanceprofiles",
			Group:    "performance.openshift.io",
			Version:  "v2"}).Namespace("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("error listing performance profiles: %w", err)
	}

	if len(performanceProfiles.Items) == 0 {
		e2e.Logf("no performance profile detected, using 0-3 as reserved cores")

		return 3, nil
	}

	if len(performanceProfiles.Items) > 1 {
		return 0, fmt.Errorf("unable to determine reserved cores, more than 1 performance profile was found")
	}

	pprof := performanceProfiles.Items[0]
	reservedCPU, found, err := unstructured.NestedString(pprof.Object, "spec", "cpu", "reserved")
	if err != nil {
		return 0, fmt.Errorf("error getting reservedCPUSet from PerformanceProfile: %w", err)
	}
	if !found {
		return 0, fmt.Errorf("expected spec.reserved to be found in PerformanceProfile(%s)", pprof.GetName())
	}

	reservedCPUset, err := cpuset.Parse(reservedCPU)
	if err != nil {
		return 0, errors.Wrap(err, "unable to parse the reserved cpuset")
	}

	reservedCPUs := strings.Split(reservedCPUset.String(), "-")
	if len(reservedCPUs) != 2 {
		return 0, fmt.Errorf("abnormal reserved cpu configuration detected. Please use the form '0-X'")
	}

	reservedEnd, err := strconv.Atoi(reservedCPUs[1])
	if err != nil {
		return 0, errors.Wrap(err, "unable to parse the end of the reserved cpu block")
	}

	return reservedEnd, nil
}

type rtevalOutput struct {
	XMLName    xml.Name `xml:"rteval"`
	Statistics struct {
		XMLName               xml.Name `xml:"statistics"`
		Samples               int      `xml:"samples"`
		Minimum               int      `xml:"minimum"`
		Maximum               int      `xml:"maximum"`
		Median                float32  `xml:"median"`
		Mode                  int      `xml:"mode"`
		Range                 int      `xml:"range"`
		Mean                  float32  `xml:"mean"`
		MeanAbsoluteDeviation float32  `xml:"mean_absolute_deviation"`
		StandardDeviation     float32  `xml:"standard_deviation"`
	} `xml:"Measurements>Profile>cyclictest>system>statistics"`
}

func runRteval(oc *exutil.CLI) error {
	// The working directory for the pod under test
	// This is where rteval will create a directory and write results
	rtevalWorkDir := "/tmp"

	// Run the test
	args := []string{rtPodName, "--", "rteval", "--duration=10m", fmt.Sprintf("--workdir=%s", rtevalWorkDir)}
	_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return errors.Wrap(err, "error running rteval")
	}

	// rteval-YYYYMMDD-S This is a directory created by rteval to hold the summary.xml file where S is the Sequence this has been run (should be 1 for this test)
	today := time.Now().Format("20060102") // YYYYMMDD
	summaryFile := fmt.Sprintf("%s/rteval-%s-%d/summary.xml", rtevalWorkDir, today, 1)

	// Gather the results
	args = []string{rtPodName, "--", "cat", summaryFile}
	report, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
	if err != nil {
		return errors.Wrap(err, "error retrieving rteval results")
	}

	var res rtevalOutput
	if err := xml.Unmarshal([]byte(report), &res); err != nil {
		return errors.Wrap(err, "Unable to parse rteval xml report")
	}

	// Verify we meet the threshold value
	if res.Statistics.Maximum > rtevalThresholdusec {
		return fmt.Errorf("maximum rteval latency of %d usec exceeded maximum allowed of %d usec", res.Statistics.Maximum, rtevalThresholdusec)
	}

	return nil
}
