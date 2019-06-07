package main

import (
	"bytes"
	"encoding/json"
	goflag "flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/serviceability"
	"github.com/openshift/origin/pkg/version"
)

func main() {

	rand.Seed(time.Now().UTC().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()
	defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
	defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	command := NewCommitParseCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

type CommitParseOptions struct {
	Filename string
}

func NewCommitParseCommand() *cobra.Command {
	o := &CommitParseOptions{}
	cmd := &cobra.Command{
		Use: "commit-parse",
		Run: func(cmd *cobra.Command, args []string) {
			if err := o.Run(); err != nil {
				klog.Fatal(err)
			}
		},
	}
	cmd.Flags().StringVarP(&o.Filename, "filename", "f", o.Filename, "json file")

	return cmd
}

type OrgCommits struct {
	RepoCommitMap `json:",inline"`
}

type RepoCommitMap map[string]RepoCommits

type RepoCommits struct {
	LastYear []ContributorCommits `json:"lastYear"`
	LastFive []ContributorCommits `json:"lastFive"`
}

type ContributorCommits map[string]int

func (o *CommitParseOptions) Run() error {
	jsonBytes, err := ioutil.ReadFile(o.Filename)
	if err != nil {
		return err
	}

	//orgCommits := &OrgCommits{}
	//if err := json.NewDecoder(bytes.NewBuffer(jsonBytes)).Decode(orgCommits); err != nil {
	//	return err
	//}
	//
	//lastYearContributorCommits := ContributorCommits{}
	//for _, repoCommits := range orgCommits.RepoCommitMap {
	//	for _, currLastYear := range repoCommits.LastYear {
	//		for contributor, commits := range currLastYear {
	//			currVal := lastYearContributorCommits[contributor]
	//			lastYearContributorCommits[contributor] = currVal + commits
	//		}
	//	}
	//}

	orgCommits := map[string]interface{}{}
	if err := json.NewDecoder(bytes.NewBuffer(jsonBytes)).Decode(&orgCommits); err != nil {
		return err
	}

	lastYearContributorCommits := ContributorCommits{}
	for _, repoCommits := range orgCommits {
		repoCommitMap := repoCommits.(map[string]interface{})
		lastYearInterface := repoCommitMap["lastYear"]
		lastYearSlice := lastYearInterface.([]interface{})
		for _, currLastYear := range lastYearSlice {
			for contributor, commits := range currLastYear.(map[string]interface{}) {
				currVal := lastYearContributorCommits[contributor]
				lastYearContributorCommits[contributor] = currVal + int(commits.(float64))
			}
		}
	}

	for contributor, commits := range lastYearContributorCommits {
		fmt.Printf("%q, %d\n", contributor, commits)
	}

	return nil
}
