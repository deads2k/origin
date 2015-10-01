package syncgroups

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"

	configapilatest "github.com/openshift/origin/pkg/cmd/server/api/latest"
	kapi "k8s.io/kubernetes/pkg/api"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	kerrs "k8s.io/kubernetes/pkg/util/errors"
	"k8s.io/kubernetes/pkg/util/sets"
	kyaml "k8s.io/kubernetes/pkg/util/yaml"

	"github.com/openshift/origin/pkg/auth/ldaputil"
	osclient "github.com/openshift/origin/pkg/client"
	"github.com/openshift/origin/pkg/cmd/experimental/syncgroups/interfaces"
	"github.com/openshift/origin/pkg/cmd/experimental/syncgroups/rfc2307"
	"github.com/openshift/origin/pkg/cmd/server/api"
	"github.com/openshift/origin/pkg/cmd/server/api/validation"
	"github.com/openshift/origin/pkg/cmd/util/clientcmd"
)

const (
	SyncGroupsRecommendedName = "sync-groups"

	syncGroupsLong = `
Sync OpenShift Groups with records from an external provider.

In order to sync OpenShift Group records with those from an external provider, determine which Groups you wish
to sync and where their records live. For instance, all or some groups may be selected from the current Groups
stored in OpenShift that have been synced previously, or similarly all or some groups may be selected from those 
stored on an LDAP server. The path to a sync configuration file is required in order to describe how data is 
requested from the external record store and migrated to OpenShift records. Default behavior is to sync all 
groups from the LDAP server returned by the LDAP query templates.
`
	syncGroupsExamples = `  // Sync all groups from an LDAP server
  $ %[1]s --sync-config=/path/to/ldap-sync-config.yaml

  // Sync specific groups specified in a whitelist file with an LDAP server 
  $ %[1]s --whitelist=/path/to/whitelist.txt --sync-config=/path/to/sync-config.yaml

  // Sync all OpenShift Groups that have been synced previously with an LDAP server
  $ %[1]s --existing --sync-config=/path/to/ldap-sync-config.yaml

  // Sync specific OpenShift Groups if they have been synced previously with an LDAP server
  $ %[1]s groups/group1 groups/group2 groups/group3 --sync-config=/path/to/sync-config.yaml
`
)

// GroupSyncScope determines the scope of the group sync operation
type GroupSyncScope string

const (
	// GroupSyncScopeAll determines that all groups from the source should be synced
	GroupSyncScopeAll GroupSyncScope = "All"
	// GroupSyncScopeWhitelist determines that a whitelist of groups from the source should be synced
	GroupSyncScopeWhitelist GroupSyncScope = "Whitelist"
)

func ValidateScope(scope GroupSyncScope) bool {
	knownScopes := sets.NewString(string(GroupSyncScopeAll), string(GroupSyncScopeWhitelist))
	return knownScopes.Has(string(scope))
}

// GroupSyncSource determines the source of the groups to be synced
type GroupSyncSource string

const (
	// GroupSyncSourceLDAP determines that the groups to be synced are determined from an LDAP record
	GroupSyncSourceLDAP GroupSyncSource = "LDAP"
	// GroupSyncSourceOpenShift determines that the groups to be synced are determined from OpenShift records
	GroupSyncSourceOpenShift GroupSyncSource = "OpenShift"
)

func ValidateSource(source GroupSyncSource) bool {
	knownSources := sets.NewString(string(GroupSyncSourceLDAP), string(GroupSyncSourceOpenShift))
	return knownSources.Has(string(source))
}

type SyncGroupsOptions struct {
	// Source determines the source of the list of groups to sync
	Source GroupSyncSource

	// Scope determines the scope of the group sync
	Scope GroupSyncScope

	// ConfigSource is the path to the sync config
	ConfigSource string

	// Config is the LDAP sync config read from file
	Config api.LDAPSyncConfig

	// WhitelistSource is the path to the whitelist file, if provided
	WhitelistSource string

	// WhitelistContents are the contents of the whitelist: names of OpenShift group or LDAP group UIDs
	WhitelistContents []string

	// SyncExisting determines that only groups in OpenShift previously synced with this LDAP server
	// will be synced again
	SyncExisting bool

	// Confirm determines whether not to write to openshift
	Confirm bool

	// GroupsInterface is the interface used to interact with OpenShift Group objects
	GroupInterface osclient.GroupInterface

	// Stderr is the writer to write warnings and errors to
	Stderr io.Writer

	// Out is the writer to write output to
	Out io.Writer
}

func NewSyncGroupsOptions() *SyncGroupsOptions {
	return &SyncGroupsOptions{
		Stderr:            os.Stderr,
		WhitelistContents: []string{},
	}
}

func NewCmdSyncGroups(name, fullName string, f *clientcmd.Factory, out io.Writer) *cobra.Command {
	options := NewSyncGroupsOptions()
	options.Out = out

	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s [SOURCE SCOPE WHITELIST --whitelist=WHITELIST-FILE] --sync-config=CONFIG-SOURCE", name),
		Short:   "Sync OpenShift Groups with records from an external provider.",
		Long:    syncGroupsLong,
		Example: fmt.Sprintf(syncGroupsExamples, fullName),
		Run: func(c *cobra.Command, args []string) {
			if err := options.Complete(args, f); err != nil {
				cmdutil.CheckErr(cmdutil.UsageError(c, err.Error()))
			}

			if err := options.Validate(); err != nil {
				cmdutil.CheckErr(cmdutil.UsageError(c, err.Error()))
			}

			err := options.Run(c, f)
			if err != nil {
				if aggregate, ok := err.(kerrs.Aggregate); ok {
					for _, err := range aggregate.Errors() {
						fmt.Printf("%s\n", err)
					}
					os.Exit(1)
				}
			}
			cmdutil.CheckErr(err)
		},
	}

	cmd.Flags().StringVar(&options.WhitelistSource, "whitelist", "", "path to the group whitelist")
	cmd.Flags().StringVar(&options.ConfigSource, "sync-config", "", "path to the sync config")
	cmd.Flags().BoolVar(&options.SyncExisting, "existing", false, "sync only existing, previously-synced groups")
	cmd.Flags().BoolVar(&options.Confirm, "confirm", false, "if true, modify OpenShift groups; if false, display groups")
	cmdutil.AddPrinterFlags(cmd)
	cmd.Flags().Lookup("output").DefValue = "yaml"
	cmd.Flags().Lookup("output").Value.Set("yaml")

	return cmd
}

func (o *SyncGroupsOptions) Complete(args []string, f *clientcmd.Factory) error {
	if o.SyncExisting {
		o.Source = GroupSyncSourceOpenShift
	} else {
		o.Source = GroupSyncSourceLDAP
	}

	// if no scope argument is given, use default
	if len(args) == 0 {
		o.Scope = GroupSyncScopeAll
	}

	// if args are given, they are OpenShift Group names forming a whitelist
	if len(args) > 0 {
		o.Scope = GroupSyncScopeWhitelist
		o.WhitelistContents = append(o.WhitelistContents, args[0:]...)
	}

	// unpack whitelist file from source
	if len(o.WhitelistSource) != 0 {
		if whitelistData, err := readLines(o.WhitelistSource); err != nil {
			return err
		} else {
			o.WhitelistContents = append(o.WhitelistContents, whitelistData...)
		}
	}

	yamlConfig, err := ioutil.ReadFile(o.ConfigSource)
	if err != nil {
		return fmt.Errorf("could not read file %s: %v", o.ConfigSource, err)
	}
	jsonConfig, err := kyaml.ToJSON(yamlConfig)
	if err != nil {
		return fmt.Errorf("could not parse file %s: %v", o.ConfigSource, err)
	}
	if err := configapilatest.Codec.DecodeInto(jsonConfig, &o.Config); err != nil {
		return err
	}

	if f != nil {
		osClient, _, err := f.Clients()
		if err != nil {
			return err
		}
		o.GroupInterface = osClient.Groups()
	}

	return nil
}

// readLines interprets a file as plaintext and returns a string array of the lines of text in the file
func readLines(path string) ([]string, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %v", path, err)
	}
	rawLines := strings.Split(string(bytes), "\n")
	var trimmedLines []string
	for _, line := range rawLines {
		trimmedLines = append(trimmedLines, strings.TrimSpace(line))
	}
	return trimmedLines, nil
}

func (o *SyncGroupsOptions) Validate() error {
	if !ValidateSource(o.Source) {
		return fmt.Errorf("sync source must be one of the following: %v", []GroupSyncSource{GroupSyncSourceLDAP, GroupSyncSourceOpenShift})
	}
	if !ValidateScope(o.Scope) {
		return fmt.Errorf("sync scope must be one of the following: %v", []GroupSyncScope{GroupSyncScopeAll, GroupSyncScopeWhitelist})
	}
	// If the scope is a whitelist, a list of whitelist contents must be provided
	if o.Scope == GroupSyncScopeWhitelist && len(o.WhitelistContents) == 0 {
		return fmt.Errorf("a list of unique group identifiers is required for sync scope %s", o.Scope)
	}

	results := validation.ValidateLDAPSyncConfig(o.Config)
	// TODO(skuznets): pretty-print validation results
	if len(results.Errors) > 0 {
		return fmt.Errorf("validation of LDAP sync config failed: %v", kerrs.NewAggregate([]error(results.Errors)))
	}
	return nil
}

// Run creates the GroupSyncer specified and runs it to sync groups
// the arguments are only here because its the only way to get the printer we need
func (o *SyncGroupsOptions) Run(cmd *cobra.Command, f *clientcmd.Factory) error {
	// In order to create the GroupSyncer, we need to build its' parts:
	// interpret user-provided configuration
	clientConfig, err := ldaputil.NewLDAPClientConfig(
		o.Config.URL,
		o.Config.BindDN,
		o.Config.BindPassword,
		o.Config.CA,
		o.Config.Insecure)
	if err != nil {
		return fmt.Errorf("could not determine LDAP client configuration: %v", err)
	}

	// populate schema-independent syncer fields
	syncer := LDAPGroupSyncer{
		Host:         clientConfig.Host,
		GroupClient:  o.GroupInterface,
		SyncExisting: o.SyncExisting,
	}

	if len(o.Config.LDAPGroupUIDToOpenShiftGroupNameMapping) > 0 {
		syncer.GroupNameMapper = NewUserDefinedGroupNameMapper(o.Config.LDAPGroupUIDToOpenShiftGroupNameMapping)
	}

	switch {
	case o.Config.RFC2307Config != nil:
		syncer.UserNameMapper = NewUserNameMapper(o.Config.RFC2307Config.UserNameAttributes)

		// config values are internalized
		groupQuery, err := ldaputil.NewLDAPQueryOnAttribute(o.Config.RFC2307Config.AllGroupsQuery, o.Config.RFC2307Config.GroupUIDAttribute)
		if err != nil {
			return err
		}

		userQuery, err := ldaputil.NewLDAPQueryOnAttribute(o.Config.RFC2307Config.AllUsersQuery, o.Config.RFC2307Config.UserUIDAttribute)
		if err != nil {
			return err
		}

		// the schema-specific ldapInterface is built from the config
		ldapInterface := rfc2307.NewLDAPInterface(clientConfig,
			groupQuery,
			o.Config.RFC2307Config.GroupNameAttributes,
			o.Config.RFC2307Config.GroupMembershipAttributes,
			userQuery,
			o.Config.RFC2307Config.UserNameAttributes)

		// The LDAPInterface knows how to extract group members
		syncer.GroupMemberExtractor = &ldapInterface

		// In order to build the GroupNameMapper, we need to know if the user defined a hard mapping
		// or one based on LDAP group entry attributes
		if syncer.GroupNameMapper == nil {
			if o.Config.RFC2307Config.GroupNameAttributes == nil {
				return errors.New("not enough information to build a group name mapper")
			}
			syncer.GroupNameMapper = NewEntryAttributeGroupNameMapper(o.Config.RFC2307Config.GroupNameAttributes, &ldapInterface)
		}

		// In order to build the groupLister, we need to know about the group sync scope and source:
		syncer.GroupLister = getGroupLister(o.Scope,
			o.Source,
			o.WhitelistContents,
			o.GroupInterface,
			clientConfig.Host,
			&ldapInterface)

	case o.Config.ActiveDirectoryConfig != nil:
		fallthrough
	case o.Config.AugmentedActiveDirectoryConfig != nil:
		fallthrough
	default:
		return fmt.Errorf("invalid schema-specific query template type: %v", o.Config.RFC2307Config)
	}

	// Now we run the Syncer and report any errors
	if o.Confirm {
		syncErrors := syncer.Sync()
		return kerrs.NewAggregate(syncErrors)
	}

	openshiftGroups, errors := syncer.GetResultingGroups()
	list := &kapi.List{}
	for _, item := range openshiftGroups {
		list.Items = append(list.Items, item)
	}
	if err := f.Factory.PrintObject(cmd, list, o.Out); err != nil {
		return err
	}

	return kerrs.NewAggregate(errors)

}

// getGroupLister returns an LDAPGroupLister. The GroupLister is created by taking into account
// both the scope and the source of the search.
//   - Syncing a whitelist of LDAP groups will require a WhitelistLDAPGroupLister
//   - Syncing a whitelist of OpenShift groups will require a LocalGroupLister
//   - Syncing all LDAP groups will require us to use the ldapInterface as the lister
//   - Syncing all OpenShift groups will require a AllLocalGroupLister
func getGroupLister(scope GroupSyncScope,
	source GroupSyncSource,
	whitelist []string,
	client osclient.GroupInterface,
	host string,
	groupLister interfaces.LDAPGroupLister) interfaces.LDAPGroupLister {
	switch scope {
	case GroupSyncScopeWhitelist:
		switch source {
		case GroupSyncSourceLDAP:
			return NewLDAPWhitelistGroupLister(whitelist)
		case GroupSyncSourceOpenShift:
			return NewOpenShiftWhitelistGroupLister(whitelist, client)
		}
	case GroupSyncScopeAll:
		switch source {
		case GroupSyncSourceLDAP:
			return groupLister
		case GroupSyncSourceOpenShift:
			return NewAllOpenShiftGroupLister(host, client)
		}
	}
	return nil
}
