package main

import (
	"fmt"
	"strings"

	"github.com/mattermost/mattermost-plugin-api/experimental/command"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
	"github.com/pkg/errors"
)

const (
	cmdDependencyTrack = "dtrack"
	cmdKeyHelp         = "help"
	cmdProjectKey      = "project"
	cmdPermissionsKey  = "permissions"
	cmdSubscribeKey    = "subscriptions"
	cmdError           = "Command Error"
)

// type CommandHandlerFunc func(p *Plugin, c *plugin.Context, header *model.CommandArgs, args ...string) *model.CommandResponse

const helpText = "###### Mattermost DependencyTrack Plugin\n" +
	"* `/dtrack project <command>` - Available subcommands: reference, sync.\n" +
	"* `/dtrack subscriptions <command>` - Available subcommands: list, add, delete. Subscribe the current channel to receive DependencyTrack notifications. Once a channel is subscribed, the service will listen to any Webhook Events from the DependencyTrack tool and publish it on the subscribed channel\n" +
	"* `/dtrack permissions <command>` - Available subcommands: list, add, delete. Access Control users who can run DependencyTrack slash commands.\n" +
	""

func (p *Plugin) getCommand(config *configuration) (*model.Command, error) {
	iconData, err := command.GetIconData(p.API, "assets/icon.svg")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get icon data")
	}

	return &model.Command{
		Trigger:              cmdDependencyTrack,
		AutoComplete:         true,
		AutoCompleteDesc:     "Available commands: help, permissions, project, subscriptions",
		AutoCompleteHint:     "[command]",
		AutocompleteData:     getAutocompleteData(config),
		AutocompleteIconData: iconData,
	}, nil
}

func (p *Plugin) ExecuteCommand(c *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	split := strings.Fields(args.Command)
	command := ""

	if len(split) > 1 {
		command = split[1]
	}

	if command == cmdKeyHelp {
		return p.sendEphemeralResponse(args, helpText), nil
	}

	isAllowed, err := p.IsAuthorized(args.UserId)
	msg := ""
	if err != nil {
		msg = fmt.Sprintf("error occurred while authorizing the command: %v", err)
		return p.sendEphemeralResponse(args, msg), nil
	}
	if !isAllowed {
		msg := fmt.Sprintf("%s commands can only be executed by a system administrator or a list of users whitelisted. Please ask your system administrator to run the command, eg: `/%s permissions add @user1` to whitelist a specific user.", cmdDependencyTrack, cmdDependencyTrack)
		return p.sendEphemeralResponse(args, msg), nil
	}

	switch command {
	case cmdProjectKey:
		return p.executeProjectCommand(args, split[2:])
	case cmdSubscribeKey:
		return p.executeSubscriptions(args, split[2:])
	case cmdPermissionsKey:
		return p.executePermissions(args, split[2:])
	default:
		return p.sendEphemeralResponse(args, helpText), nil
	}
}

func getAutocompleteData(config *configuration) *model.AutocompleteData {
	dtrack := model.NewAutocompleteData(cmdDependencyTrack, "[command]", "Available commands: help, permissions, project, subscriptions")

	help := model.NewAutocompleteData(cmdKeyHelp, "", "Display Slash Command help text")
	dtrack.AddCommand(help)

	subscriptions := model.NewAutocompleteData(cmdSubscribeKey, "[command]", "Available commands: list, add, delete")

	subscribeAdd := model.NewAutocompleteData("add", "", "When executed, the current channel will be subscribed to receive notifications. This command will print the URL which should be configured as Outbound Webhooks URL in the DependencyTrack Tool. Once subscribed, the service will listen to any Webhook Events from the DependencyTrack tool and publish it on the subscribed channel.")
	subscriptions.AddCommand(subscribeAdd)

	subscribeDelete := model.NewAutocompleteData("delete", "[index]", "The specified channel will stop receiving any notifications for any events from the DependencyTrack tool. You can run the command '/dtrack subscriptions list' to get the index position.")
	subscriptions.AddCommand(subscribeDelete)

	subscribeList := model.NewAutocompleteData("list", "", "Lists all the channels which has been set to receive DependencyTrack notifications")
	subscriptions.AddCommand(subscribeList)

	dtrack.AddCommand(subscriptions)

	permissions := model.NewAutocompleteData(cmdPermissionsKey, "[command]", "Available commands: list, allow, remove")

	permissionAdd := model.NewAutocompleteData("add", "@username", "Whitelist the user to run the DependencyTrack slash commands. "+permissionsNote)
	permissions.AddCommand(permissionAdd)

	permissionsRemove := model.NewAutocompleteData("delete", "@username", "Remove the user from running the DependencyTrack slash commands. "+permissionsNote)
	permissions.AddCommand(permissionsRemove)

	permissionsList := model.NewAutocompleteData("list", "", "List all the users who are allowed to run the DependencyTrack slash commands. "+permissionsNote)
	permissions.AddCommand(permissionsList)

	dtrack.AddCommand(permissions)

	project := model.NewAutocompleteData(cmdProjectKey, "[command]", "Available commands: reference, sync")

	projectReference := model.NewAutocompleteData("reference", "", "This option is provided to consider the analysis for vulnerabilities for one project in reference to all the other projects.")

	projectReferenceAdd := model.NewAutocompleteData("add", "<project>", "Enter the Project ID")
	projectReferenceAdd.AddNamedDynamicListArgument("project", "The Project Identifier", routeAutocomplete+subrouteProjects, true)
	projectReference.AddCommand(projectReferenceAdd)

	projectReferenceList := model.NewAutocompleteData("list", "", "List the reference project set")
	projectReference.AddCommand(projectReferenceList)

	projectReferenceDelete := model.NewAutocompleteData("delete", "", "Select this option to delete the previously set Reference Project ID")
	projectReference.AddCommand(projectReferenceDelete)

	project.AddCommand(projectReference)

	projectSync := model.NewAutocompleteData("sync", "--reference-project project1 --target-project project2", "This command will check the status of all alerts from the reference_project_id and update the same to the target_project_id")
	projectSync.AddNamedDynamicListArgument("reference-project", "Reference Project Identifier", routeAutocomplete+subrouteProjects, true)
	projectSync.AddNamedDynamicListArgument("target-project", "Target Project Identifier", routeAutocomplete+subrouteProjects, true)

	project.AddCommand(projectSync)

	dtrack.AddCommand(project)

	return dtrack
}
