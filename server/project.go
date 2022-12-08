package main

import (
	"fmt"
	"net/http"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/pkg/errors"
)

const (
	projectReferenceKey = "projectReference"
)

func (p *Plugin) StoreProjectReference(projectId string) error {
	b := []byte(projectId)

	if appErr := p.API.KVSet(projectReferenceKey, b); appErr != nil {
		return errors.Wrap(appErr, "could not store project reference in KV store")
	}

	return nil
}

func (p *Plugin) GetProjectReference() (string, error) {
	value, appErr := p.API.KVGet(projectReferenceKey)
	if appErr != nil {
		return "", errors.Wrap(appErr, "could not get project reference from KVStore")
	}

	return string(value), nil
}

func (p *Plugin) DeleteProjectReference() error {
	appErr := p.API.KVDelete(projectReferenceKey)
	if appErr != nil {
		return errors.Wrap(appErr, "could not delete project reference from KVStore")
	}
	return nil
}

func (p *Plugin) executeProjectCommand(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {
	if len(split) < 1 {
		msg := "Invalid project command. Available commands are 'reference', 'sync'."
		return p.sendEphemeralResponse(args, msg), nil
	}

	command := split[0]

	switch {
	case command == "reference":
		return p.handleProjectReference(args, split)
	case command == "sync":
		return p.handleProjectSync(args, split)
	default:
		msg := "Unknown subcommand for project command. Available commands are 'reference' and 'sync'."
		return p.sendEphemeralResponse(args, msg), nil
	}
}

func (p *Plugin) handleProjectReference(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {

	if len(split) < 2 || split[1] == "" {
		msg := "Incomplete arguments provided for the `/project reference` command. Available options: add, list or delete"
		return p.sendEphemeralResponse(args, msg), nil
	}
	command := split[1]
	switch command {
	case "delete":
		err := p.DeleteProjectReference()
		if err != nil {
			msg := fmt.Sprintf("Something went wrong while deleting the project reference. Error: %s\n", err.Error())
			return p.sendEphemeralResponse(args, msg), nil
		}
		msg := "Reference project removed."
		return p.sendEphemeralResponse(args, msg), nil
	case "add":
		if len(split) < 4 || split[2] != "--project" || split[3] == "" {
			msg := "Incomplete arguments provided for the `/project reference add` command. Please provide the identifier of the project.\nExample: `/dtrack project reference add --project project_id`"
			return p.sendEphemeralResponse(args, msg), nil
		}

		// Check if project is found and is active
		projectId := split[3]
		project, err := p.fetchProject(projectId)
		if err != nil || !project.Active {
			msg := fmt.Sprintf("Project not found or is inactive. Please recheck if the project_id %s is present and is active", projectId)
			return p.sendEphemeralResponse(args, msg), nil
		}

		err = p.StoreProjectReference(projectId)
		if err != nil {
			msg := fmt.Sprintf("Something went wrong while deleting the project reference. Error: %s\n", err.Error())
			return p.sendEphemeralResponse(args, msg), nil
		}

		msg := "Reference project set."
		return p.sendEphemeralResponse(args, msg), nil
	case "list":
		id, err := p.GetProjectReference()
		if err != nil {
			msg := fmt.Sprintf("Something went wrong while getting the project reference. Error: %s\n", err.Error())
			return p.sendEphemeralResponse(args, msg), nil
		}
		// Get Project Details
		referenceProject, err := p.fetchProject(id)
		if err != nil {
			msg := fmt.Sprintf("Reference Project Id not found or is inactive. Please recheck if the reference project id %s is present.", id)
			return p.sendEphemeralResponse(args, msg), nil
		}
		msg := fmt.Sprintf("Reference Project: %s", referenceProject.ToMarkdown(p.getConfiguration().DependencyTrackUrl))
		if id == "" {
			msg = "No Reference Project saved"
		}
		return p.sendEphemeralResponse(args, msg), nil
	default:
		msg := "Invalid option. Available options: add, list or delete"
		return p.sendEphemeralResponse(args, msg), nil
	}
}

func (p *Plugin) handleProjectSync(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {
	// Expected cmd: /project sync --reference-project project1_id --target-project project2_id
	if len(split) < 5 || split[1] != "--reference-project" || split[2] == "" || split[3] != "--target-project" || split[4] == "" {
		msg := "Incomplete arguments provided for the `/dtrack project sync` command. Please provide the identifier of the reference project & target project.\nExample: `/dtrack project sync --reference-project project1-id --target-project project2-id`"
		return p.sendEphemeralResponse(args, msg), nil
	}

	referenceProjectId := split[2]
	targetProjectId := split[4]

	// Check if config is valid
	if err := p.getConfiguration().IsValid(); err != nil {
		msg := "DependencyTrack Plugin configuration is incomplete/incorrect. Please ask a system administrator to check the plugin configuration before running this command."
		return p.sendEphemeralResponse(args, msg), nil
	}

	// Check if Reference Projects exists
	referenceProject, err := p.fetchProject(referenceProjectId)
	if err != nil || !referenceProject.Active {
		msg := fmt.Sprintf("Reference Project Id not found or is inactive. Please recheck if the reference projec id %s is present and is active.", referenceProjectId)
		return p.sendEphemeralResponse(args, msg), nil
	}

	// Get User
	user, _ := p.API.GetUser(args.UserId)

	// Check if Target Projects exists
	targetProject, err := p.fetchProject(targetProjectId)
	if err != nil || !targetProject.Active {
		msg := fmt.Sprintf("Target Project Id not found or is inactive. Please recheck if the target project id %s is present and is active", targetProjectId)
		return p.sendEphemeralResponse(args, msg), nil
	}

	// Fetch open findings from target Project
	findings, err := p.fetchFindings(targetProjectId)
	if err != nil {
		msg := fmt.Sprintf("Something went wrong while performing the project sync command. Error: %s\n", err.Error())
		return p.sendEphemeralResponse(args, msg), nil
	}

	errors := ""

	// Update analysis of the open findings in the target Project
	for _, finding := range findings {
		vulnComponentId, err := p.findComponentIdForVulnerability(referenceProjectId, finding.Vulnerability.Source, finding.Vulnerability.VulnId)

		if err != nil {
			errors += fmt.Sprintf("Could not find component details. Error: %s\n", err.Error())
		}

		analysis, err := p.fetchAnalysis(referenceProjectId, finding.Vulnerability.Id, vulnComponentId)
		if err != nil {
			errors += fmt.Sprintf("- %s\n", err.Error())
		}
		if len(analysis.State) > 0 {
			p.updateAnalysis(targetProject.Id, finding.Vulnerability.Id, finding.Component.Id, analysis, user.Username)
		}
	}

	if len(findings) > 0 {
		msg := fmt.Sprintf("Findings in the project %s %s has been successfully synced with %s %s\n", targetProject.Name, targetProject.Version, referenceProject.Name, referenceProject.Version)
		if len(errors) > 0 {
			errorMsg := "Few errors were found while syncing the findings. Please check the logs for more information.\n"
			msg += errorMsg
			p.API.LogError(errorMsg + errors)
		}
		return p.sendEphemeralResponse(args, msg), nil
	}

	msg := fmt.Sprintf("There were no open findings found in the target project %s. No sync actions were performed.", targetProject.Name)
	return p.sendEphemeralResponse(args, msg), nil
}

func (p *Plugin) autocompleteProjects(w http.ResponseWriter, r *http.Request) {
	// Check if user is allowed to perform
	if !p.ensureAuthorized(w, r) {
		return
	}

	// Fetch Projects
	projects, err := p.fetchProjects()
	if err != nil {
		p.respondAndLogErr(w, http.StatusInternalServerError, err)
		return
	}

	out := []model.AutocompleteListItem{
		{
			HelpText: "Manually type the project identifier",
			Item:     "<project_id>",
		},
	}
	if len(projects) == 0 {
		p.respondJSON(w, out)
		return
	}

	for _, project := range projects {
		out = append(out, model.AutocompleteListItem{
			HelpText: fmt.Sprintf("%s %s", project.Name, project.Version),
			Item:     project.Id,
		})
	}
	p.respondJSON(w, out)
}
