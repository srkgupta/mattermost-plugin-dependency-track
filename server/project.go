package main

import (
	"fmt"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/pkg/errors"
)

const (
	ProjectReferenceKey = "projectReference"
)

func (p *Plugin) StoreProjectReference(projectId string) error {
	b := []byte(projectId)

	if appErr := p.API.KVSet(ProjectReferenceKey, b); appErr != nil {
		return errors.Wrap(appErr, "could not store project reference in KV store")
	}

	return nil
}

func (p *Plugin) GetProjectReference() (string, error) {
	value, appErr := p.API.KVGet(ProjectReferenceKey)
	if appErr != nil {
		return "", errors.Wrap(appErr, "could not get project reference from KVStore")
	}

	return string(value), nil
}

func (p *Plugin) DeleteProjectReference() error {
	appErr := p.API.KVDelete(ProjectReferenceKey)
	if appErr != nil {
		return errors.Wrap(appErr, "could not delete project reference from KVStore")
	}
	return nil
}

func (p *Plugin) executeProjectCommand(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {
	if 0 >= len(split) {
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
	msg := ""
	if split[1] == "delete" {
		err := p.DeleteProjectReference()
		if err != nil {
			msg := fmt.Sprintf("Something went wrong while deleting the project reference. Error: %s\n", err.Error())
			return p.sendEphemeralResponse(args, msg), nil
		}
		msg = "Reference project removed."
	} else if split[1] == "add" {
		if len(split) < 3 || split[2] == "" {
			msg := "Incomplete arguments provided for the `/project reference add` command. Please provide the project_id"
			return p.sendEphemeralResponse(args, msg), nil

		}
		err := p.StoreProjectReference(split[2])
		if err != nil {
			msg := fmt.Sprintf("Something went wrong while deleting the project reference. Error: %s\n", err.Error())
			return p.sendEphemeralResponse(args, msg), nil
		}
		msg = "Reference project set."
	} else if split[1] == "list" {
		id, err := p.GetProjectReference()
		if err != nil {
			msg := fmt.Sprintf("Something went wrong while getting the project reference. Error: %s\n", err.Error())
			return p.sendEphemeralResponse(args, msg), nil
		}
		msg = fmt.Sprintf("Reference Project: %s", id)
		if id == "" {
			msg = "No Reference Project saved"
		}
	}
	return p.sendEphemeralResponse(args, msg), nil
}

func (p *Plugin) handleProjectSync(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {
	if len(split) < 3 || split[1] == "" || split[2] == "" {
		msg := "Incomplete arguments provided for the `/project sync` command. Please provide reference_project_id and target_project_id"
		return p.sendEphemeralResponse(args, msg), nil
	}
	return p.sendEphemeralResponse(args, "Project will be synced shortly."), nil
}
