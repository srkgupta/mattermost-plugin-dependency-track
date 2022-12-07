package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/pkg/errors"
)

// Plugin utils
func (p *Plugin) sendEphemeralPost(args *model.CommandArgs, message string, attachments []*model.SlackAttachment) *model.Post {
	post := &model.Post{
		UserId:    p.BotUserID,
		ChannelId: args.ChannelId,
		Message:   message,
	}

	if attachments != nil {
		post.AddProp("attachments", attachments)
	}

	return p.API.SendEphemeralPost(
		args.UserId,
		post,
	)
}

// Wrapper of p.sendEphemeralPost() to one-line the return statements in all executeCommand functions
func (p *Plugin) sendEphemeralResponse(args *model.CommandArgs, message string) *model.CommandResponse {
	p.sendEphemeralPost(args, message, nil)
	return &model.CommandResponse{}
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func parseTime(input string) string {
	if len(input) > 5 {
		layout := "Mon Jan 02 2006 3:04 PM"
		t, _ := time.Parse(time.RFC3339, input)
		output := t.Format(layout)
		if output == "Mon Jan 01 0001 12:00 AM" {
			// If the input is not in the RFC3339 format, return input as is
			return input
		}
		return output
	}
	return "-"
}

func (p *Plugin) getWebhookURL() string {
	siteURL := *p.API.GetConfig().ServiceSettings.SiteURL
	siteURL = strings.TrimRight(siteURL, "/")
	webhookSecret := p.getConfiguration().WebhooksSecret
	return fmt.Sprintf("%s/plugins/%s%s/%s", siteURL, dtrackPluginId, routeWebhooks, webhookSecret)
}

func (p *Plugin) ensureAuthorized(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-Id")
	isAllowed, err := p.IsAuthorized(userID)
	if err != nil {
		p.API.LogError("Error while checking for isAuthorized in autocompleting projects", err)
		http.NotFound(w, r)
		return
	}
	if !isAllowed {
		http.NotFound(w, r)
		return
	}
}

func (p *Plugin) respondAndLogErr(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
	p.API.LogError(err.Error())
}

func (p *Plugin) respondJSON(w http.ResponseWriter, obj interface{}) {
	data, err := json.Marshal(obj)
	if err != nil {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "failed to marshal response"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(data)
	if err != nil {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "failed to write response"))
		return
	}

	w.WriteHeader(http.StatusOK)
}
