package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
	"github.com/pkg/errors"
)

const (
	routeWebhooks            = "/hooks"
	routeAutocomplete        = "/autocomplete"
	subrouteProjects         = "/projects"
	routeUpdateVulnerability = "/status/vulnerability"
)

func (p *Plugin) initializeRouter() {
	p.router = mux.NewRouter()
	autocompleteRouter := p.router.PathPrefix(routeAutocomplete).Subrouter()
	autocompleteRouter.HandleFunc(subrouteProjects, p.autocompleteProjects).Methods("GET")

	p.router.HandleFunc(routeWebhooks+"/{secret}", p.httpHandleWebhook).Methods("POST")
	p.router.HandleFunc(routeUpdateVulnerability, p.httpHandleUpdateVulnerability).Methods("POST")
}

// ServeHTTP allows the plugin to implement the http.Handler interface. Requests destined for the
// /plugins/{id} path will be routed to the plugin.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	p.API.LogDebug("Request received", "URL", r.URL)
	p.router.ServeHTTP(w, r)
}

func (p *Plugin) httpHandleUpdateVulnerability(w http.ResponseWriter, r *http.Request) {
	// Check if user is allowed to perform
	p.ensureAuthorized(w, r)

	userID := r.Header.Get("Mattermost-User-Id")
	requestData := model.PostActionIntegrationRequestFromJson(r.Body)
	if requestData == nil {
		p.API.LogError("Empty request data", "request", r)
		return
	}

	responsePost, err := p.API.GetPost(requestData.PostId)

	if err != nil {
		p.API.LogError("Unable to fetch post Id", err)
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "Post not found"))
	}

	// Check if user is found
	user, err := p.API.GetUser(userID)
	if err != nil {
		p.API.LogError("User not found", err)
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "User not found"))
	}

	// Check if user has permission to access the requested postId, i.e. check if post belongs to same channel Id
	if requestData.ChannelId != responsePost.ChannelId {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "Post not found"))
	}

	vulnActions := []string{"Exploitable", "False Positive", "Not Affected", "New"}

	// Get Context info
	action := fmt.Sprintf("%s", requestData.Context["Action"])
	componentId := fmt.Sprintf("%s", requestData.Context["ComponentId"])
	VulnerabilityId := fmt.Sprintf("%s", requestData.Context["VulnerabilityId"])
	projectIds := fmt.Sprintf("%v", requestData.Context["ProjectIds"])

	// Check if action is in one of the allowed list
	if !contains(vulnActions, action) && action != "Suppress" {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "Invalid action"))
	}

	attachment := responsePost.Attachments()[0]
	attachment.Actions = []*model.PostAction{}
	replyPost := &model.Post{}

	// Reset previous Status, Status Updated By & Suppressed By fields
	newFields := []*model.SlackAttachmentField{}
	if action == "Suppress" {
		for _, field := range attachment.Fields {
			if !strings.Contains(field.Title, "Suppressed") {
				newFields = append(newFields, field)
			}
		}
	} else {
		for _, field := range attachment.Fields {
			if !strings.Contains(field.Title, "Status") && !strings.Contains(field.Title, "Suppressed") {
				newFields = append(newFields, field)
			}
		}
	}
	attachment.Fields = newFields

	// Provide Mark as New Option
	if action != "New" {
		attachment.Actions = append(attachment.Actions,
			&model.PostAction{
				Id:   "markNew",
				Name: "Mark as New",
				Type: model.POST_ACTION_TYPE_BUTTON,
				Integration: &model.PostActionIntegration{
					URL: fmt.Sprintf("/plugins/%s/%s", dtrackPluginId, routeUpdateVulnerability),
					Context: map[string]interface{}{
						"ComponentId":     componentId,
						"VulnerabilityId": VulnerabilityId,
						"ProjectIds":      projectIds,
						"Action":          "New",
					},
				},
			},
		)
	}

	// Update Status
	if contains(vulnActions, action) {
		attachment.Fields = append(attachment.Fields, &model.SlackAttachmentField{
			Title: "Status",
			Value: action,
			Short: true,
		})
		attachment.Fields = append(attachment.Fields, &model.SlackAttachmentField{
			Title: "Status Updated By",
			Value: fmt.Sprintf("@%s", user.Username),
			Short: true,
		})

		// Provide option to Suppress the vulnerability if False Positive/Not affected
		if action == "False Positive" || action == "Not Affected" {
			attachment.Actions = append(attachment.Actions,
				&model.PostAction{
					Id:   "markSuppressed",
					Name: "Suppress",
					Type: model.POST_ACTION_TYPE_BUTTON,
					Integration: &model.PostActionIntegration{
						URL: fmt.Sprintf("/plugins/%s/%s", dtrackPluginId, routeUpdateVulnerability),
						Context: map[string]interface{}{
							"ComponentId":     componentId,
							"VulnerabilityId": VulnerabilityId,
							"ProjectIds":      projectIds,
							"Action":          "Suppress",
						},
					},
				},
			)
			attachment.Color = "#8eb8e8" // blue
		} else if action == "New" {

			// Reset and show the 3 options again
			attachment.Color = "#FF8000" // red
			attachment.Actions = []*model.PostAction{}
			newActions := []string{"Exploitable", "False Positive", "Not Affected"}

			for _, act := range newActions {
				actionId := strings.ReplaceAll(act, " ", "")
				attachment.Actions = append(attachment.Actions,
					&model.PostAction{
						Id:   "mark" + actionId,
						Name: "Mark as " + act,
						Type: model.POST_ACTION_TYPE_BUTTON,
						Integration: &model.PostActionIntegration{
							URL: fmt.Sprintf("/plugins/%s/%s", dtrackPluginId, routeUpdateVulnerability),
							Context: map[string]interface{}{
								"ComponentId":     componentId,
								"VulnerabilityId": VulnerabilityId,
								"ProjectIds":      projectIds,
								"Action":          act,
							},
						},
					},
				)
			}
		} else {
			attachment.Color = "#e61220" // red
		}
		replyPost = &model.Post{
			UserId:    p.BotUserID,
			ChannelId: requestData.ChannelId,
			RootId:    requestData.PostId,
			Message:   fmt.Sprintf("@%s updated the status as %s", user.Username, action),
		}
	}

	if action == "Suppress" {
		attachment.Fields = append(attachment.Fields, &model.SlackAttachmentField{
			Title: "Suppressed By",
			Value: fmt.Sprintf("@%s", user.Username),
			Short: false,
		})
		attachment.Color = "#7d7a7b" // grey
		replyPost = &model.Post{
			UserId:    p.BotUserID,
			ChannelId: requestData.ChannelId,
			RootId:    requestData.PostId,
			Message:   fmt.Sprintf("@%s suppressed this vulnerability", user.Username),
		}
	}

	responsePost.AddProp("attachments", []*model.SlackAttachment{
		attachment,
	})

	p.API.UpdatePost(responsePost)
	if replyPost.Message != "" {
		p.API.CreatePost(replyPost)
	}
}
