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
	vulnerability := fmt.Sprintf("%s", requestData.Context["Vulnerability"])
	action := fmt.Sprintf("%s", requestData.Context["Action"])
	componentId := fmt.Sprintf("%s", requestData.Context["ComponentId"])
	VulnerabilityId := fmt.Sprintf("%s", requestData.Context["VulnerabilityId"])
	projectIds := fmt.Sprintf("%v", requestData.Context["ProjectIds"])
	projectIdsArr := strings.Split(projectIds, ",")

	// Check if action is in one of the allowed list
	if !contains(vulnActions, action) && action != "Suppress" {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "Invalid action"))
	}

	attachment := responsePost.Attachments()[0]
	attachment.Actions = []*model.PostAction{}

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
						"Vulnerability":   vulnerability,
					},
				},
			},
		)
		responsePost.Message = ":white_check_mark: Action Taken"
	} else {
		responsePost.Message = ""
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
							"Vulnerability":   vulnerability,
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
								"Vulnerability":   vulnerability,
							},
						},
					},
				)
			}
		} else {
			attachment.Color = "#e61220" // red
		}
	}

	if action == "Suppress" {
		attachment.Fields = append(attachment.Fields, &model.SlackAttachmentField{
			Title: "Suppressed By",
			Value: fmt.Sprintf("@%s", user.Username),
			Short: false,
		})
		attachment.Color = "#7d7a7b" // grey
	}
	responsePost.AddProp("attachments", []*model.SlackAttachment{
		attachment,
	})

	// Update DependencyTrack tool
	errorMessages := ""
	analysis := p.ActionToAnalysis(action)
	for _, projectId := range projectIdsArr {
		vulnerability, err := p.fetchVulnerability(VulnerabilityId)
		if err != nil {
			errorMessages += fmt.Sprintf("Could not find vulnerability details. Error: %s\n", err.Error())
			p.API.LogError("Something went wrong while fetching the vulnerability details in the DependencyTrack Tool", "error", err.Error())
		}
		if len(vulnerability.VulnId) > 0 {
			vulnComponentId, err := p.findComponentIdForVulnerability(projectId, vulnerability.Source, vulnerability.VulnId)

			if err != nil {
				errorMessages += fmt.Sprintf("Could not find component details. Error: %s\n", err.Error())
				p.API.LogError("Something went wrong while fetching the component details in the DependencyTrack Tool", "error", err.Error())
			}

			if len(vulnComponentId) > 0 {
				if action == "Suppress" {
					prevAnalysis, err := p.fetchAnalysis(projectId, VulnerabilityId, vulnComponentId)
					if err != nil {
						errorMessages += fmt.Sprintf("Could not find previous analysis while suppressing it. Error: %s\n", err.Error())
						p.API.LogError("Something went wrong while fetching the previous analysis status in the DependencyTrack Tool", "error", err.Error())
					}
					analysis.State = prevAnalysis.State
				}
				err := p.updateAnalysis(projectId, VulnerabilityId, vulnComponentId, analysis, user.Username)
				if err != nil {
					errorMessages += fmt.Sprintf("%s\n", err.Error())
					p.API.LogError("Something went wrong while updating the analysis status in the DependencyTrack Tool", "error", err.Error())
				}
			}
		}
	}

	if len(errorMessages) > 1 {
		message := "Something went wrong while updating the analysis in the DependencyTrack Tool. Please check the logs for more information."
		p.API.LogError(fmt.Sprintf("%s\n%s", message, errorMessages))
		errPost := &model.Post{
			UserId:    p.BotUserID,
			ChannelId: responsePost.ChannelId,
			Message:   message,
			RootId:    responsePost.Id,
		}
		p.API.CreatePost(errPost)
	} else {
		// Update Post if no errors
		p.API.UpdatePost(responsePost)
	}

}

func (p *Plugin) ActionToAnalysis(action string) FindingAnalysis {
	analysis := FindingAnalysis{Suppressed: false}
	switch action {
	case "New":
		analysis.State = "NOT_SET"
	case "Exploitable":
		analysis.State = "EXPLOITABLE"
	case "False Positive":
		analysis.State = "FALSE_POSITIVE"
	case "Not Affected":
		analysis.State = "NOT_AFFECTED"
	case "Suppress":
		analysis.Suppressed = true
	}
	return analysis
}
