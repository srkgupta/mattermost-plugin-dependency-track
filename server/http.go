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
		return
	}

	// Check if user is found
	user, err := p.API.GetUser(userID)
	if err != nil {
		p.API.LogError("User not found", err)
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "User not found"))
		return
	}

	// Check if user has permission to access the requested postId, i.e. check if post belongs to same channel Id
	if requestData.ChannelId != responsePost.ChannelId {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "Post not found"))
		return
	}

	vulnActions := []string{"Exploitable", "False Positive", "Not Affected", "New"}

	// Get Context info
	vulnerability := fmt.Sprintf("%s", requestData.Context["Vulnerability"])
	action := fmt.Sprintf("%s", requestData.Context["Action"])
	componentId := fmt.Sprintf("%s", requestData.Context["ComponentId"])
	vulnerabilityId := fmt.Sprintf("%s", requestData.Context["VulnerabilityId"])
	projectIds := fmt.Sprintf("%v", requestData.Context["ProjectIds"])
	projectIdsArr := strings.Split(projectIds, ",")

	// Check if action is in one of the allowed list
	if !contains(vulnActions, action) && action != "Suppress" {
		p.respondAndLogErr(w, http.StatusInternalServerError, errors.WithMessage(err, "Invalid action"))
		return
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

	responsePost.Message = ""

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
						"VulnerabilityId": vulnerabilityId,
						"ProjectIds":      projectIds,
						"Action":          "New",
						"Vulnerability":   vulnerability,
					},
				},
			},
		)
		responsePost.Message = ":white_check_mark: Action Taken"
	}

	// Update Status
	switch action {
	case "False Positive", "Not Affected":
		// Provide option to Suppress the vulnerability if False Positive/Not affected
		attachment.Actions = append(attachment.Actions,
			&model.PostAction{
				Id:   "markSuppressed",
				Name: "Suppress",
				Type: model.POST_ACTION_TYPE_BUTTON,
				Integration: &model.PostActionIntegration{
					URL: fmt.Sprintf("/plugins/%s/%s", dtrackPluginId, routeUpdateVulnerability),
					Context: map[string]interface{}{
						"ComponentId":     componentId,
						"VulnerabilityId": vulnerabilityId,
						"ProjectIds":      projectIds,
						"Action":          "Suppress",
						"Vulnerability":   vulnerability,
					},
				},
			},
		)
		attachment.Color = "#8eb8e8" // blue

	case "New":
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
							"VulnerabilityId": vulnerabilityId,
							"ProjectIds":      projectIds,
							"Action":          act,
							"Vulnerability":   vulnerability,
						},
					},
				},
			)
		}

	case "Suppress":
		attachment.Fields = append(attachment.Fields, &model.SlackAttachmentField{
			Title: "Suppressed By",
			Value: fmt.Sprintf("@%s", user.Username),
			Short: false,
		})
		attachment.Color = "#7d7a7b" // grey

	default:
		attachment.Color = "#e61220" // red
	}

	responsePost.AddProp("attachments", []*model.SlackAttachment{
		attachment,
	})

	// Update DependencyTrack tool
	errorMessages := ""
	analysis := p.ActionToAnalysis(action)
	for _, projectId := range projectIdsArr {
		vulnerability, err := p.fetchVulnerability(vulnerabilityId)
		if err != nil || len(vulnerability.VulnId) == 0 {
			errorMessage := fmt.Sprintf("- Could not find vulnerability details for vulnerability Id: %s", vulnerabilityId)
			p.API.LogError(errorMessage, "error", err.Error())
			errorMessages += errorMessage
			continue
		}

		vulnComponentId, err := p.findComponentIdForVulnerability(projectId, vulnerability.Source, vulnerability.VulnId)

		if err != nil || len(vulnComponentId) == 0 {
			errorMessage := fmt.Sprintf("- Could not find component details for projectId: %s, source: %s, vulnId: %s\n", projectId, vulnerability.Source, vulnerability.VulnId)
			p.API.LogError(errorMessage, "error", err.Error())
			errorMessages += errorMessage
			continue
		}

		if action == "Suppress" {
			prevAnalysis, err := p.fetchAnalysis(projectId, vulnerabilityId, vulnComponentId)
			if err != nil {
				errorMessage := fmt.Sprintf("- Could not find previous analysis while suppressing it for projectId: %s, vulnerabilityId: %s, componentId: %s\n", projectId, vulnerabilityId, vulnComponentId)
				p.API.LogError(errorMessage, "error", err.Error())
				errorMessages += errorMessage
				continue
			}
			analysis.State = prevAnalysis.State
		}

		err = p.updateAnalysis(projectId, vulnerabilityId, vulnComponentId, analysis, user.Username)

		if err != nil {
			errorMessage := fmt.Sprintf("- Error while updating the analysis status for projectId: %s, vulnerabilityId: %s, componentId: %s, analysis: %s", projectId, vulnerabilityId, vulnComponentId, analysis)
			p.API.LogError(errorMessage, "error", err.Error())
			errorMessages += errorMessage
			continue
		}
	}

	if len(errorMessages) > 1 {
		message := fmt.Sprintf("Errors encountered while updating the analysis in the DependencyTrack Tool:\n %s", errorMessages)
		errPost := &model.Post{
			UserId:    p.BotUserID,
			ChannelId: responsePost.ChannelId,
			Message:   message,
			RootId:    responsePost.Id,
		}
		p.API.CreatePost(errPost)
		return
	}

	// Update Post if no errors
	p.API.UpdatePost(responsePost)

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
