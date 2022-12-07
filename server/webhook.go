package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost-server/v5/model"
)

const (
	nvd                     = "NVD"
	nvdSite                 = "https://nvd.nist.gov/vuln/detail/%s"
	npm                     = "NPM"
	npmSite                 = "https://github.com/advisories/%s"
	vulndb                  = "VULNDB"
	vulndbSite              = "https://vuldb.com/?id.%s"
	actionSuppress          = "Suppress"
	actionFalsePositive     = "False Positive"
	actionNotAffected       = "Not Affected"
	actionNew               = "New"
	actionExploitable       = "Exploitable"
	actionSuppressed        = "Suppressed"
	newVulnerability        = "NEW_VULNERABILITY"
	analysisNotSet          = "NOT_SET"
	analysisNotAffected     = "NOT_AFFECTED"
	analysisExploitable     = "EXPLOITABLE"
	analysisFalsePositive   = "FALSE_POSITIVE"
	newVulnerableDependency = "NEW_VULNERABLE_DEPENDENCY"
	bomConsumed             = "BOM_CONSUMED"
	bomProcessed            = "BOM_PROCESSED"
	orangeColor             = "#FF8000"
	lightBlueColor          = "#ADD8E6"
	redColor                = "#FF0000"
	darkRedColor            = "#800000"
	greenColor              = "#50F100"
	greyColor               = "#7d7a7b"
)

// WebhookInfo from the webhook
type WebhookInfo struct {
	Notification       Notification `json:"notification"`
	DependencyTrackUrl string       `json:"dependency_track_url"`
}

func (vuln *Vulnerability) ToUrl() string {
	url := ""
	switch vuln.Source {
	case nvd:
		url = fmt.Sprintf(nvdSite, vuln.VulnId)
	case npm:
		url = fmt.Sprintf(npmSite, vuln.VulnId)
	case vulndb:
		url = fmt.Sprintf(vulndbSite, vuln.VulnId)
	}
	return url
}

func (project *Project) ToMarkdown(dtUrl string) string {
	return fmt.Sprintf("[%s %s](%s/projects/%s)", project.Name, project.Version, dtUrl, project.Id)
}

func (vuln *Vulnerability) ToMarkdown() string {
	return fmt.Sprintf("[%s](%s)", vuln.VulnId, vuln.ToUrl())
}

func (vuln *Vulnerability) ToColor() string {
	color := greenColor

	switch strings.ToUpper(vuln.Severity) {
	case "LOW":
		color = lightBlueColor
	case "MEDIUM":
		color = orangeColor
	case "HIGH":
		color = redColor
	case "CRITICAL":
		color = darkRedColor
	}
	return color
}

// ToPost converts the WebhookInfo into a Post
func (wi *WebhookInfo) ToPost() *model.Post {
	message := ""
	attachment := &model.SlackAttachment{
		Title: wi.Notification.Title,
		Text:  wi.Notification.Content,
		Color: greenColor,
	}

	fields := []*model.SlackAttachmentField{}

	switch strings.ToUpper(wi.Notification.Group) {
	case newVulnerability:
		fields = append(fields, &model.SlackAttachmentField{
			Title: "VulnID",
			Value: wi.Notification.Subject.Vulnerability.ToMarkdown(),
			Short: true,
		})
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Severity",
			Value: wi.Notification.Subject.Vulnerability.Severity,
			Short: true,
		})
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Component",
			Value: wi.Notification.Subject.Component.PackageUrl,
			Short: true,
		})
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Source",
			Value: wi.Notification.Subject.Vulnerability.Source,
			Short: true,
		})

		affectedProjects := ""

		for _, project := range wi.Notification.Subject.Projects {
			affectedProjects += fmt.Sprintf("%s\n", project.ToMarkdown(wi.DependencyTrackUrl))
		}

		fields = append(fields, &model.SlackAttachmentField{
			Title: "Affected Projects",
			Value: affectedProjects,
			Short: false,
		})
		attachment.Color = wi.Notification.Subject.Vulnerability.ToColor()
		projectIds := make([]string, len(wi.Notification.Subject.Projects))

		for i, project := range wi.Notification.Subject.Projects {
			projectIds[i] = project.Id
		}

		attachment.Actions = []*model.PostAction{}
		vulnActions := []string{actionExploitable, actionFalsePositive, actionNotAffected}

		for _, action := range vulnActions {
			actionId := strings.ReplaceAll(action, " ", "")
			attachment.Actions = append(attachment.Actions,
				&model.PostAction{
					Id:   "mark" + actionId,
					Name: "Mark as " + action,
					Type: model.POST_ACTION_TYPE_BUTTON,
					Integration: &model.PostActionIntegration{
						URL: fmt.Sprintf("/plugins/%s/%s", dtrackPluginId, routeUpdateVulnerability),
						Context: map[string]interface{}{
							"ComponentId":     wi.Notification.Subject.Component.Id,
							"VulnerabilityId": wi.Notification.Subject.Vulnerability.Id,
							"Vulnerability":   wi.Notification.Subject.Vulnerability.VulnId,
							"ProjectIds":      strings.Join(projectIds, ","),
							"Action":          action,
						},
					},
				},
			)
		}

	case bomConsumed, bomProcessed:
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Project",
			Value: wi.Notification.Subject.Project.ToMarkdown(wi.DependencyTrackUrl),
			Short: true,
		})
		if wi.Notification.Group == bomConsumed {
			attachment.Color = orangeColor
		}

	case newVulnerableDependency:
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Component",
			Value: wi.Notification.Subject.Component.PackageUrl,
			Short: false,
		})

		fields = append(fields, &model.SlackAttachmentField{
			Title: "Project",
			Value: wi.Notification.Subject.Project.ToMarkdown(wi.DependencyTrackUrl),
			Short: false,
		})

		vulns := "| Vuln Id | Severity | CVSS Score | Vuln Type | Source |\n |--- | --- | --- | --- | ---|\n"
		for _, vuln := range wi.Notification.Subject.Vulnerabilities {
			vulns += fmt.Sprintf("| %s | %s | %.1f | %s | %s | \n", vuln.ToMarkdown(), vuln.Severity, vuln.Cvss, vuln.Cwe.Name, vuln.Source)
		}
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Vulnerabilities",
			Value: vulns,
			Short: false,
		})

		attachment.Color = redColor
	}

	attachment.Fields = fields
	attachment.Fallback = attachment.Title
	post := model.Post{
		Message: message,
	}

	post.AddProp("attachments", []*model.SlackAttachment{
		attachment,
	})

	return &post
}

func (wi *WebhookInfo) vulnPost(vuln Vulnerability) *model.Post {
	message := ""
	projectIds := make([]string, 1)
	projectIds[0] = wi.Notification.Subject.Project.Id
	vulnAttachment := &model.SlackAttachment{
		Title: vuln.ToMarkdown(),
		Text:  vuln.Description,
		Color: vuln.ToColor(),
	}
	vulnFields := []*model.SlackAttachmentField{}
	vulnFields = append(vulnFields, &model.SlackAttachmentField{
		Title: "Severity",
		Value: vuln.Severity,
		Short: true,
	})
	vulnFields = append(vulnFields, &model.SlackAttachmentField{
		Title: "Source",
		Value: vuln.Source,
		Short: true,
	})
	vulnFields = append(vulnFields, &model.SlackAttachmentField{
		Title: "CVSS Score",
		Value: fmt.Sprintf("%.1f", vuln.Cvss),
		Short: true,
	})
	if vuln.Cwe.Name != "" {
		vulnFields = append(vulnFields, &model.SlackAttachmentField{
			Title: "Vuln Type",
			Value: vuln.Cwe.Name,
			Short: true,
		})
	}
	vulnAttachment.Fields = vulnFields
	vulnAttachment.Actions = []*model.PostAction{}
	vulnActions := []string{actionExploitable, actionFalsePositive, actionNotAffected}

	for _, action := range vulnActions {
		actionId := strings.ReplaceAll(action, " ", "")
		vulnAttachment.Actions = append(vulnAttachment.Actions,
			&model.PostAction{
				Id:   "mark" + actionId,
				Name: "Mark as " + action,
				Type: model.POST_ACTION_TYPE_BUTTON,
				Integration: &model.PostActionIntegration{
					URL: fmt.Sprintf("/plugins/%s/%s", dtrackPluginId, routeUpdateVulnerability),
					Context: map[string]interface{}{
						"ComponentId":     wi.Notification.Subject.Component.Id,
						"VulnerabilityId": vuln.Id,
						"ProjectIds":      strings.Join(projectIds, ","),
						"Action":          action,
						"Vulnerability":   vuln.VulnId,
					},
				},
			},
		)
	}

	post := model.Post{
		Message: message,
	}

	post.AddProp("attachments", []*model.SlackAttachment{
		vulnAttachment,
	})

	return &post
}

func (p *Plugin) httpHandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Checking secret
	vars := mux.Vars(r)
	if vars["secret"] != p.getConfiguration().WebhooksSecret {
		http.NotFound(w, r)
		return
	}

	wi := new(WebhookInfo)
	wi.DependencyTrackUrl = p.getConfiguration().DependencyTrackUrl

	if err := json.NewDecoder(r.Body).Decode(&wi); err != nil {
		p.API.LogError("Unable to decode JSON for received webhook.", "Error", err.Error())
		return
	}

	referenceProject, err := p.GetProjectReference()
	if err != nil {
		p.API.LogError("Unable to get project reference", "err", err)
	}

	// Check status of vulnerability with reference project. If an analysis was found, update the status of affected Projects accordingly
	if len(referenceProject) > 0 && wi.Notification.Group == newVulnerability {

		//Find Component Id for reference Project and vuln id
		componentId, err := p.findComponentIdForVulnerability(referenceProject, wi.Notification.Subject.Vulnerability.Source, wi.Notification.Subject.Vulnerability.VulnId)

		if err != nil {
			p.API.LogError("Unable to find component Id for reference project", "err", err)
		}
		if len(componentId) > 0 {
			analysis, err := p.fetchAnalysis(referenceProject, wi.Notification.Subject.Vulnerability.Id, componentId)
			if err != nil {
				p.API.LogDebug("Unable to fetch Analysis for the default project", "err", err.Error())
			}

			if len(analysis.State) > 0 && analysis.State != analysisNotSet {

				// Update the status of the finding accordingly and suppress if previously suppressed.
				for _, project := range wi.Notification.Subject.Projects {
					if project.Id != referenceProject {
						vulnComponentId, err := p.findComponentIdForVulnerability(project.Id, wi.Notification.Subject.Vulnerability.Source, wi.Notification.Subject.Vulnerability.VulnId)

						if err != nil {
							p.API.LogError("Unable to find component Id while updating the status of the finding", "err", err)
						}

						if len(vulnComponentId) > 0 {
							p.updateAnalysis(project.Id, wi.Notification.Subject.Vulnerability.Id, vulnComponentId, analysis, "dependencytrack")
						}
					}
				}
				return
			}
		}
	}

	allSubs, err := p.GetSubscriptions()
	if err != nil {
		p.API.LogError("Unable to get subscriptions", "err", err)
		return
	}
	postWithoutChannel := wi.ToPost()
	postWithoutChannel.UserId = p.BotUserID

	for _, sub := range allSubs {
		post := postWithoutChannel.Clone()
		post.ChannelId = sub.ChannelID
		createdPost, appErr := p.API.CreatePost(post)
		if appErr != nil {
			p.API.LogError("Failed to create Post", "appError", appErr)
		}

		if wi.Notification.Group == newVulnerableDependency {
			// Add a Reply Post for each vulnerability and provide options
			for _, vuln := range wi.Notification.Subject.Vulnerabilities {
				vulnPost := wi.vulnPost(vuln)
				vulnPost.UserId = p.BotUserID
				vulnPost.ChannelId = createdPost.ChannelId
				vulnPost.RootId = createdPost.Id

				if _, appErr := p.API.CreatePost(vulnPost); appErr != nil {
					p.API.LogError("Failed to create reply Post", "appError", appErr)
				}

			}
		}
	}
}
