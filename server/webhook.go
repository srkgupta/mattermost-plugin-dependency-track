package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost-server/v5/model"
)

// WebhookInfo from the webhook
type WebhookInfo struct {
	Notification       Notification `json:"notification`
	DependencyTrackUrl string
}

type Notification struct {
	Level     string `json:"level"`
	Scope     string `json:"scope"`
	Group     string `json:"group"`
	Timestamp string `json:"timestamp"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Subject   struct {
		Component       Component
		Vulnerability   Vulnerability   `json:"vulnerability,omitempty"`
		Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
		Project         Project         `json:"project,omitempty"`
		Projects        []Project       `json:"affectedProjects,omitempty"`
		Analysis        Analysis        `json:"analysis,omitempty"`
	}
}

type Component struct {
	Id         string `json:"uuid"`
	Group      string `json:"group"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Md5        string `json:"md5"`
	Sha1       string `json:"sha1"`
	Sha256     string `json:"sha256"`
	PackageUrl string `json:"purl"`
}

type Vulnerability struct {
	Id          string  `json:"uuid"`
	VulnId      string  `json:"vulnId"`
	Source      string  `json:"source"`
	Description string  `json:"description"`
	Cvss        float32 `json:"cvssv2"`
	Severity    string  `json:"severity"`
	Cwe         struct {
		Id   int32  `json:"cweId"`
		Name string `json:"name"`
	}
}

type Project struct {
	Id      string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Analysis struct {
	Suppresed       bool   `json:"suppressed"`
	State           string `json:"state"`
	ProjectId       string `json:"project"`
	ComponentId     string `json:"component"`
	VulnerabilityId string `json:"vulnerability"`
}

func (vuln *Vulnerability) ToUrl() string {
	url := ""
	switch vuln.Source {
	case "NVD":
		url = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.VulnId)
	case "NPM":
		url = fmt.Sprintf("https://github.com/advisories/%s", vuln.VulnId)
	case "VULNDB":
		url = fmt.Sprintf("https://vuldb.com/?id.%s", vuln.VulnId)
	}
	return url
}

func (project *Project) ToMarkdown(dtUrl string) string {
	return fmt.Sprintf("[%s](%s/projects/%s)", project.Name, dtUrl, project.Id)
}

func (vuln *Vulnerability) ToMarkdown() string {
	return fmt.Sprintf("[%s](%s)", vuln.VulnId, vuln.ToUrl())
}

func (vuln *Vulnerability) ToColor() string {
	color := "#50F100" // green

	switch strings.ToUpper(vuln.Severity) {
	case "LOW":
		color = "#ADD8E6" // light blue
	case "MEDIUM":
		color = "#FF8000" // orange
	case "HIGH":
		color = "#FF0000" // red
	case "CRITICAL":
		color = "#800000" // dark red
	}
	return color
}

// ToPost converts the WebhookInfo into a Post
func (wi *WebhookInfo) ToPost() *model.Post {
	message := ""
	attachment := &model.SlackAttachment{
		Title: wi.Notification.Title,
		Text:  wi.Notification.Content,
		Color: "#50F100", // green
	}

	fields := []*model.SlackAttachmentField{}

	if wi.Notification.Group == "NEW_VULNERABILITY" {
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
			affectedProjects += fmt.Sprintf("[%s](%s)\n", project.Name, project.ToMarkdown(wi.DependencyTrackUrl))
		}

		fields = append(fields, &model.SlackAttachmentField{
			Title: "Affected Projects",
			Value: affectedProjects,
			Short: true,
		})
		attachment.Color = wi.Notification.Subject.Vulnerability.ToColor()
	}

	if wi.Notification.Group == "BOM_CONSUMED" || wi.Notification.Group == "BOM_PROCESSED" {
		fields = append(fields, &model.SlackAttachmentField{
			Title: "Project",
			Value: wi.Notification.Subject.Project.ToMarkdown(wi.DependencyTrackUrl),
			Short: true,
		})
		if wi.Notification.Group == "BOM_CONSUMED" {
			attachment.Color = "#FF8000" // orange
		}
	}

	if wi.Notification.Group == "NEW_VULNERABLE_DEPENDENCY" {
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

		attachment.Color = "#FF0000" // red
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

	// TODO: Perform an internal list of tasks based on configured reference project
	// If Reference Project is configured, then check the status of the triggered Vulnerability in the reference project_id and the package versions.
	// If the status in the reference project was suppressed, marked
	// If it's not found, then display the notification

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
		if _, appErr := p.API.CreatePost(post); appErr != nil {
			p.API.LogError("Failed to create Post", "appError", appErr)
		}
	}
}
