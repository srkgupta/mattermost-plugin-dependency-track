package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

const (
	configPath   = "/static/config.json"
	apiPath      = "/api/v1/"
	projectPath  = "project"
	findingPath  = "finding/project"
	analysisPath = "analysis"
	headerAPIKey = "X-API-Key"
)

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
	ProjectId  string `json:"project,omitempty"`
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

type Projects struct {
	Projects []Project `json:"data"`
}
type Project struct {
	Id                     string  `json:"uuid"`
	Name                   string  `json:"name"`
	Version                string  `json:"version"`
	LastBomImport          int64   `json:"lastBomImport,omitempty"`
	LastBomImportFormat    string  `json:"lastBomImportFormat,omitempty"`
	LastInheritedRiskScore float32 `json:"lastInheritedRiskScore,omitempty"`
	Active                 bool    `json:"active,omitempty"`
}

type Analysis struct {
	Suppressed      bool   `json:"suppressed"`
	State           string `json:"state,omitempty"`
	ProjectId       string `json:"project"`
	ComponentId     string `json:"component"`
	VulnerabilityId string `json:"vulnerability"`
	Comment         string `json:"comment"`
	AnalysisState   string `json:"analysisState"`
}

type FindingAnalysis struct {
	Suppressed bool              `json:"isSuppressed"`
	State      string            `json:"analysisState"`
	Comments   []AnalysisComment `json:"analysisComments"`
}

type AnalysisComment struct {
	Timestamp int64
	Comment   string
}

type Finding struct {
	Analysis struct {
		Suppressed bool `json:"isSuppressed"`
	}
	Component     Component
	Vulnerability Vulnerability
}

type DependencyTrackConfig struct {
	ApiBaseUrl string `json:"api_base_url"`
}

func (p *Plugin) doHTTPRequest(method string, path string, body io.Reader) (*http.Response, error) {
	apiKey := p.getConfiguration().DependencyTrackApiKey
	apiBaseUrl := p.getConfiguration().DependencyTrackApiUrl
	url := apiBaseUrl + apiPath + path

	if len(apiKey) < 1 || len(apiBaseUrl) < 1 {
		return nil, errors.New("Invalid DependencyTrack config.")
	}

	p.API.LogDebug("Making HTTP request to DependencyTrack API:", url)
	req, err := http.NewRequest(method, url, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add(headerAPIKey, apiKey)
	if err != nil {
		return nil, errors.Wrap(err, "bad request for url:"+url)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "connection problem for url:"+url)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New(fmt.Sprintf("non-ok %d status code for url: %s", resp.StatusCode, url))
	}
	return resp, err
}

func (p *Plugin) fetchProjects() ([]Project, error) {
	projectsEndpoint := fmt.Sprintf("%s?excludeInactive=true&searchText=&sortOrder=asc&pageSize=20&pageNumber=1", projectPath)
	resp, err := p.doHTTPRequest(http.MethodGet, projectsEndpoint, nil)
	if err != nil {
		p.API.LogError("Something went wrong while getting the projects from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogError("Something went wrong while getting the projects from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}

	if resp.Body == nil {
		return nil, nil
	}

	var response []Project
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogError("Something went wrong while getting the projects from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	return response, err
}

func (p *Plugin) fetchAnalysis(projectId string, vulnUid string, componentUid string) (FindingAnalysis, error) {
	analysisEndpoint := fmt.Sprintf("%s?project=%s&component=%s&vulnerability=%s", analysisPath, projectId, componentUid, vulnUid)
	resp, err := p.doHTTPRequest(http.MethodGet, analysisEndpoint, nil)
	if err != nil {
		p.API.LogError("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return FindingAnalysis{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogError("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return FindingAnalysis{}, err
	}

	// If analysis is not found, then response will be empty
	if resp.Body == nil {
		return FindingAnalysis{}, nil
	}

	var response FindingAnalysis
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogError("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return FindingAnalysis{}, err
	}
	return response, err
}

func (p *Plugin) updateAnalysis(projectId string, vulnUid string, componentUid string, analysis FindingAnalysis, username string) error {
	comment := fmt.Sprintf("Status updated by @%s using the Mattermost DependencyTrack Plugin.", username)

	if analysis.Suppressed {
		comment = fmt.Sprintf("Suppressed by @%s using the Mattermost DependencyTrack Plugin.", username)
	}
	newAnalysis := Analysis{
		Suppressed:      analysis.Suppressed,
		AnalysisState:   analysis.State,
		ProjectId:       projectId,
		ComponentId:     componentUid,
		VulnerabilityId: vulnUid,
		Comment:         comment,
	}

	b, err := json.Marshal(newAnalysis)
	if err != nil {
		return fmt.Errorf("json.Marshal error while updating analysis: %w", err)
	}
	p.API.LogDebug(fmt.Sprintf("Updating analysis with params: %s", string(b)))
	resp, err := p.doHTTPRequest(http.MethodPut, analysisPath, bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogError("Something went wrong while updating the analysis in the DependencyTrack Tool", "error", err.Error())
		return err
	}

	return nil
}

func (p *Plugin) fetchProject(projectId string) (Project, error) {
	projectEndpoint := fmt.Sprintf("%s/%s", projectPath, projectId)
	resp, err := p.doHTTPRequest(http.MethodGet, projectEndpoint, nil)
	if err != nil {
		p.API.LogError("Something went wrong while getting the project from DependencyTrack Tool", "error", err.Error())
		return Project{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogError("Something went wrong while getting the project from DependencyTrack Tool", "error", err.Error())
		return Project{}, err
	}

	var response Project
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogError("Something went wrong while getting the project from DependencyTrack Tool", "error", err.Error())
		return Project{}, err
	}
	return response, err
}

func (p *Plugin) fetchFindings(projectId string) ([]Finding, error) {
	findingsEndpoint := fmt.Sprintf("%s/%s?suppressed=false&searchText=&sortOrder=asc", findingPath, projectId)
	resp, err := p.doHTTPRequest(http.MethodGet, findingsEndpoint, nil)
	if err != nil {
		p.API.LogError("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogError("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	var response []Finding
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogError("Something went wrong while getting the findings from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	return response, err
}

func (p *Plugin) fetchConfig() (DependencyTrackConfig, error) {
	url := fmt.Sprintf("%s/%s", p.getConfiguration().DependencyTrackUrl, configPath)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return DependencyTrackConfig{}, errors.Wrap(err, "bad request for url:"+url)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return DependencyTrackConfig{}, errors.Wrap(err, "connection problem for url:"+url)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return DependencyTrackConfig{}, errors.Wrap(err, "non-ok status code for url:"+url)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogError("Something went wrong while getting the config from DependencyTrack Tool", "error", err.Error())
		return DependencyTrackConfig{}, err
	}

	var response DependencyTrackConfig
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogError("Something went wrong while getting the config from DependencyTrack Tool", "error", err.Error())
		return DependencyTrackConfig{}, err
	}
	return response, err
}
