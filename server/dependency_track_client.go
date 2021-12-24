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
	apiPath      = "/api/v1/"
	projectPath  = "project"
	findingPath  = "finding/project"
	analysisPath = "analysis"
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
	Id      string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Analysis struct {
	Suppressed      bool   `json:"suppressed"`
	State           string `json:"state"`
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
	Timestamp string
	Comment   string
	Commenter string
}

type Finding struct {
	Analysis struct {
		Suppressed bool `json:"isSuppressed"`
	}
	Component     Component
	Vulnerability Vulnerability
}

func (p *Plugin) doHTTPRequest(method string, path string, body io.Reader) (*http.Response, error) {
	bearer := p.getConfiguration().DependencyTrackApiKey
	url := p.getConfiguration().DependencyTrackUrl + apiPath + path
	p.API.LogDebug("Making HTTP request to DependencyTrack API:", url)
	req, err := http.NewRequest(method, url, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer: %s", bearer))
	if err != nil {
		return nil, errors.Wrap(err, "bad request for url:"+url)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "connection problem for url:"+url)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("non-ok status code for url:" + url)
	}
	return resp, err
}

func (p *Plugin) fetchProjects() ([]Project, error) {
	projectsEndpoint := fmt.Sprintf("%s?excludeInactive=true&searchText=&sortOrder=asc&pageSize=20&pageNumber=1", projectPath)
	resp, err := p.doHTTPRequest(http.MethodGet, projectsEndpoint, nil)
	if err != nil {
		p.API.LogWarn("Something went wrong while getting the projects from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogWarn("Something went wrong while getting the projects from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}

	if resp.Body == nil {
		return nil, nil
	}

	var response []Project
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogWarn("Something went wrong while getting the projects from DependencyTrack Tool", "error", err.Error())
		return nil, err
	}
	return response, err
}

func (p *Plugin) fetchAnalysis(projectId string, vulnUid string, componentUid string) (FindingAnalysis, error) {
	analysisEndpoint := fmt.Sprintf("%s?project=%s&component=%s&vulnerability=%s", analysisPath, projectId, componentUid, vulnUid)
	resp, err := p.doHTTPRequest(http.MethodGet, analysisEndpoint, nil)
	if err != nil {
		p.API.LogWarn("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return FindingAnalysis{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogWarn("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return FindingAnalysis{}, err
	}

	// If analysis is not found, then response will be empty
	if resp.Body == nil {
		return FindingAnalysis{}, nil
	}

	var response FindingAnalysis
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		p.API.LogWarn("Something went wrong while getting the analysis from DependencyTrack Tool", "error", err.Error())
		return FindingAnalysis{}, err
	}
	return response, err
}

func (p *Plugin) updateAnalysis(projectId string, vulnUid string, componentUid string, analysis FindingAnalysis) error {
	prevComment := analysis.Comments[len(analysis.Comments)-1]
	comment := fmt.Sprintf("Suppressed automatically by the Mattermost DependencyTrack Plugin. Reference comment: %s", prevComment)
	newAnalysis := Analysis{
		Suppressed:      analysis.Suppressed,
		ProjectId:       projectId,
		ComponentId:     componentUid,
		VulnerabilityId: vulnUid,
		Comment:         comment,
	}

	b, err := json.Marshal(newAnalysis)
	if err != nil {
		return fmt.Errorf("json.Marshal error while updating analysis: %w", err)
	}
	resp, err := p.doHTTPRequest(http.MethodPut, analysisPath, bytes.NewReader(b))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.API.LogWarn("Something went wrong while updating the analysis in the DependencyTrack Tool", "error", err.Error())
		return err
	}

	return nil
}

func (p *Plugin) fetchProject(projectId string) (Project, error) {
	return Project{}, nil
}

func (p *Plugin) fetchFindings(projectId string) ([]Finding, error) {
	return nil, nil
}

func (p *Plugin) fetchFinding(projectId string, vulnId string) (Finding, error) {
	return Finding{}, nil
}
