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
	vulnPath     = "vulnerability"
	analysisPath = "analysis"
	headerAPIKey = "X-API-Key"
)

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
	return resp, nil
}

func (p *Plugin) fetchProjects() ([]Project, error) {
	projectsEndpoint := fmt.Sprintf("%s?excludeInactive=true&searchText=&sortOrder=asc&pageSize=20&pageNumber=1", projectPath)
	resp, err := p.doHTTPRequest(http.MethodGet, projectsEndpoint, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	if resp.Body == nil {
		return nil, nil
	}

	var response []Project
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func (p *Plugin) fetchAnalysis(projectId string, vulnUid string, componentUid string) (FindingAnalysis, error) {
	analysisEndpoint := fmt.Sprintf("%s?project=%s&component=%s&vulnerability=%s", analysisPath, projectId, componentUid, vulnUid)
	resp, err := p.doHTTPRequest(http.MethodGet, analysisEndpoint, nil)
	if err != nil {
		return FindingAnalysis{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// If analysis is not found, then response will be empty
	if resp.Body == nil {
		return FindingAnalysis{}, nil
	}

	var response FindingAnalysis
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return FindingAnalysis{}, err
	}
	return response, nil
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
		return fmt.Errorf("json.Marshal error while updating analysis: %s", err.Error())
	}
	p.API.LogDebug(fmt.Sprintf("Updating analysis with params: %s", string(b)))
	resp, err := p.doHTTPRequest(http.MethodPut, analysisPath, bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return errors.New("Something went wrong while updating the analysis in the DependencyTrack Tool")
	}

	return nil
}

func (p *Plugin) fetchProject(projectId string) (Project, error) {
	projectEndpoint := fmt.Sprintf("%s/%s", projectPath, projectId)
	resp, err := p.doHTTPRequest(http.MethodGet, projectEndpoint, nil)
	if err != nil {
		return Project{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Project{}, err
	}

	var response Project
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return Project{}, err
	}
	return response, nil
}

func (p *Plugin) fetchFindings(projectId string) ([]Finding, error) {
	findingsEndpoint := fmt.Sprintf("%s/%s?suppressed=false&searchText=&sortOrder=asc", findingPath, projectId)
	resp, err := p.doHTTPRequest(http.MethodGet, findingsEndpoint, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("non-ok %d status code for url: %s", resp.StatusCode, findingsEndpoint)
		return nil, errors.Wrap(err, msg)
	}

	var response []Finding
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
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

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("non-ok %d status code for url: %s", resp.StatusCode, url)
		return DependencyTrackConfig{}, errors.Wrap(err, msg)
	}

	var response DependencyTrackConfig
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return DependencyTrackConfig{}, err
	}
	return response, nil
}

func (p *Plugin) fetchVulnerability(vulnerabilityId string) (Vulnerability, error) {
	vulnEndpoint := fmt.Sprintf("%s/%s", vulnPath, vulnerabilityId)
	resp, err := p.doHTTPRequest(http.MethodGet, vulnEndpoint, nil)
	if err != nil {
		return Vulnerability{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("non-ok %d status code for url: %s", resp.StatusCode, vulnEndpoint)
		return Vulnerability{}, errors.Wrap(err, msg)
	}

	var response Vulnerability
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return Vulnerability{}, err
	}
	return response, nil
}

func (p *Plugin) findComponentIdForVulnerability(projectId string, source string, vulnId string) (string, error) {
	vulnEndpoint := fmt.Sprintf("%s/source/%s/vuln/%s", vulnPath, source, vulnId)
	resp, err := p.doHTTPRequest(http.MethodGet, vulnEndpoint, nil)
	componentId := ""

	if err != nil {
		return componentId, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("non-ok %d status code for url: %s", resp.StatusCode, vulnEndpoint)
		return componentId, errors.Wrap(err, msg)
	}

	var response VulnerabilitySource
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&response); err != nil {
		return componentId, err
	}

	for _, component := range response.Components {
		if projectId == component.Project.Id {
			componentId = component.Id
			break
		}
	}

	return componentId, nil
}
