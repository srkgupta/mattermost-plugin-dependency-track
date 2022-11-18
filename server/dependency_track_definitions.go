package main

type Notification struct {
	Level     string `json:"level"`
	Scope     string `json:"scope"`
	Group     string `json:"group"`
	Timestamp string `json:"timestamp"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Subject   struct {
		Component       Component       `json:"component"`
		Vulnerability   Vulnerability   `json:"vulnerability,omitempty"`
		Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
		Project         Project         `json:"project,omitempty"`
		Projects        []Project       `json:"affectedProjects,omitempty"`
		Analysis        Analysis        `json:"analysis,omitempty"`
	} `json:"subject"`
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
	} `json:"cwe"`
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
	Timestamp int64  `json:"timestamp"`
	Comment   string `json:"comment"`
}

type Finding struct {
	Analysis struct {
		Suppressed bool `json:"isSuppressed"`
	} `json:"analysis"`
	Component     Component     `json:"component"`
	Vulnerability Vulnerability `json:"vulnerability"`
}

type DependencyTrackConfig struct {
	ApiBaseUrl string `json:"api_base_url"`
}

type VulnerabilitySource struct {
	Components []VulnerabilityComponent `json:"components"`
}
type VulnerabilityComponent struct {
	Id      string  `json:"uuid"`
	Project Project `json:"project"`
}
