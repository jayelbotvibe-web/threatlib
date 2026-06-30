package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// ─────────────────────────────────────────────────────────────
// Config holds all parsed configuration.
// ─────────────────────────────────────────────────────────────

type Config struct {
	Org      OrgConfig
	Sources  SourcesConfig
	Routing  RoutingConfig
	Risk     RiskConfig
	Matchers MatchersConfig
}

// ─────────────────────────────────────────────────────────────
// Org
// ─────────────────────────────────────────────────────────────

type OrgConfig struct {
	Name            string `yaml:"name"`
	Sector          string `yaml:"sector"`
	Country         string `yaml:"country"`
	Timezone        string `yaml:"timezone"`
	DataSensitivity string `yaml:"data_sensitivity"`
}

func LoadOrg(path string) (OrgConfig, error) {
	var wrapper struct {
		Org OrgConfig `yaml:"org"`
	}
	if err := loadYAML(path, &wrapper); err != nil {
		return OrgConfig{}, err
	}
	return wrapper.Org, nil
}

func (o OrgConfig) ToOrgContext(apps []model.App) model.OrgContext {
	return model.OrgContext{
		OrgID:           "default",
		Name:            o.Name,
		Sector:          o.Sector,
		Country:         o.Country,
		Timezone:        o.Timezone,
		DataSensitivity: o.DataSensitivity,
		TechStack:       apps,
	}
}

// ─────────────────────────────────────────────────────────────
// Sources
// ─────────────────────────────────────────────────────────────

type SourceEntry struct {
	ID           string `yaml:"id"`
	Type         string `yaml:"type"`
	Name         string `yaml:"name"`
	URL          string `yaml:"url"`
	AuthKeyEnv   string `yaml:"auth_key_env"`
	Confidence   string `yaml:"confidence"`
	Enabled      bool   `yaml:"enabled"`
	PullInterval string `yaml:"pull_interval"`
}

type SourcesConfig struct {
	Sources []SourceEntry `yaml:"sources"`
}

func LoadSources(path string) (SourcesConfig, error) {
	var cfg SourcesConfig
	if err := loadYAML(path, &cfg); err != nil {
		return SourcesConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Routing
// ─────────────────────────────────────────────────────────────

// RoutingRule matches alert severity + confidence to notification channels.
type RoutingRule struct {
	Severity   string   `yaml:"severity"`
	Confidence []string `yaml:"confidence"`
	Channels   []string `yaml:"channels"`
	Format     string   `yaml:"format"`
}

type RoutingConfig struct {
	Rules []RoutingRule `yaml:"rules"`
}

func LoadRouting(path string) (RoutingConfig, error) {
	var cfg RoutingConfig
	if err := loadYAML(path, &cfg); err != nil {
		return RoutingConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Risk
// ─────────────────────────────────────────────────────────────

type RiskConfig struct {
	Dimensions struct {
		Likelihood struct {
			Max     int `yaml:"max"`
			Factors map[string]int `yaml:"factors"`
		} `yaml:"likelihood"`
		Impact struct {
			Max     int `yaml:"max"`
			Factors map[string]int `yaml:"factors"`
		} `yaml:"impact"`
		Exposure struct {
			Max     int `yaml:"max"`
			Factors map[string]int `yaml:"factors"`
		} `yaml:"exposure"`
		Confidence struct {
			Max     int `yaml:"max"`
			Factors map[string]int `yaml:"factors"`
		} `yaml:"confidence"`
	} `yaml:"dimensions"`
	Severity struct {
		Thresholds map[string]float64 `yaml:"thresholds"`
	} `yaml:"severity"`
}

func LoadRisk(path string) (RiskConfig, error) {
	var cfg RiskConfig
	if err := loadYAML(path, &cfg); err != nil {
		return RiskConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Matchers
// ─────────────────────────────────────────────────────────────

type MatcherEntry struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
}

type MatchersConfig struct {
	Matchers []MatcherEntry `yaml:"matchers"`
}

func LoadMatchers(path string) (MatchersConfig, error) {
	var cfg MatchersConfig
	if err := loadYAML(path, &cfg); err != nil {
		return MatchersConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Load all config from a directory.
// ─────────────────────────────────────────────────────────────

func LoadAll(configDir string) (*Config, []model.App, error) {
	cfg := &Config{}

	// Org
	org, err := LoadOrg(configDir + "/org.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("org: %w", err)
	}
	cfg.Org = org

	// Sources
	sources, err := LoadSources(configDir + "/sources.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("sources: %w", err)
	}
	cfg.Sources = sources

	// Routing
	routing, err := LoadRouting(configDir + "/routing.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("routing: %w", err)
	}
	cfg.Routing = routing

	// Risk
	risk, err := LoadRisk(configDir + "/risk.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("risk: %w", err)
	}
	cfg.Risk = risk

	// Matchers
	matchers, err := LoadMatchers(configDir + "/matchers.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("matchers: %w", err)
	}
	cfg.Matchers = matchers

	// Tech stack (CSV)
	apps, err := ParseTechStack(configDir + "/techstack.csv")
	if err != nil {
		return nil, nil, fmt.Errorf("techstack: %w", err)
	}

	return cfg, apps, nil
}

// ─────────────────────────────────────────────────────────────
// YAML helper
// ─────────────────────────────────────────────────────────────

func loadYAML(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
