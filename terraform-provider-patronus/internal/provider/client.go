package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Client for interacting with Patronus
type Client struct {
	ConfigPath string
	ApiUrl     string
	ApiToken   string
	httpClient *http.Client
}

// DeclarativeConfig represents a Patronus configuration resource
type DeclarativeConfig struct {
	ApiVersion string                 `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                 `yaml:"kind" json:"kind"`
	Metadata   Metadata               `yaml:"metadata" json:"metadata"`
	Spec       map[string]interface{} `yaml:"spec" json:"spec"`
}

type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// NewClient creates a new Patronus client
func (c *Client) Init() {
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
}

// WriteConfig writes a configuration to a YAML file
func (c *Client) WriteConfig(config *DeclarativeConfig) error {
	// Ensure config directory exists
	if err := os.MkdirAll(c.ConfigPath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate filename from kind and name
	filename := fmt.Sprintf("%s-%s.yaml", config.Kind, config.Metadata.Name)
	filepath := filepath.Join(c.ConfigPath, filename)

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ReadConfig reads a configuration from a YAML file
func (c *Client) ReadConfig(kind, name string) (*DeclarativeConfig, error) {
	filename := fmt.Sprintf("%s-%s.yaml", kind, name)
	filepath := filepath.Join(c.ConfigPath, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config DeclarativeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// DeleteConfig deletes a configuration file
func (c *Client) DeleteConfig(kind, name string) error {
	filename := fmt.Sprintf("%s-%s.yaml", kind, name)
	filepath := filepath.Join(c.ConfigPath, filename)

	if err := os.Remove(filepath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to delete config file: %w", err)
	}

	return nil
}

// ApplyConfig sends a configuration to the Patronus API for application
func (c *Client) ApplyConfig(config *DeclarativeConfig) error {
	if c.ApiUrl == "" {
		// No API configured, just write to file
		return c.WriteConfig(config)
	}

	c.Init()

	url := fmt.Sprintf("%s/api/v1/config/apply", c.ApiUrl)

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.ApiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiToken))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Also write to local file
	return c.WriteConfig(config)
}

// GetConfig retrieves a configuration from the Patronus API
func (c *Client) GetConfig(kind, name string) (*DeclarativeConfig, error) {
	if c.ApiUrl == "" {
		// No API configured, read from file
		return c.ReadConfig(kind, name)
	}

	c.Init()

	url := fmt.Sprintf("%s/api/v1/config/%s/%s", c.ApiUrl, kind, name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.ApiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiToken))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Fallback to file
		return c.ReadConfig(kind, name)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return c.ReadConfig(kind, name) // Fallback to file
	}

	var config DeclarativeConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &config, nil
}

// RemoveConfig deletes a configuration via API and/or file
func (c *Client) RemoveConfig(kind, name string) error {
	if c.ApiUrl != "" {
		c.Init()

		url := fmt.Sprintf("%s/api/v1/config/%s/%s", c.ApiUrl, kind, name)

		req, err := http.NewRequest("DELETE", url, nil)
		if err == nil {
			if c.ApiToken != "" {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiToken))
			}

			resp, err := c.httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}

	// Also delete local file
	return c.DeleteConfig(kind, name)
}
