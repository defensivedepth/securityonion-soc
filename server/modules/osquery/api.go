package osquery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/apex/log"
	"io/ioutil"
	"net/http"
)

// Client holds base URL and authentication for API requests
type Client struct {
	BaseURL  string
	Username string
	Password string
	Logger   *log.Entry
}

type OsqueryPackRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Enabled     bool             `json:"enabled"`
	PolicyIDs   []string         `json:"policy_ids"`
	Queries     map[string]Query `json:"queries"` // Map format for creating/updating packs
	Shards      map[string]int   `json:"shards,omitempty"`
}

type Query struct {
	Query      string                 `json:"query"`
	Interval   int                    `json:"interval"`
	Snapshot   bool                   `json:"snapshot"`
	Removed    bool                   `json:"removed"`
	Timeout    int                    `json:"timeout"`
	EcsMapping map[string]interface{} `json:"ecs_mapping,omitempty"`
}

// For GET responses where queries is an array
type OsqueryPackResponse struct {
	ID          string          `json:"id"` // Include the ID field to capture it
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	PolicyIDs   []string        `json:"policy_ids"`
	Queries     []QueryResponse `json:"queries"` // Array format for querying packs
	Shards      map[string]int  `json:"shards,omitempty"`
}

type QueryResponse struct {
	ID         string               `json:"id"`
	Query      string               `json:"query"`
	Interval   int                  `json:"interval"`
	Snapshot   bool                 `json:"snapshot"`
	Removed    bool                 `json:"removed"`
	Timeout    int                  `json:"timeout"`
	EcsMapping []EcsMappingResponse `json:"ecs_mapping,omitempty"`
}

type EcsMappingResponse struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// doRequest is a generic function to handle HTTP requests, logging request and response details for debugging.
func (c *Client) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
	logger := c.Logger.WithFields(log.Fields{
		"method":   method,
		"endpoint": endpoint,
	})

	// Marshal body to JSON if provided
	var jsonBody []byte
	var err error
	if body != nil {
		jsonBody, err = json.Marshal(body)
		if err != nil {
			logger.WithError(err).Error("failed to marshal JSON body")
			return nil, fmt.Errorf("failed to marshal JSON body: %w", err)
		}
	}

	// Create the request
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		logger.WithError(err).Error("failed to create HTTP request")
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Log the request body if it exists
	if jsonBody != nil {
		logger.WithField("request_body", string(jsonBody)).Info("request body")
	}

	// Set headers and basic auth
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithError(err).Error("failed to send HTTP request")
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Log response status code
	logger.WithField("status_code", resp.StatusCode).Info("received response")

	// Check for HTTP status codes other than 200 or 201
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		logger.WithField("response_body", string(bodyBytes)).Error("unexpected status code")
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read and return response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.WithError(err).Error("failed to read response body")
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logger.WithField("response_body", string(responseBody)).Info("successful response")
	return responseBody, nil
}

// CheckIfPackExists checks if an Osquery pack with the given name exists and returns the pack's ID if it does
func (c *Client) CheckIfPackExists(packName string) (string, error) {
	logger := c.Logger.WithField("pack_name", packName)
	logger.Info("checking if pack exists")

	response, err := c.doRequest("GET", "/api/osquery/packs", nil)
	if err != nil {
		return "", err
	}

	var packResponse struct {
		Data []OsqueryPackResponse `json:"data"`
	}
	if err := json.Unmarshal(response, &packResponse); err != nil {
		logger.WithError(err).Error("failed to unmarshal JSON")
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	for _, pack := range packResponse.Data {
		if pack.Name == packName {
			logger.Info("pack found")
			return pack.ID, nil
		}
	}
	logger.Info("pack not found")
	return "", nil
}

// CreatePack creates a new Osquery pack
func (c *Client) CreatePack(pack OsqueryPackRequest) error {
	logger := c.Logger.WithField("pack_name", pack.Name)
	logger.Info("creating osquery pack")

	_, err := c.doRequest("POST", "/api/osquery/packs", pack)
	if err != nil {
		logger.WithError(err).Error("failed to create osquery pack")
		return fmt.Errorf("failed to create osquery pack: %w", err)
	}
	logger.Info("osquery pack created successfully")
	return nil
}

// UpdatePack updates an existing Osquery pack using its ID
func (c *Client) UpdatePack(packID string, pack OsqueryPackRequest) error {
	logger := c.Logger.WithField("pack_id", packID)
	logger.Info("updating osquery pack")

	endpoint := fmt.Sprintf("/api/osquery/packs/%s", packID)
	_, err := c.doRequest("PUT", endpoint, pack)
	if err != nil {
		logger.WithError(err).Error("failed to update osquery pack")
		return fmt.Errorf("failed to update osquery pack: %w", err)
	}
	logger.Info("osquery pack updated successfully")
	return nil
}
