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

type OsqueryPackResponse struct {
	SavedObjectID string          `json:"saved_object_id"` // Correct field for unique ID
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Enabled       bool            `json:"enabled"`
	PolicyIDs     []string        `json:"policy_ids"`
	Queries       []QueryResponse `json:"queries"` // Array format for querying packs
	Shards        map[string]int  `json:"shards,omitempty"`
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

// CheckIfPackExists checks if an Osquery pack with the given name exists and returns the pack's saved_object_id if it does
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

	// Iterate over packs and check if any pack's name matches the target name
	for _, pack := range packResponse.Data {
		if pack.Name == packName {
			logger.WithField("saved_object_id", pack.SavedObjectID).Info("pack found")
			return pack.SavedObjectID, nil
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

// UpdatePack updates an existing Osquery pack by merging new queries with existing ones.
func (c *Client) UpdatePack(packID string, newPack OsqueryPackRequest) error {
	logger := c.Logger.WithField("pack_id", packID)
	logger.Info("retrieving existing pack queries for update")

	// Retrieve the existing pack to get current queries
	endpoint := fmt.Sprintf("/api/osquery/packs/%s", packID)
	response, err := c.doRequest("GET", endpoint, nil)
	if err != nil {
		logger.WithError(err).Error("failed to retrieve existing pack for update")
		return fmt.Errorf("failed to retrieve existing pack: %w", err)
	}

	// Unmarshal the response to get existing queries
	var existingPack OsqueryPackResponse
	if err := json.Unmarshal(response, &existingPack); err != nil {
		logger.WithError(err).Error("failed to unmarshal existing pack JSON")
		return fmt.Errorf("failed to unmarshal existing pack JSON: %w", err)
	}

	// Initialize mergedQueries and add all queries from `existingPack`
	mergedQueries := make(map[string]Query)

	// Parse each query in existingPack, treating it as a nested map structure
	for id, existingQuery := range existingPack.Queries {
		logger.WithField("existing_query_id", id).Info("adding existing query to mergedQueries")
		mergedQueries[id] = Query{
			Query:    existingQuery.Query,
			Interval: existingQuery.Interval,
			Snapshot: existingQuery.Snapshot,
			Removed:  existingQuery.Removed,
			Timeout:  existingQuery.Timeout,
		}
	}

	// Add new queries if they don't already exist in `mergedQueries`
	for id, newQuery := range newPack.Queries {
		if _, exists := mergedQueries[id]; !exists {
			logger.WithField("new_query_id", id).Info("adding new query to mergedQueries")
			mergedQueries[id] = newQuery
		} else {
			logger.WithField("query_id", id).Info("query already exists, skipping")
		}
	}

	// Update the pack with the full merged queries set
	updatedPack := OsqueryPackRequest{
		Name:        newPack.Name,
		Description: newPack.Description,
		Enabled:     newPack.Enabled,
		PolicyIDs:   newPack.PolicyIDs,
		Queries:     mergedQueries,
		Shards:      newPack.Shards,
	}

	logger.WithField("updatedPack", updatedPack).Info("final updated pack with merged queries")

	// Send the PUT request with the full set of merged queries
	_, err = c.doRequest("PUT", endpoint, updatedPack)
	if err != nil {
		logger.WithError(err).Error("failed to update osquery pack")
		return fmt.Errorf("failed to update osquery pack: %w", err)
	}

	logger.Info("osquery pack updated successfully with merged queries")
	return nil
}
