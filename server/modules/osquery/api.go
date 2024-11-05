// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package osquery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/apex/log"
	"io/ioutil"
	"net/http"
)

type Client struct {
	BaseURL  string
	Username string
	Password string
	Logger   *log.Entry
}

func NewClient(baseURL, username, password string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		Logger:   log.WithField("module", "osquery-client"),
	}
}

type PackData struct {
	Name          string           `json:"name"`
	Description   string           `json:"description,omitempty"`
	Enabled       bool             `json:"enabled"`
	CreatedAt     string           `json:"created_at,omitempty"`
	CreatedBy     string           `json:"created_by,omitempty"`
	UpdatedAt     string           `json:"updated_at,omitempty"`
	UpdatedBy     string           `json:"updated_by,omitempty"`
	SavedObjectID string           `json:"saved_object_id,omitempty"`
	PolicyIDs     []string         `json:"policy_ids"`
	Queries       map[string]Query `json:"queries"`
}

type Query struct {
	ID         string   `json:"id,omitempty"`
	Query      string   `json:"query"`
	Interval   int      `json:"interval"`
	Snapshot   bool     `json:"snapshot,omitempty"`
	Removed    bool     `json:"removed,omitempty"`
	Timeout    int      `json:"timeout"`
	ECSMapping []ECSMap `json:"ecs_mapping,omitempty"`
}

type ECSMap struct {
	Key   string      `json:"key"`
	Value ECSMapValue `json:"value"`
}

type ECSMapValue struct {
	Field string   `json:"field,omitempty"`
	Value []string `json:"value,omitempty"`
}

// makeRequest is a helper function that creates and sends an HTTP request, handling common setup.
func (c *Client) makeRequest(method, endpoint string, headers map[string]string, body []byte) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("error response: %s - %s", resp.Status, string(body))
	}
	return resp, nil
}

// CheckIfPackExists checks if a pack exists and returns the pack ID if it does
func (c *Client) CheckIfPackExists(packName string) (string, error) {
	resp, err := c.makeRequest("GET", "/api/osquery/packs", nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	for _, pack := range result["data"].([]interface{}) {
		if pack.(map[string]interface{})["name"] == packName {
			return pack.(map[string]interface{})["saved_object_id"].(string), nil
		}
	}
	return "", nil
}

// CreatePack sends a request to create a new pack with the provided PackData
func (c *Client) CreatePack(pack PackData) error {
	payload, err := json.Marshal(pack)
	if err != nil {
		return fmt.Errorf("failed to marshal pack data: %w", err)
	}

	c.Logger.Infof("Creating pack with payload: %s", string(payload))
	resp, err := c.makeRequest("POST", "/api/osquery/packs", nil, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.Logger.Info("Pack created successfully")
	return nil
}

// GetPack retrieves the details of a specific pack by its ID
func (c *Client) GetPack(packID string) (PackData, error) {
	resp, err := c.makeRequest("GET", fmt.Sprintf("/api/osquery/packs/%s", packID), nil, nil)
	if err != nil {
		return PackData{}, err
	}
	defer resp.Body.Close()

	rawBody, _ := ioutil.ReadAll(resp.Body)
	c.Logger.Infof("Raw response from GetPack: %s", string(rawBody))

	var response struct {
		Data PackData `json:"data"`
	}
	if err := json.Unmarshal(rawBody, &response); err != nil {
		return PackData{}, fmt.Errorf("failed to decode pack data: %w", err)
	}

	c.Logger.Infof("Decoded PackData: %+v", response.Data)
	return response.Data, nil
}

// AddQueryToPack adds a new query to an existing pack or updates an existing query
func (c *Client) AddQueryToPack(packID, newQueryName string, newQuery Query) error {
	pack, err := c.GetPack(packID)
	if err != nil {
		return fmt.Errorf("failed to retrieve pack: %w", err)
	}

	if pack.Queries == nil {
		pack.Queries = make(map[string]Query)
	}
	pack.Queries[newQueryName] = newQuery

	payload, err := json.Marshal(pack)
	if err != nil {
		return fmt.Errorf("failed to marshal updated pack data: %w", err)
	}

	c.Logger.Infof("Full payload for pack update: %s", string(payload))
	resp, err := c.makeRequest("PUT", fmt.Sprintf("/api/osquery/packs/%s", packID), nil, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.Logger.Info("Query added successfully to pack")
	return nil
}

func (client *Client) createBuiltinPack(packName string) error {
	// Define possible packs
	packs := map[string]PackData{
		"All-Enrolled-Hosts": {
			Name:        "All-Enrolled-Hosts",
			Description: "This is a builtin pack for all enrolled hosts - it is managed by Security Onion Detections.",
			Enabled:     true,
			PolicyIDs:   []string{}, // Leave it empty, so that it applies to all Fleet Policies
			Queries:     map[string]Query{},
		},
		"Grid-Nodes": {
			Name:        "Grid-Nodes",
			Description: "This is a builtin pack for grid nodes - it is managed by Security Onion Detections.",
			Enabled:     true,
			PolicyIDs:   []string{"so-grid-nodes_general"},
			Queries:     map[string]Query{},
		},
	}

	// Check if the provided packName exists in the predefined packs
	packData, exists := packs[packName]
	if !exists {
		client.Logger.Errorf("Unknown pack: %s", packName)
		return fmt.Errorf("unknown pack: %s", packName)
	}

	// Log the pack data to verify its structure
	client.Logger.Infof("Pack data being sent: %+v", packData)

	// Create the pack
	err := client.CreatePack(packData)
	if err != nil {
		client.Logger.Errorf("Error creating pack %s: %s", packData.Name, err)
		return err
	}

	return nil
}
