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
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Enabled       bool     `json:"enabled"`
	CreatedAt     string   `json:"created_at,omitempty"`
	CreatedBy     string   `json:"created_by,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
	UpdatedBy     string   `json:"updated_by,omitempty"`
	SavedObjectID string   `json:"saved_object_id,omitempty"`
	PolicyIDs     []string `json:"policy_ids,omitempty"`
	Queries       []Query  `json:"queries"` // Queries is now a slice, not a map
}

type Query struct {
	ID         string   `json:"id,omitempty"` // Includes ID for identification
	Query      string   `json:"query"`
	Interval   int      `json:"interval"`
	Snapshot   bool     `json:"snapshot,omitempty"`
	Removed    bool     `json:"removed,omitempty"`
	Timeout    int      `json:"timeout"`
	ECSMapping []ECSMap `json:"ecs_mapping,omitempty"` // ECSMapping as a list
}

type ECSMap struct {
	Key   string      `json:"key"`
	Value ECSMapValue `json:"value"`
}

type ECSMapValue struct {
	Field string   `json:"field,omitempty"`
	Value []string `json:"value,omitempty"`
}

// CheckIfPackExists checks if a pack exists and returns the pack ID if it does
func (c *Client) CheckIfPackExists(packName string) (string, error) {
	url := fmt.Sprintf("%s/api/osquery/packs", c.BaseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("kbn-xsrf", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch packs: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	for _, pack := range result["data"].([]interface{}) {
		if pack.(map[string]interface{})["name"] == packName {
			return pack.(map[string]interface{})["saved_object_id"].(string), nil
		}
	}
	return "", nil
}

func (c *Client) CreatePack(pack PackData) error {
	url := fmt.Sprintf("%s/api/osquery/packs", c.BaseURL)
	payload, err := json.Marshal(pack)
	if err != nil {
		return fmt.Errorf("failed to marshal pack data: %v", err)
	}

	// Log the payload to inspect it
	c.Logger.Infof("Creating pack with payload: %s", string(payload))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to create pack: %s - %s", resp.Status, string(body))
	}
	c.Logger.Info("Pack created successfully")
	return nil
}

func (c *Client) GetPack(packID string) (PackData, error) {
	url := fmt.Sprintf("%s/api/osquery/packs/%s", c.BaseURL, packID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return PackData{}, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("kbn-xsrf", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return PackData{}, err
	}
	defer resp.Body.Close()

	rawBody, _ := ioutil.ReadAll(resp.Body)
	c.Logger.Infof("Raw response from GetPack: %s", string(rawBody))

	if resp.StatusCode != http.StatusOK {
		return PackData{}, fmt.Errorf("failed to retrieve pack: %s - %s", resp.Status, string(rawBody))
	}

	// Decode the response into PackData
	var response struct {
		Data PackData `json:"data"` // Match response format
	}
	if err := json.Unmarshal(rawBody, &response); err != nil {
		return PackData{}, fmt.Errorf("failed to decode pack data: %v", err)
	}

	c.Logger.Infof("Decoded PackData: %+v", response.Data)
	return response.Data, nil
}

func (c *Client) AddQueryToPack(packID, newQueryName string, newQuery Query) error {
	// Fetch the existing pack to get all its details
	pack, err := c.GetPack(packID)
	if err != nil {
		return fmt.Errorf("failed to retrieve pack: %v", err)
	}

	// Check if the query exists and merge accordingly
	updated := false
	for i, q := range pack.Queries {
		if q.ID == newQueryName { // Check if query ID matches
			pack.Queries[i] = newQuery
			updated = true
			break
		}
	}
	if !updated {
		newQuery.ID = newQueryName // Set ID for new queries
		pack.Queries = append(pack.Queries, newQuery)
	}

	// Prepare the updated pack payload for the PUT request
	url := fmt.Sprintf("%s/api/osquery/packs/%s", c.BaseURL, packID)
	payload, err := json.Marshal(pack)
	if err != nil {
		return fmt.Errorf("failed to marshal updated pack data: %v", err)
	}

	c.Logger.Infof("Full payload for pack update: %s", string(payload))

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to update pack: %s - %s", resp.Status, string(body))
	}
	c.Logger.Info("Query added successfully to pack")
	return nil
}
