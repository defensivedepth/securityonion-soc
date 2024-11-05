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

// PackData represents the pack details
type PackData struct {
	Name          string           `json:"name"`                      // Required
	Description   string           `json:"description,omitempty"`     // Optional
	Enabled       bool             `json:"enabled"`                   // Required
	PolicyIDs     []string         `json:"policy_ids,omitempty"`      // Optional
	Queries       map[string]Query `json:"queries,omitempty"`         // Required if non-empty
	SavedObjectID string           `json:"saved_object_id,omitempty"` // Ignored during creation
}

// Query represents the osquery query structure
type Query struct {
	Query      string            `json:"query"`
	Interval   int               `json:"interval"`
	Timeout    int               `json:"timeout"`
	ECSMapping map[string]ECSMap `json:"ecs_mapping,omitempty"`
}

// ECSMap represents the ECS mapping details
type ECSMap struct {
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

// GetPack retrieves a pack by its ID
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

	var pack PackData
	if err := json.NewDecoder(resp.Body).Decode(&pack); err != nil {
		return PackData{}, err
	}
	return pack, nil
}

func (c *Client) AddQueryToPack(packID, newQueryName string, newQuery Query) error {
	pack, err := c.GetPack(packID)
	if err != nil {
		return err
	}

	if pack.Queries == nil {
		pack.Queries = make(map[string]Query)
	}
	pack.Queries[newQueryName] = newQuery

	url := fmt.Sprintf("%s/api/osquery/packs/%s", c.BaseURL, packID)
	payload, _ := json.Marshal(pack)
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
		return fmt.Errorf("failed to update pack: %s", resp.Status)
	}
	c.Logger.Info("Query added successfully to pack")
	return nil
}
