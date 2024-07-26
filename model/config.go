// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"regexp"
	"strings"
)

type Setting struct {
	Id                  string `json:"id"`
	Title               string `json:"title"`
	Description         string `json:"description"`
	Global              bool   `json:"global"` // If Global == Node then the setting applies to both
	Node                bool   `json:"node"`
	NodeId              string `json:"nodeId"`
	Default             string `json:"default"`
	DefaultAvailable    bool   `json:"defaultAvailable"`
	Value               string `json:"value"`
	Multiline           bool   `json:"multiline"`
	Readonly            bool   `json:"readonly"`
	ReadonlyUi          bool   `json:"readonlyUi"`
	Sensitive           bool   `json:"sensitive"`
	Regex               string `json:"regex"`
	RegexFailureMessage string `json:"regexFailureMessage"`
	File                bool   `json:"file"`
	Advanced            bool   `json:"advanced"`
	HelpLink            string `json:"helpLink"`
	Syntax              string `json:"syntax"`
	ForcedType          string `json:"forcedType"`
	Duplicates          bool   `json:"duplicates"`
	Extended            bool   `json:"extended"`
}

func NewSetting(id string) *Setting {
	setting := &Setting{}
	setting.SetId(id)
	return setting
}

func (setting *Setting) SetId(id string) {
	setting.Id = id
	setting.Extended = IsExtendedSetting(setting)
}

func IsExtendedSetting(setting *Setting) bool {
	return strings.HasPrefix(setting.Id, "elasticsearch.index_settings.")
}

func IsValidMinionId(id string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(id)
}

func IsValidSettingId(id string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9\*\/:_.-]+$`).MatchString(id)
}
