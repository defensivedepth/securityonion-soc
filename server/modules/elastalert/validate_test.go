// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
)

func TestParseRule(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name          string
		Input         string
		ExpectedError *string
	}{
		{
			Name:          "Empty Rule",
			Input:         `{}`,
			ExpectedError: util.Ptr("missing required fields: title, logsource, detection.condition"),
		},
		{
			Name:          "Detection but No Condition",
			Input:         `{ title: "title", logsource: { category: "test" }, detection: {}}`,
			ExpectedError: util.Ptr("missing required fields: detection.condition"),
		},
		{
			Name:  "Minimal Rule With Single Detection Condition",
			Input: `{ title: "title", logsource: { category: "test" }, detection: { condition: "condition" }}`,
		},
		{
			Name:  "Minimal Rule With Multiple Detection Condition",
			Input: `{ title: "title", logsource: { category: "test" }, detection: { condition: [ "conditionOne", "conditionTwo" ] }}`,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseElastAlertRule([]byte(test.Input))
			if test.ExpectedError == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, *test.ExpectedError, err.Error())
			}
		})
	}
}