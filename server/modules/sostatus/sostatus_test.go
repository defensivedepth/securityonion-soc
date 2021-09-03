// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package sostatus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSoStatusInit(tester *testing.T) {
	status := NewSoStatus(nil)
	cfg := make(map[string]interface{})
	cfg["refreshIntervalMs"] = float64(1000)
	cfg["offlineThresholdMs"] = float64(2000)
	err := status.Init(cfg)
	if assert.Nil(tester, err) {
		assert.Equal(tester, 1000, status.refreshIntervalMs)
		assert.Equal(tester, 2000, status.offlineThresholdMs)
	}
}
