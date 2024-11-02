// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package osquery

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"gopkg.in/yaml.v3"
)

func TestCheckAutoEnabledSigmaRule(t *testing.T) {
	e := &OsqueryEngine{
		autoEnabledSigmaRules: []string{"securityonion-resources+high", "core+critical"},
	}

	tests := []struct {
		name     string
		ruleset  string
		severity model.Severity
		expected bool
	}{
		{"securityonion-resources rule with high severity, rule enabled", "securityonion-resources", model.SeverityHigh, true},
		{"securityonion-resources rule with high severity upper case, rule enabled", "securityonion-RESOURCES", model.SeverityHigh, true},
		{"core rule with critical severity, rule enabled", "core", model.SeverityCritical, true},
		{"core rule with high severity, rule not enabled", "core", model.SeverityHigh, false},
		{"empty ruleset, high severity, rule not enabled", "", model.SeverityHigh, false},
		{"core ruleset, empty severity, rule not enabled", "core", "", false},
		{"empty ruleset, empty severity, rule not enabled", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := &model.Detection{
				Ruleset:  tt.ruleset,
				Severity: tt.severity,
			}
			checkRulesetEnabled(e, det)
			assert.Equal(t, tt.expected, det.IsEnabled)
		})
	}
}

func TestElastAlertModule(t *testing.T) {
	srv := &server.Server{
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
	}
	mod := NewOsqueryEngine(srv)

	assert.Implements(t, (*module.Module)(nil), mod)
	assert.Implements(t, (*server.DetectionEngine)(nil), mod)

	err := mod.Init(nil)
	assert.NoError(t, err)

	mod.showAiSummaries = false

	err = mod.Start()
	assert.NoError(t, err)

	assert.True(t, mod.IsRunning())

	err = mod.Stop()
	assert.NoError(t, err)

	assert.Equal(t, 1, len(srv.DetectionEngines))
	assert.Same(t, mod, srv.DetectionEngines[model.EngineNameElastAlert])
}

func TestTimeFrame(t *testing.T) {
	tf := TimeFrame{}

	tf.SetWeeks(1)
	assert.Equal(t, 1, *tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetDays(1)
	assert.Nil(t, tf.Weeks)
	assert.Equal(t, 1, *tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetHours(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Equal(t, 1, *tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetMinutes(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Equal(t, 1, *tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetSeconds(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Equal(t, 1, *tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetMilliseconds(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Equal(t, 1, *tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetSchedule("0 0 0 * * *")
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Equal(t, "0 0 0 * * *", *tf.Schedule)

	tf.Schedule = nil // everything is now nil

	yml, err := yaml.Marshal(tf)
	assert.NoError(t, err)
	assert.Equal(t, "0\n", string(yml))

	err = yaml.Unmarshal(yml, &tf)
	assert.NoError(t, err)
	assert.Empty(t, tf)

	tf.SetWeeks(1)

	yml, err = yaml.Marshal(tf)
	assert.NoError(t, err)
	assert.Equal(t, "weeks: 1\n", string(yml))

	err = yaml.Unmarshal(yml, &tf)
	assert.NoError(t, err)
	assert.Equal(t, 1, *tf.Weeks)
}

func TestSigmaToElastAlertError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("Error: something went wrong"), 1, time.Duration(0), errors.New("non-zero return"))

	engine := OsqueryEngine{
		IOManager: iom,
	}

	det := &model.Detection{
		Auditable: model.Auditable{
			Id: "00000000-0000-0000-0000-000000000000",
		},
		Content:  "totally good sigma",
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.Empty(t, query)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "problem with sigma cli")
}

func TestParseRepoRules(t *testing.T) {
	t.Parallel()

	data := `title: Security Onion - SOC Login Failure
id: bf86ef21-41e6-417b-9a05-b9ea6bf28a38
status: experimental
description: Detects when a user fails to login to the Security Onion Console (Web UI). Review associated logs for target username and source IP.
author: Security Onion Solutions
date: 2024/03/06
logsource:
    product: kratos
    service: audit
detection:
    selection:
        msg: Encountered self-service login error.
    condition: selection
falsepositives:
    - none
level: high
license: Elastic-2.0
`

	repos := []*detections.RepoOnDisk{
		{
			Repo: &model.RuleRepo{
				Repo:      "github.com/repo-user/repo-path",
				License:   "DRL",
				Community: true,
			},
			Path: "repo-path",
		},
	}

	iom := mock.NewMockIOManager(gomock.NewController(t))
	iom.EXPECT().WalkDir(gomock.Eq("repo-path"), gomock.Any()).DoAndReturn(func(path string, fn fs.WalkDirFunc) error {
		return fn("rules/so_soc_failed_login.yml", &handmock.MockDirEntry{
			Filename: "so_soc_failed_login.yml",
		}, nil)
	})
	iom.EXPECT().ReadFile(gomock.Eq("rules/so_soc_failed_login.yml")).Return([]byte(data), nil)

	engine := OsqueryEngine{
		isRunning: true,
		IOManager: iom,
	}

	expected := &model.Detection{
		Author:      "Security Onion Solutions",
		PublicID:    "bf86ef21-41e6-417b-9a05-b9ea6bf28a38",
		Title:       "Security Onion - SOC Login Failure",
		Severity:    model.SeverityHigh,
		Content:     data,
		Description: "Detects when a user fails to login to the Security Onion Console (Web UI). Review associated logs for target username and source IP.",
		IsCommunity: true,
		Product:     "kratos",
		Service:     "audit",
		Engine:      model.EngineNameElastAlert,
		Language:    model.SigLangSigma,
		Ruleset:     "repo-path",
		License:     model.LicenseDRL,
	}

	dets, errMap := engine.parseRepoRules(repos)
	assert.Nil(t, errMap)
	assert.Len(t, dets, 1)
	assert.Equal(t, expected, dets[0])
}

const (
	SimpleRuleSID = "bcc6f179-11cd-4111-a9a6-0fab68515cf7"
	SimpleRule    = `title: Griffon Malware Attack Pattern
id: bcc6f179-11cd-4111-a9a6-0fab68515cf7
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely
level: critical`
	SimpleRuleNoId = `title: Griffon Malware Attack Pattern
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely
level: critical`
	SimpleRuleNoExtract = `title: Required
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely`
	SimpleRule2SID = "19aa1142-94dc-43ef-af58-9b31406dcdc9"
	SimpleRule2    = `title: Griffon Malware Attack Pattern
id: 19aa1142-94dc-43ef-af58-9b31406dcdc9
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely
level: critical`
)

func TestSyncElastAlert(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name           string
		Detections     []*model.Detection
		InitMock       func(*OsqueryEngine, *mock.MockIOManager)
		ExpectedErr    error
		ExpectedErrMap map[string]string
	}{
		{
			Name: "Enable New Simple Rule",
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
					Title:     "TEST",
					Severity:  model.SeverityMedium,
				},
			},
			InitMock: func(mod *OsqueryEngine, m *mock.MockIOManager) {
				// IndexExistingRules
				m.EXPECT().ReadDir(mod.elastAlertRulesFolder).Return([]fs.DirEntry{}, nil)
				// sigmaToElastAlert
				m.EXPECT().ExecCommand(gomock.Any()).Return([]byte("[sigma rule]"), 0, time.Duration(0), nil)
				// WriteFile when enabling
				m.EXPECT().WriteFile(SimpleRuleSID+".yml", []byte("detection_title: TEST\ndetection_public_id: "+SimpleRuleSID+"\nevent.module: sigma\nevent.dataset: sigma.alert\nevent.severity: 3\nsigma_level: medium\nalert:\n    - modules.so.securityonion-es.SecurityOnionESAlerter\nindex: .ds-logs-*\nname: TEST -- "+SimpleRuleSID+"\nrealert:\n    seconds: 0\ntype: any\nfilter:\n    - eql: '[sigma rule]'\n"), fs.FileMode(0644)).Return(nil)
			},
		},
		{
			Name: "Disable Simple Rule",
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					IsEnabled: false,
				},
			},
			InitMock: func(mod *OsqueryEngine, m *mock.MockIOManager) {
				// IndexExistingRules
				filename := SimpleRuleSID + ".yml"
				m.EXPECT().ReadDir(mod.elastAlertRulesFolder).Return([]fs.DirEntry{
					&handmock.MockDirEntry{
						Filename: filename,
					},
					&handmock.MockDirEntry{
						Filename: "ignored_dir",
						Dir:      true,
					},
					&handmock.MockDirEntry{
						Filename: "ignored.txt",
					},
				}, nil)
				// DeleteFile when disabling
				m.EXPECT().DeleteFile(filename).Return(nil)
			},
		},
		{
			Name: "Enable Rule w/Override",
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
					Title:     "TEST",
					Severity:  model.SeverityMedium,
					Overrides: []*model.Override{
						{
							Type:      model.OverrideTypeCustomFilter,
							IsEnabled: false,
							OverrideParameters: model.OverrideParameters{
								CustomFilter: util.Ptr(`sofilter_users:
	user.name: SA_ITOPS
sofilter_hosts:
	host.name|contains:
		- devops
		- sysadmin`),
							},
						},
					},
				},
			},
			InitMock: func(mod *OsqueryEngine, m *mock.MockIOManager) {
				// IndexExistingRules
				m.EXPECT().ReadDir(mod.elastAlertRulesFolder).Return([]fs.DirEntry{}, nil)
				// sigmaToElastAlert
				m.EXPECT().ExecCommand(gomock.Any()).Return([]byte(`any where process.command_line:"*\\local\\temp\\*" and process.command_line:"*//b /e:jscript*" and process.command_line:"*.txt*"`), 0, time.Duration(0), nil)
				// WriteFile when enabling
				m.EXPECT().WriteFile(SimpleRuleSID+".yml", []byte("detection_title: TEST\ndetection_public_id: "+SimpleRuleSID+"\nevent.module: sigma\nevent.dataset: sigma.alert\nevent.severity: 3\nsigma_level: medium\nalert:\n    - modules.so.securityonion-es.SecurityOnionESAlerter\nindex: .ds-logs-*\nname: TEST -- "+SimpleRuleSID+"\nrealert:\n    seconds: 0\ntype: any\nfilter:\n    - eql: any where process.command_line:\"*\\\\local\\\\temp\\\\*\" and process.command_line:\"*//b /e:jscript*\" and process.command_line:\"*.txt*\"\n"), fs.FileMode(0644)).Return(nil)
			},
		},
	}

	ctx := context.Background()

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := mock.NewMockIOManager(ctrl)

			mod := NewOsqueryEngine(&server.Server{
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
			})

			mod.IOManager = mockIO
			mod.srv.DetectionEngines[model.EngineNameElastAlert] = mod

			if test.InitMock != nil {
				test.InitMock(mod, mockIO)
			}

			errMap, err := mod.SyncLocalDetections(ctx, test.Detections)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)
		})
	}
}

func TestExtractDetails(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name             string
		Input            string
		ExpectedErr      *string
		ExpectedTitle    string
		ExpectedPublicID string
		ExpectedSeverity model.Severity
	}{
		{
			Name:             "Simple Extraction",
			Input:            SimpleRule,
			ExpectedTitle:    "Griffon Malware Attack Pattern",
			ExpectedPublicID: SimpleRuleSID,
			ExpectedSeverity: model.SeverityCritical,
		},
		{
			Name:        "No Public Id",
			Input:       SimpleRuleNoId,
			ExpectedErr: util.Ptr("missing required fields: id"),
		},
		{
			Name:             "Minimal Extracted Values, No Error",
			Input:            SimpleRuleNoExtract,
			ExpectedTitle:    "Required",
			ExpectedPublicID: "00000000-0000-0000-0000-000000000000",
			ExpectedSeverity: model.SeverityUnknown,
		},
	}

	eng := &OsqueryEngine{}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			detect := &model.Detection{
				Content: test.Input,
			}

			err := eng.ExtractDetails(detect)
			if test.ExpectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, *test.ExpectedErr, err.Error())
			}

			assert.Equal(t, test.ExpectedTitle, detect.Title)
			assert.Equal(t, test.ExpectedPublicID, detect.PublicID)
			assert.Equal(t, test.ExpectedSeverity, detect.Severity)
		})
	}
}

func TestGetDeployedPublicIds(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	path := "path"

	iom.EXPECT().ReadDir(path).Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "00000000-0000-0000-0000-000000000000.yml",
		},
		&handmock.MockDirEntry{
			Filename: "11111111-1111-1111-1111-111111111111.yaml",
		},
		&handmock.MockDirEntry{
			Filename: "ignored_dir",
			Dir:      true,
		},
		&handmock.MockDirEntry{
			Filename: "ignored.txt",
		},
	}, nil)

	eng := &OsqueryEngine{
		elastAlertRulesFolder: path,
		IOManager:             iom,
	}

	ids, err := eng.getDeployedPublicIds()
	assert.NoError(t, err)

	assert.Len(t, ids, 2)
	assert.Contains(t, ids, "00000000-0000-0000-0000-000000000000")
	assert.Contains(t, ids, "11111111-1111-1111-1111-111111111111")
}

func TestSyncWriteNoReadFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "123").Return(nil, errors.New("Object not found"))

	wnr := util.Ptr("123")

	eng := &OsqueryEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		writeNoRead: wnr,
	}

	logger := log.WithField("detectionEngine", "test-elastalert")

	err := eng.Sync(logger, false)
	assert.Equal(t, detections.ErrSyncFailed, err)
	assert.Equal(t, wnr, eng.writeNoRead)
}

func TestSyncIncrementalNoChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	buf := bytes.NewBuffer([]byte{})

	writer := zip.NewWriter(buf)
	sr, err := writer.Create("rules/simple_rule.yml")
	assert.NoError(t, err)

	_, err = sr.Write([]byte(SimpleRule))
	assert.NoError(t, err)

	assert.NoError(t, writer.Close())

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	eng := &OsqueryEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		isRunning:                     true,
		sigmaPipelineFinal:            "sigmaPipelineFinal",
		sigmaPipelineSO:               "sigmaPipelineSO",
		sigmaPipelinesFingerprintFile: "sigmaPipelinesFingerprintFile",
		reposFolder:                   "repos",
		rulesFingerprintFile:          "rulesFingerprintFile",
		elastAlertRulesFolder:         "elastAlertRulesFolder",
		rulesRepos: []*model.RuleRepo{
			{
				Repo:      "https://github.com/user/repo",
				Community: true,
			},
		},
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:       iom,
		showAiSummaries: false,
	}

	logger := log.WithField("detectionEngine", "test-elastalert")

	// checkSigmaPipelines
	iom.EXPECT().ReadFile("sigmaPipelineFinal").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelineSO").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelinesFingerprintFile").Return([]byte("3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7-3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"), nil)
	// downloadSigmaPackages
	iom.EXPECT().MakeRequest(gomock.Any()).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(buf),
	}, nil)
	// UpdateRepos
	iom.EXPECT().ReadDir("repos").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "repos/repo", nil).Return(false, false)
	// check for changes before sync
	iom.EXPECT().ReadFile("rulesFingerprintFile").Return([]byte(`{"core+": "c6OTI9nTQxGEeeNkSZZB9+OESMNvfMXrb+XLtMiVhf0="}`), nil)
	// WriteStateFile
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRuleSID + ".yml",
		},
	}, nil) // getDeployedPublicIds
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: nil,
	}, nil)

	err = eng.Sync(logger, false)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
}

func TestSyncChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	buf := bytes.NewBuffer([]byte{})

	writer := zip.NewWriter(buf)
	sr, err := writer.Create("rules/simple_rule.yml")
	assert.NoError(t, err)

	_, err = sr.Write([]byte(SimpleRule))
	assert.NoError(t, err)

	assert.NoError(t, writer.Close())

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	auditm := servermock.NewMockBulkIndexer(ctrl)

	eng := &OsqueryEngine{
		srv: &server.Server{
			Context:        context.Background(),
			Detectionstore: detStore,
		},
		isRunning:                     true,
		sigmaPipelineFinal:            "sigmaPipelineFinal",
		sigmaPipelineSO:               "sigmaPipelineSO",
		sigmaPipelinesFingerprintFile: "sigmaPipelinesFingerprintFile",
		reposFolder:                   "repos",
		rulesFingerprintFile:          "rulesFingerprintFile",
		elastAlertRulesFolder:         "elastAlertRulesFolder",
		rulesRepos: []*model.RuleRepo{
			{
				Repo:      "https://github.com/user/repo",
				Community: true,
			},
		},
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:       iom,
		showAiSummaries: false,
	}

	logger := log.WithField("detectionEngine", "test-elastalert")

	workItems := []esutil.BulkIndexerItem{}
	auditItems := []esutil.BulkIndexerItem{}

	// checkSigmaPipelines
	iom.EXPECT().ReadFile("sigmaPipelineFinal").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelineSO").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelinesFingerprintFile").Return([]byte("a different hash"), nil)
	// downloadSigmaPackages
	iom.EXPECT().MakeRequest(gomock.Any()).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(buf),
	}, nil)
	// UpdateRepos
	iom.EXPECT().ReadDir("repos").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "repos/repo", nil).Return(false, false)
	// parseRepoRules
	iom.EXPECT().WalkDir("repos/repo", gomock.Any()).DoAndReturn(func(path string, fn fs.WalkDirFunc) error {
		files := []fs.DirEntry{
			&handmock.MockDirEntry{
				Filename: "rules/123.yml",
			},
			&handmock.MockDirEntry{
				Filename: "rules/456.yml",
			},
		}

		for _, file := range files {
			err := fn(file.Name(), file, nil)
			assert.NoError(t, err)
		}

		return nil
	})
	iom.EXPECT().ReadFile("rules/123.yml").Return([]byte(SimpleRule), nil)
	iom.EXPECT().ReadFile("rules/456.yml").Return([]byte(SimpleRule2), nil)
	// syncCommunityDetections
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRuleSID + ".yml",
		},
		&handmock.MockDirEntry{
			Filename: "00000000-0000-0000-0000-000000000000.yml",
		},
	}, nil) // IndexExistingRules
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: {
			Auditable: model.Auditable{
				Id:         "abc",
				CreateTime: util.Ptr(time.Now()),
			},
			PublicID:  SimpleRuleSID,
			IsEnabled: true,
		},
		"00000000-0000-0000-0000-000000000000": {
			Auditable: model.Auditable{
				Id: "deleteme",
			},
			PublicID: "00000000-0000-0000-0000-000000000000",
		},
	}, nil)
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil).Times(3)
	bim.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: "id",
			}
			item.OnSuccess(ctx, item, resp)
		}

		workItems = append(workItems, item)

		return nil
	}).Times(3)
	iom.EXPECT().DeleteFile("elastAlertRulesFolder/00000000-0000-0000-0000-000000000000.yml").Return(nil)
	bim.EXPECT().Close(gomock.Any()).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
	iom.EXPECT().ExecCommand(gomock.Any()).Return([]byte("\n[query]"), 0, time.Duration(time.Second), nil) // sigmaToElastAlert
	iom.EXPECT().WriteFile("elastAlertRulesFolder/bcc6f179-11cd-4111-a9a6-0fab68515cf7.yml", gomock.Any(), fs.FileMode(0644)).Return(nil)
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditm, nil)
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("document"), "index", nil).Times(3)
	auditm.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: "id",
			}
			item.OnSuccess(ctx, item, resp)
		}

		auditItems = append(auditItems, item)

		return nil
	}).Times(3)
	auditm.EXPECT().Close(gomock.Any()).Return(nil)
	auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
	// SyncLocalDetections
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRule2SID: {
			PublicID: SimpleRule2SID,
		},
	}, nil)
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRule2SID + ".yml",
		},
	}, nil) // IndexExistingRules
	iom.EXPECT().DeleteFile("elastAlertRulesFolder/" + SimpleRule2SID + ".yml").Return(nil)
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)        // WriteStateFile
	iom.EXPECT().WriteFile("rulesFingerprintFile", gomock.Any(), fs.FileMode(0644)).Return(nil) // WriteFingerprintFile
	// regenNeeded
	iom.EXPECT().WriteFile("sigmaPipelinesFingerprintFile", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRuleSID + ".yml",
		},
	}, nil) // getDeployedPublicIds
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: nil,
	}, nil)

	err = eng.Sync(logger, true)
	assert.NoError(t, err)

	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)

	assert.Len(t, workItems, 3)
	assert.Len(t, auditItems, 3)

	workActions := lo.Map(workItems, func(item esutil.BulkIndexerItem, _ int) string {
		return item.Action
	})

	auditActions := lo.Map(auditItems, func(item esutil.BulkIndexerItem, _ int) string {
		return item.Action
	})

	assert.Equal(t, []string{"update", "create", "delete"}, workActions)
	assert.Equal(t, []string{"create", "create", "create"}, auditActions)

	workDocIds := lo.Map(workItems, func(item esutil.BulkIndexerItem, _ int) string {
		return item.DocumentID
	})

	assert.Equal(t, []string{"abc", "", "deleteme"}, workDocIds) // update has an id, create does not, delete does
}

func TestLoadAndMergeAuxiliaryData(t *testing.T) {
	tests := []struct {
		Name              string
		PublicId          string
		Content           string
		ExpectedAiFields  bool
		ExpectedAiSummary string
		ExpectedReviewed  bool
		ExpectedStale     bool
	}{
		{
			Name:             "No Auxiliary Data",
			PublicId:         "bd82a1a6-7bac-401e-afcf-5adf07c0c035",
			ExpectedAiFields: false,
		},
		{
			Name:              "Data, Unreviewed",
			PublicId:          "67ee455d-099f-4048-b021-43bb91af9298",
			Content:           "alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for 67ee455d-099f-4048-b021-43bb91af9298",
			ExpectedReviewed:  false,
			ExpectedStale:     false,
		},
		{
			Name:              "Data, Reviewed",
			PublicId:          "83b3a29f-3009-4884-86c6-b6c3973788fa",
			Content:           "no-alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for 83b3a29f-3009-4884-86c6-b6c3973788fa",
			ExpectedReviewed:  true,
			ExpectedStale:     true,
		},
	}

	e := OsqueryEngine{
		showAiSummaries: true,
	}
	err := e.LoadAuxiliaryData([]*model.AiSummary{
		{
			PublicId:     "83b3a29f-3009-4884-86c6-b6c3973788fa",
			Summary:      "Summary for 83b3a29f-3009-4884-86c6-b6c3973788fa",
			Reviewed:     true,
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
		},
		{
			PublicId:     "67ee455d-099f-4048-b021-43bb91af9298",
			Summary:      "Summary for 67ee455d-099f-4048-b021-43bb91af9298",
			Reviewed:     false,
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
		},
	})
	assert.NoError(t, err)

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			det := &model.Detection{
				PublicID: test.PublicId,
				Content:  test.Content,
			}

			e.showAiSummaries = true
			err := e.MergeAuxiliaryData(det)
			assert.NoError(t, err)
			if test.ExpectedAiFields {
				assert.NotNil(t, det.AiFields)
				assert.Equal(t, test.ExpectedAiSummary, det.AiSummary)
				assert.Equal(t, test.ExpectedReviewed, det.AiSummaryReviewed)
				assert.Equal(t, test.ExpectedStale, det.IsAiSummaryStale)
			} else {
				assert.Nil(t, det.AiFields)
			}

			e.showAiSummaries = false
			det.AiFields = nil

			err = e.MergeAuxiliaryData(det)
			assert.NoError(t, err)
			assert.Nil(t, det.AiFields)
		})
	}
}
