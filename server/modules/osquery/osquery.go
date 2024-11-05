// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package osquery

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/kennygrant/sanitize"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_AIRGAP_BASE_PATH                         = "/nsm/rules/detect-osquery/rulesets/"
	DEFAULT_ALLOW_REGEX                              = ""
	DEFAULT_DENY_REGEX                               = ""
	DEFAULT_AIRGAP_ENABLED                           = false
	DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECONDS = 86400
	DEFAULT_ELASTALERT_RULES_FOLDER                  = "/opt/sensoroni/elastalert"
	DEFAULT_RULES_FINGERPRINT_FILE                   = "/opt/sensoroni/fingerprints/osquery.fingerprint"
	DEFAULT_SIGMA_PIPELINES_FINGERPRINT_FILE         = "/opt/sensoroni/fingerprints/osquery.pipelines.fingerprint"
	DEFAULT_REPOS_FOLDER                             = "/opt/sensoroni/sigma/repos"
	DEFAULT_STATE_FILE_PATH                          = "/opt/sensoroni/fingerprints/elastalertengine.state"
	DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS        = 300
	DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT       = 10
	DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS        = 600
	DEFAULT_AI_REPO                                  = "https://github.com/Security-Onion-Solutions/securityonion-resources"
	DEFAULT_AI_REPO_BRANCH                           = "generated-summaries-published"
	DEFAULT_AI_REPO_PATH                             = "/opt/sensoroni/ai_summary_repos"
	DEFAULT_SHOW_AI_SUMMARIES                        = true
)

var ( // treat as constant
	DEFAULT_RULES_REPOS = []*model.RuleRepo{
		{
			Repo:    "https://github.com/Security-Onion-Solutions/securityonion-resources",
			License: "DRL",
			Folder:  util.Ptr("sigma/stable"),
		},
	}
)

var acceptedExtensions = map[string]bool{
	".yml":  true,
	".yaml": true,
}

type OsqueryEngine struct {
	srv                            *server.Server
	airgapBasePath                 string
	failAfterConsecutiveErrorCount int
	elastAlertRulesFolder          string
	rulesFingerprintFile           string
	//autoEnabledSigmaRules              []string
	rulesRepos      []*model.RuleRepo
	reposFolder     string
	isRunning       bool
	interm          sync.Mutex
	airgapEnabled   bool
	notify          bool
	writeNoRead     *string
	aiSummaries     *sync.Map // map[string]*detections.AiSummary{}
	showAiSummaries bool
	aiRepoUrl       string
	aiRepoBranch    string
	aiRepoPath      string
	detections.SyncSchedulerParams
	detections.IntegrityCheckerData
	detections.IOManager
	model.EngineState
}

//func checkRulesetEnabled(e *OsqueryEngine, det *model.Detection) {
//	det.IsEnabled = false
//	if det.Ruleset == "" || det.Severity == "" {
//		return
//	}

// Combine Ruleset and Severity into a single string
//	metaCombined := det.Ruleset + "+" + string(det.Severity)
//	for _, rule := range e.autoEnabledSigmaRules {
//		if strings.EqualFold(rule, metaCombined) {
//			det.IsEnabled = true
//			break
//		}
//	}
//}

func NewOsqueryEngine(srv *server.Server) *OsqueryEngine {
	engine := &OsqueryEngine{
		srv: srv,
	}

	resMan := &detections.ResourceManager{Config: srv.Config}
	engine.IOManager = resMan

	return engine
}

func (e *OsqueryEngine) PrerequisiteModules() []string {
	return nil
}

func (e *OsqueryEngine) GetState() *model.EngineState {
	return util.Ptr(e.EngineState)
}

func (e *OsqueryEngine) Init(config module.ModuleConfig) (err error) {
	e.SyncThread = &sync.WaitGroup{}
	e.InterruptChan = make(chan bool, 1)
	e.IntegrityCheckerData.Thread = &sync.WaitGroup{}
	e.IntegrityCheckerData.Interrupt = make(chan bool, 1)
	e.aiSummaries = &sync.Map{}

	e.airgapBasePath = module.GetStringDefault(config, "airgapBasePath", DEFAULT_AIRGAP_BASE_PATH)
	e.CommunityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECONDS)
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", DEFAULT_RULES_FINGERPRINT_FILE)
	e.CommunityRulesImportErrorSeconds = module.GetIntDefault(config, "communityRulesImportErrorSeconds", DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS)
	e.failAfterConsecutiveErrorCount = module.GetIntDefault(config, "failAfterConsecutiveErrorCount", DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT)

	e.IntegrityCheckerData.FrequencySeconds = module.GetIntDefault(config, "integrityCheckFrequencySeconds", DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS)

	e.reposFolder = module.GetStringDefault(config, "reposFolder", DEFAULT_REPOS_FOLDER)
	e.rulesRepos, err = model.GetReposDefault(config, "rulesRepos", DEFAULT_RULES_REPOS)
	if err != nil {
		return fmt.Errorf("unable to parse Osquery's rulesRepos: %w", err)
	}

	if e.srv != nil && e.srv.Config != nil {
		e.airgapEnabled = e.srv.Config.AirgapEnabled
	} else {
		e.airgapEnabled = DEFAULT_AIRGAP_ENABLED
	}

	e.SyncSchedulerParams.StateFilePath = module.GetStringDefault(config, "stateFilePath", DEFAULT_STATE_FILE_PATH)

	e.showAiSummaries = module.GetBoolDefault(config, "showAiSummaries", DEFAULT_SHOW_AI_SUMMARIES)
	e.aiRepoUrl = module.GetStringDefault(config, "aiRepoUrl", DEFAULT_AI_REPO)
	e.aiRepoBranch = module.GetStringDefault(config, "aiRepoBranch", DEFAULT_AI_REPO_BRANCH)
	e.aiRepoPath = module.GetStringDefault(config, "aiRepoPath", DEFAULT_AI_REPO_PATH)

	return nil
}

func (e *OsqueryEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameOsquery] = e
	e.isRunning = true
	e.IntegrityCheckerData.IsRunning = true

	// start long running processes
	go detections.SyncScheduler(e, &e.SyncSchedulerParams, &e.EngineState, model.EngineNameOsquery, &e.isRunning, e.IOManager)
	go detections.IntegrityChecker(model.EngineNameOsquery, e, &e.IntegrityCheckerData, &e.EngineState.IntegrityFailure)

	// update Ai Summaries once and don't block
	if e.showAiSummaries {
		go func() {
			logger := log.WithField("detectionEngine", model.EngineNameOsquery)

			err := detections.RefreshAiSummaries(e, model.SigLangSigma, &e.isRunning, e.aiRepoPath, e.aiRepoUrl, e.aiRepoBranch, logger, e.IOManager)
			if err != nil {
				if errors.Is(err, detections.ErrModuleStopped) {
					return
				}

				logger.WithError(err).Error("unable to refresh AI summaries")
			} else {
				logger.Info("successfully refreshed AI summaries")
			}
		}()
	}

	return nil
}

func (e *OsqueryEngine) Stop() error {
	e.isRunning = false

	e.InterruptSync(false, false)
	e.SyncSchedulerParams.SyncThread.Wait()
	e.PauseIntegrityChecker()
	e.interruptIntegrityCheck()
	e.IntegrityCheckerData.Thread.Wait()

	return nil
}

func (e *OsqueryEngine) InterruptSync(fullUpgrade bool, notify bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = notify

	if len(e.InterruptChan) == 0 {
		e.InterruptChan <- fullUpgrade
	}
}

func (e *OsqueryEngine) resetInterruptSync() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.InterruptChan) != 0 {
		<-e.InterruptChan
	}
}

func (e *OsqueryEngine) interruptIntegrityCheck() {
	e.interm.Lock()
	defer e.interm.Unlock()

	if len(e.IntegrityCheckerData.Interrupt) == 0 {
		e.IntegrityCheckerData.Interrupt <- true
	}
}

func (e *OsqueryEngine) PauseIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = false
}

func (e *OsqueryEngine) ResumeIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = true
}

func (e *OsqueryEngine) IsRunning() bool {
	return e.isRunning
}

func (e *OsqueryEngine) ValidateRule(data string) (string, error) {
	_, err := ParseOsqueryRule([]byte(data))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *OsqueryEngine) ApplyFilters(detect *model.Detection) (bool, error) {
	return false, nil
}

func (e *OsqueryEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
	return e.sigmaToOsquery(ctx, detect)
}

func (e *OsqueryEngine) ExtractDetails(detect *model.Detection) error {
	rule, err := ParseOsqueryRule([]byte(detect.Content))
	if err != nil {
		return err
	}

	if rule.ID != nil {
		detect.PublicID = *rule.ID
	}

	if detect.PublicID == "" {
		return fmt.Errorf("rule does not contain a public Id")
	}

	if rule.Description != nil {
		detect.Description = *rule.Description
	}

	if rule.Level != nil {
		switch strings.ToLower(string(*rule.Level)) {
		case "informational":
			detect.Severity = model.SeverityInformational
		case "low":
			detect.Severity = model.SeverityLow
		case "medium":
			detect.Severity = model.SeverityMedium
		case "high":
			detect.Severity = model.SeverityHigh
		case "critical":
			detect.Severity = model.SeverityCritical
		default:
			detect.Severity = model.SeverityUnknown
		}
	} else {
		detect.Severity = model.SeverityUnknown
	}

	if rule.Title != "" {
		detect.Title = rule.Title
	} else {
		detect.Title = "Detection title not yet provided - click here to update this title"
	}

	if rule.Author != nil {
		detect.Author = *rule.Author
	}

	return nil
}

func (e *OsqueryEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	errMap = map[string]string{} // map[publicID]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for _, det := range detections {
		log.Info(det.Title)
		if det.IsEnabled {

			client := NewClient("http://sa-upgradetest-jb:5601", "so_elastic", "+A;hhx>.w8~RGsa)mHm>esA43*4Q#N:(V?=o[nl6?@uMk8g;l0Z>-hc9AB5L1t1S+ao>vZf|")

			packName := "All-Hosts"
			packID, err := client.CheckIfPackExists(packName)
			if err != nil {
				client.Logger.Errorf("Error checking if pack exists: %s", err)

			}

			if packID == "" {

				packData := PackData{
					Name:        "All-Hosts",
					Description: "This is a test pack",
					Enabled:     true,
					PolicyIDs:   []string{"so-grid-nodes_general"},
					Queries: map[string]Query{
						det.PublicID: {
							Query:    "SELECT * FROM listening_ports;",
							Interval: 60,
							Timeout:  120,
							ECSMapping: map[string]ECSMap{
								"client.port": {Field: "port"},
								"tags":        {Value: []string{"tag1", "tag2"}},
							},
						},
					},
				}

				// Log the pack data to verify its structure
				client.Logger.Infof("Pack data being sent: %+v", packData)

				err = client.CreatePack(packData)
				if err != nil {
					client.Logger.Errorf("Error creating pack: %s", err)
				}

			} else {
				client.Logger.Infof("Pack %s exists with ID %s, adding new query...", packName, packID)
				newQuery := Query{
					Query:    "SELECT * FROM processes WHERE name = 'nginx';",
					Interval: 120,
					Timeout:  30,
				}
				err = client.AddQueryToPack(packID, det.PublicID, newQuery)
				if err != nil {
					client.Logger.Errorf("Error adding query to pack: %s", err)
				}
			}

		} else {
			// was enabled, no longer is enabled: Disable
			// TODO - Remove query from Pack
			log.Info("osquery - TODO")
		}
	}

	return errMap, nil
}

func (e *OsqueryEngine) Sync(logger *log.Entry, forceSync bool) error {
	defer func() {
		e.resetInterruptSync()
	}()

	// handle write/no-read
	if e.writeNoRead != nil {
		if detections.CheckWriteNoRead(e.srv.Context, e.srv.Detectionstore, e.writeNoRead) {
			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameOsquery,
					Status: "error",
				})
			}

			return detections.ErrSyncFailed
		}
	}

	e.writeNoRead = nil

	if e.showAiSummaries {
		err := detections.RefreshAiSummaries(e, model.SigLangSigma, &e.isRunning, e.aiRepoPath, e.aiRepoUrl, e.aiRepoBranch, logger, e.IOManager)
		if err != nil {
			if errors.Is(err, detections.ErrModuleStopped) {
				return err
			}

			logger.WithError(err).Error("unable to refresh AI summaries")
		} else {
			logger.Info("successfully refreshed AI summaries")
		}
	}

	// announce the beginning of the sync
	e.EngineState.Syncing = true

	var errMap map[string]error

	// ensure repos are up to date
	dirtyRepos, repoChanges, err := detections.UpdateRepos(&e.isRunning, e.reposFolder, e.rulesRepos, e.IOManager)
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			return err
		}

		logger.WithError(err).Error("unable to update Osquery repos")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameOsquery,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	if !forceSync {
		// if we're not forcing a sync, check to see if anything has changed
		// if nothing has changed, the sync is finished
		raw, err := e.ReadFile(e.rulesFingerprintFile)
		if err != nil && !os.IsNotExist(err) {
			logger.WithError(err).WithField("fingerprintPath", e.rulesFingerprintFile).Error("unable to read rules fingerprint file")

			return detections.ErrSyncFailed
		}

		oldHashes := map[string]string{}

		err = json.Unmarshal(raw, &oldHashes)
		if err != nil {
			logger.WithError(err).Error("unable to unmarshal rules fingerprint file")

			return detections.ErrSyncFailed
		}

		if !repoChanges {
			// only an exact match means no work needs to be done.
			// If there's extra hashes in the old file, we need to remove them.
			// If there's extra hashes in the new file, we need to add them.
			// If there's a mix of new and old hashes, we need to include them all
			// or the old ones would be removed.
			logger.Info("community rule sync found no changes")

			detections.WriteStateFile(e.IOManager, e.StateFilePath)

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameOsquery,
					Status: "success",
				})
			}

			_, _, err = e.IntegrityCheck(false, logger)

			e.EngineState.IntegrityFailure = err != nil

			if err != nil {
				logger.WithError(err).Error("post-sync integrity check failed")
			} else {
				logger.Info("post-sync integrity check passed")
			}

			// a non-forceSync sync that found no changes is a success
			return nil
		}
	}

	if !e.isRunning {
		return detections.ErrModuleStopped
	}

	if errors.Is(errMap["module"], detections.ErrModuleStopped) || !e.isRunning {
		return detections.ErrModuleStopped
	}

	detects, errMap := e.parseRepoRules(dirtyRepos)
	if errMap != nil {
		logger.WithField("sigmaParseError", errMap).Error("something went wrong while parsing sigma rule files from repos")
	}

	if errors.Is(errMap["module"], detections.ErrModuleStopped) || !e.isRunning {
		return detections.ErrModuleStopped
	}

	detects = detections.DeduplicateByPublicId(detects)

	errMap, err = e.syncCommunityDetections(e.srv.Context, logger, detects)
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			logger.Info("incomplete sync of osquery community detections due to module stopping")
			return err
		}

		if err.Error() == "Object not found" {
			// errMap contains exactly 1 error: the publicId of the detection that
			// was written to but not read back
			for publicId := range errMap {
				e.writeNoRead = util.Ptr(publicId)
			}
		}

		logger.WithError(err).Error("unable to sync osquery community detections")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameOsquery,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	localrules, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameOsquery), model.WithCommunity(false))
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			return err
		}

		logger.WithError(err).Error("unable to get local detections")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameOsquery,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	if len(localrules) > 0 {
		local := make([]*model.Detection, 0, len(localrules))
		for _, det := range localrules {
			local = append(local, det)
		}

		errMapLocal, err := e.SyncLocalDetections(e.srv.Context, local)
		if err != nil {
			if errors.Is(err, detections.ErrModuleStopped) {
				return err
			}

			logger.WithError(err).Error("unable to sync local detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameOsquery,
					Status: "error",
				})
			}

			return detections.ErrSyncFailed
		}

		for publicID, err := range errMapLocal {
			errMap[publicID] = errors.New(err)
		}
	}

	detections.WriteStateFile(e.IOManager, e.StateFilePath)

	if len(errMap) > 0 {
		// there were errors, don't save the fingerprint.
		// idempotency means we might fix it if we try again later.
		logger.WithField("elastAlertSyncErrors", detections.TruncateMap(errMap, 5)).Error("unable to sync all Osquery community detections")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameOsquery,
				Status: "partial",
			})
		}
	} else {
		zipHashes := "TODO"
		fingerprints, err := json.Marshal(zipHashes)
		if err != nil {
			logger.WithError(err).Error("unable to marshal rules fingerprints")
		} else {
			err = e.WriteFile(e.rulesFingerprintFile, fingerprints, 0644)
			if err != nil {
				logger.WithError(err).WithField("fingerprintPath", e.rulesFingerprintFile).Error("unable to write rules fingerprint file")
			}
		}

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameOsquery,
				Status: "success",
			})
		}

		_, _, err = e.IntegrityCheck(false, logger)

		e.EngineState.IntegrityFailure = err != nil

		if err != nil {
			logger.WithError(err).Error("post-sync integrity check failed")
		} else {
			logger.Info("post-sync integrity check passed")
		}
	}

	return nil
}

func (e *OsqueryEngine) parseRepoRules(allRepos []*detections.RepoOnDisk) (detects []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[repoName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for _, repo := range allRepos {
		if !e.isRunning {
			return nil, map[string]error{"module": detections.ErrModuleStopped}
		}

		baseDir := repo.Path
		if repo.Repo.Folder != nil {
			baseDir = filepath.Join(baseDir, *repo.Repo.Folder)
		}

		err := e.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.WithError(err).WithField("repoPath", path).Error("Failed to walk path")
				return nil
			}

			if !e.isRunning {
				return detections.ErrModuleStopped
			}

			if d.IsDir() {
				return nil
			}

			ext := filepath.Ext(d.Name())
			if strings.ToLower(ext) != ".yml" && strings.ToLower(ext) != ".yaml" {
				return nil
			}

			raw, err := e.ReadFile(path)
			if err != nil {
				log.WithError(err).WithField("elastAlertRuleFile", path).Error("failed to read elastalert rule file")
				return nil
			}

			rule, err := ParseOsqueryRule(raw)
			if err != nil {
				errMap[path] = err
				return nil
			}

			ruleset := filepath.Base(repo.Path)

			det := rule.ToDetection(ruleset, repo.Repo.License, repo.Repo.Community)

			detects = append(detects, det)

			return nil
		})
		if err != nil {
			log.WithError(err).WithField("elastAlertRuleRepo", repo.Path).Error("Failed to walk repo")
			continue
		}
	}

	return detects, errMap
}

func (e *OsqueryEngine) syncCommunityDetections(ctx context.Context, logger *log.Entry, detects []*model.Detection) (errMap map[string]error, err error) {

	community, err := e.srv.Detectionstore.GetAllDetections(ctx, model.WithEngine(model.EngineNameOsquery), model.WithCommunity(true))
	if err != nil {
		return nil, err
	}

	index := map[string]string{}
	toDelete := map[string]struct{}{} // map[publicID]struct{}
	for _, det := range community {
		toDelete[det.PublicID] = struct{}{}

	}

	results := struct {
		Added     int32
		Updated   int32
		Removed   int32
		Unchanged int32
		Audited   int32
	}{}

	errMap = map[string]error{} // map[publicID]error
	et := detections.NewErrorTracker(e.failAfterConsecutiveErrorCount)

	bulk, err := e.srv.Detectionstore.BuildBulkIndexer(e.srv.Context, logger)
	if err != nil {
		return nil, err
	}

	createAudit := make([]model.AuditInfo, 0, len(detects))
	auditMut := sync.Mutex{}
	errMut := sync.Mutex{}

	for i := range detects {
		detect := detects[i]

		if !e.isRunning {
			return nil, detections.ErrModuleStopped
		}

		delete(toDelete, detect.PublicID)

		logger.WithFields(log.Fields{
			"rule.uuid": detect.PublicID,
			"rule.name": detect.Title,
		}).Info("syncing rule")

		path, ok := index[detect.PublicID]
		if !ok {
			path = index[detect.Title]
		}

		// 1. Save osquery Detection to ElasticSearch
		orig, exists := community[detect.PublicID]
		if exists {
			detect.IsEnabled = orig.IsEnabled
			detect.Id = orig.Id
			detect.Overrides = orig.Overrides
			detect.CreateTime = orig.CreateTime
		} else {
			detect.CreateTime = util.Ptr(time.Now())
			// checkRulesetEnabled(e, detect)
		}

		_, err = e.ApplyFilters(detect)
		if err != nil {
			errMap[detect.PublicID] = err
			continue
		}

		document, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", detect, &detect.Auditable, exists, nil, nil)
		if err != nil {
			errMap[detect.PublicID] = err
			continue
		}

		if exists {
			if orig.Content != detect.Content || orig.Ruleset != detect.Ruleset || len(detect.Overrides) != 0 {
				logger.WithFields(log.Fields{
					"rule.uuid": detect.PublicID,
					"rule.name": detect.Title,
				}).Info("updating Osquery detection")

				err = bulk.Add(ctx, esutil.BulkIndexerItem{
					Index:      index,
					Action:     "update",
					DocumentID: detect.Id,
					Body:       bytes.NewReader(document),
					OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
						auditMut.Lock()
						defer auditMut.Unlock()

						results.Updated++

						createAudit = append(createAudit, model.AuditInfo{
							Detection: detect,
							DocId:     resp.DocumentID,
							Op:        "update",
						})
					},
					OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
						errMut.Lock()
						defer errMut.Unlock()

						if err != nil {
							errMap[detect.PublicID] = err
						} else {
							errMap[detect.PublicID] = errors.New(resp.Error.Reason)
						}
					},
				})
				if err != nil && err.Error() == "Object not found" {
					errMap = map[string]error{
						detect.PublicID: err,
					}

					return errMap, err
				}

				eterr := et.AddError(err)
				if eterr != nil {
					return nil, eterr
				}

				if err != nil {
					errMap[detect.PublicID] = fmt.Errorf("unable to update detection: %s", err)
					continue
				}
			} else {
				results.Unchanged++
			}
		} else {
			// new detection, create it
			logger.WithFields(log.Fields{
				"rule.uuid": detect.PublicID,
				"rule.name": detect.Title,
			}).Info("creating new Osquery detection")

			err = bulk.Add(ctx, esutil.BulkIndexerItem{
				Index:  index,
				Action: "create",
				Body:   bytes.NewReader(document),
				OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
					auditMut.Lock()
					defer auditMut.Unlock()

					results.Added++

					createAudit = append(createAudit, model.AuditInfo{
						Detection: detect,
						DocId:     resp.DocumentID,
						Op:        "create",
					})
				},
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()

					if err != nil {
						errMap[detect.PublicID] = err
					} else {
						errMap[detect.PublicID] = errors.New(resp.Error.Reason)
					}
				},
			})
			if err != nil && err.Error() == "Object not found" {
				errMap = map[string]error{
					detect.PublicID: err,
				}

				return errMap, err
			}

			eterr := et.AddError(err)
			if eterr != nil {
				return nil, eterr
			}

			if err != nil {
				errMap[detect.PublicID] = fmt.Errorf("unable to create detection: %s", err)
				continue
			}
		}

		if detect.IsEnabled {
			// 2. if enabled, send data to cli package to get converted to query
			rule, err := e.sigmaToOsquery(ctx, detect)
			if err != nil {
				errMap[detect.PublicID] = fmt.Errorf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			// 3. put query in elastAlertRulesFolder for salt to pick up
			if path == "" {
				name := sanitize.Name(detect.PublicID)
				path = filepath.Join(e.elastAlertRulesFolder, fmt.Sprintf("%s.yml", name))
			}

			err = e.WriteFile(path, []byte(rule), 0644)
			if err != nil {
				errMap[detect.PublicID] = fmt.Errorf("unable to write enabled detection file: %s", err)
				continue
			}
		} else if path != "" {
			// detection is disabled but a file exists, remove it
			err = e.DeleteFile(path)
			if err != nil {
				errMap[detect.PublicID] = fmt.Errorf("unable to remove disabled detection file: %s", err)
				continue
			}
		}
	}

	for publicId := range toDelete {
		if !e.isRunning {
			return nil, detections.ErrModuleStopped
		}

		id := community[publicId].Id

		_, index, _ := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", community[publicId], &community[publicId].Auditable, false, nil, nil)

		err = bulk.Add(ctx, esutil.BulkIndexerItem{
			Index:      index,
			Action:     "delete",
			DocumentID: id,
			OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
				auditMut.Lock()
				defer auditMut.Unlock()

				results.Removed++

				createAudit = append(createAudit, model.AuditInfo{
					Detection: community[publicId],
					DocId:     resp.DocumentID,
					Op:        "delete",
				})
			},
			OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
				errMut.Lock()
				defer errMut.Unlock()

				if err != nil {
					errMap[publicId] = err
				} else {
					errMap[publicId] = errors.New(resp.Error.Reason)
				}
			},
		})
		if err != nil {
			errMap[publicId] = fmt.Errorf("unable to delete unreferenced detection: %s", err)
			continue
		}

	}

	err = bulk.Close(ctx)
	if err != nil {
		return nil, err
	}

	stats := bulk.Stats()
	logger.WithFields(log.Fields{
		"NumAdded":    stats.NumAdded,
		"NumCreated":  stats.NumCreated,
		"NumDeleted":  stats.NumDeleted,
		"NumFailed":   stats.NumFailed,
		"NumFlushed":  stats.NumFlushed,
		"NumIndexed":  stats.NumIndexed,
		"NumRequests": stats.NumRequests,
		"NumUpdated":  stats.NumUpdated,
	}).Debug("detections bulk sync stats")

	if len(createAudit) != 0 {
		bulk, err = e.srv.Detectionstore.BuildBulkIndexer(e.srv.Context, logger)
		if err != nil {
			return nil, err
		}

		for _, audit := range createAudit {
			// prepare audit doc
			document, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", audit.Detection, &audit.Detection.Auditable, false, &audit.DocId, &audit.Op)
			if err != nil {
				errMap[audit.Detection.PublicID] = err
				continue
			}

			// create audit doc
			err = bulk.Add(ctx, esutil.BulkIndexerItem{
				Index:  index,
				Action: "create",
				Body:   bytes.NewReader(document),
				OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
					atomic.AddInt32(&results.Audited, 1)
				},
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()

					if err != nil {
						errMap[audit.Detection.PublicID] = err
					} else {
						errMap[audit.Detection.PublicID] = errors.New(resp.Error.Reason)
					}
				},
			})
			if err != nil {
				errMap[audit.Detection.PublicID] = err
				continue
			}
		}

		err = bulk.Close(ctx)
		if err != nil {
			return nil, err
		}

		stats := bulk.Stats()
		logger.WithFields(log.Fields{
			"NumAdded":    stats.NumAdded,
			"NumCreated":  stats.NumCreated,
			"NumDeleted":  stats.NumDeleted,
			"NumFailed":   stats.NumFailed,
			"NumFlushed":  stats.NumFlushed,
			"NumIndexed":  stats.NumIndexed,
			"NumRequests": stats.NumRequests,
			"NumUpdated":  stats.NumUpdated,
		}).Debug("detections bulk audit sync stats")
	}

	logger.WithFields(log.Fields{
		"syncAudited":   results.Audited,
		"syncAdded":     results.Added,
		"syncUpdated":   results.Updated,
		"syncRemoved":   results.Removed,
		"syncUnchanged": results.Unchanged,
		"syncErrors":    detections.TruncateMap(errMap, 5),
	}).Info("elastalert community diff")

	return errMap, nil
}

// IndexExistingRules maps the publicID of a detection to the path of the rule file.
// Note that it indexes ALL rules and not just community rules.
func (e *OsqueryEngine) IndexExistingRules() (index map[string]string, err error) {
	index = map[string]string{} // map[id | title]path

	rules, err := e.ReadDir(e.elastAlertRulesFolder)
	if err != nil {
		return nil, fmt.Errorf("unable to read elastalert rules directory: %w", err)
	}

	for _, rule := range rules {
		if rule.IsDir() {
			continue
		}

		filename := filepath.Join(e.elastAlertRulesFolder, rule.Name())

		ext := filepath.Ext(rule.Name())
		if !acceptedExtensions[strings.ToLower(ext)] {
			continue
		}

		id := strings.TrimSuffix(rule.Name(), ext)

		index[id] = filename
	}

	return index, nil
}

func (e *OsqueryEngine) sigmaToOsquery(ctx context.Context, det *model.Detection) (string, error) {
	rule := det.Content

	filters := lo.Filter(det.Overrides, func(item *model.Override, _ int) bool {
		return item.Type == model.OverrideTypeCustomFilter && item.IsEnabled
	})

	// apply overrides
	if len(filters) > 0 {
		doc := map[string]interface{}{}

		err := yaml.Unmarshal([]byte(rule), &doc)
		if err != nil {
			return "", fmt.Errorf("unable to unmarshal sigma rule: %w", err)
		}

		detection := doc["detection"].(map[string]interface{})
		if detection == nil {
			return "", fmt.Errorf("sigma rule does not contain a detection section")
		}

		for _, f := range filters {
			o, err := f.PrepareForSigma()
			if err != nil {
				return "", fmt.Errorf("unable to marshal filter: %w", err)
			}

			for k, v := range o {
				detection[k] = v
			}
		}

		condition := detection["condition"].(string)
		detection["condition"] = fmt.Sprintf("(%s) and not 1 of sofilter*", condition)

		raw, err := yaml.Marshal(doc)
		if err != nil {
			return "", fmt.Errorf("unable to marshal sigma rule with overrides: %w", err)
		}

		rule = string(raw)
	}

	args := []string{"convert", "-t", "eql", "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "/dev/stdin"}

	cmd := exec.CommandContext(ctx, "sigma", args...)
	cmd.Stdin = strings.NewReader(rule)

	raw, code, runtime, err := e.ExecCommand(cmd)

	log.WithFields(log.Fields{
		"sigmaConvertCode":     code,
		"sigmaConvertOutput":   string(raw),
		"sigmaConvertCommand":  cmd.String(),
		"sigmaConvertExecTime": runtime.Seconds(),
		"sigmaConvertError":    err,
	}).Info("executing sigma cli")

	if err != nil {
		return "", fmt.Errorf("problem with sigma cli: %w", err)
	}

	query := string(raw)

	firstLine := strings.Index(string(raw), "\n")
	if firstLine != -1 {
		query = query[firstLine+1:]
	}

	query = strings.TrimSpace(query)

	return query, nil
}

func (e *OsqueryEngine) GenerateUnusedPublicId(ctx context.Context) (string, error) {
	id := uuid.New().String()

	i := 0
	for ; i < 10; i++ {
		detect, err := e.srv.Detectionstore.GetDetectionByPublicId(ctx, id)
		if err != nil {
			return "", err
		}

		if detect == nil {
			// no detection with this publicId, we're good
			break
		}

		id = uuid.New().String()
	}

	if i >= 10 {
		return "", fmt.Errorf("unable to generate a unique publicId")
	}

	return id, nil
}

func (e *OsqueryEngine) DuplicateDetection(ctx context.Context, detection *model.Detection) (*model.Detection, error) {
	id, err := e.GenerateUnusedPublicId(ctx)
	if err != nil {
		return nil, err
	}

	rule, err := ParseOsqueryRule([]byte(detection.Content))
	if err != nil {
		return nil, err
	}

	rule.Title += " (copy)"
	rule.ID = &id

	det := rule.ToDetection(detections.RULESET_CUSTOM, detection.License, false)

	err = e.ExtractDetails(det)
	if err != nil {
		return nil, err
	}

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	user, err := e.srv.Userstore.GetUserById(ctx, userID)
	if err != nil {
		return nil, err
	}

	det.Author = detections.AddUser(det.Author, user, ", ")

	return det, nil
}

func (e *OsqueryEngine) IsAirgapped() bool {
	return e.srv.Config.AirgapEnabled
}

func (e *OsqueryEngine) LoadAuxiliaryData(summaries []*model.AiSummary) error {
	sum := &sync.Map{}
	for _, summary := range summaries {
		sum.Store(summary.PublicId, summary)
	}

	e.aiSummaries = sum

	log.WithFields(log.Fields{
		"detectionEngine": model.EngineNameOsquery,
		"aiSummaryCount":  len(summaries),
	}).Info("loaded AI summaries")

	return nil
}

func (e *OsqueryEngine) MergeAuxiliaryData(detect *model.Detection) error {
	if e.showAiSummaries {
		obj, ok := e.aiSummaries.Load(detect.PublicID)
		if ok {
			sig := md5.Sum([]byte(detect.Content))
			hexSig := hex.EncodeToString(sig[:])

			summary := obj.(*model.AiSummary)
			detect.AiFields = &model.AiFields{
				AiSummary:         summary.Summary,
				AiSummaryReviewed: summary.Reviewed,
				IsAiSummaryStale:  !strings.EqualFold(summary.RuleBodyHash, hexSig),
			}
		}
	}

	return nil
}

type CustomWrapper struct {
	DetectionTitle    string   `yaml:"detection_title"`
	DetectionPublicId string   `yaml:"detection_public_id"`
	SigmaCategory     string   `yaml:"sigma_category,omitempty"`
	SigmaProduct      string   `yaml:"sigma_product,omitempty"`
	SigmaService      string   `yaml:"sigma_service,omitempty"`
	EventModule       string   `yaml:"event.module"`
	EventDataset      string   `yaml:"event.dataset"`
	EventSeverity     int      `yaml:"event.severity"`
	SigmaLevel        string   `yaml:"sigma_level"`
	Alert             []string `yaml:"alert"`

	Index   string                   `yaml:"index"`
	Name    string                   `yaml:"name"`
	Realert *TimeFrame               `yaml:"realert,omitempty"` // or 0
	Type    string                   `yaml:"type"`
	Filter  []map[string]interface{} `yaml:"filter"`
}

type TimeFrame struct {
	Milliseconds *int    `yaml:"milliseconds,omitempty"`
	Seconds      *int    `yaml:"seconds,omitempty"`
	Minutes      *int    `yaml:"minutes,omitempty"`
	Hours        *int    `yaml:"hours,omitempty"`
	Days         *int    `yaml:"days,omitempty"`
	Weeks        *int    `yaml:"weeks,omitempty"`
	Schedule     *string `yaml:"schedule,omitempty"`
}

func (dur *TimeFrame) SetSeconds(s int) {
	dur.Milliseconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Seconds = util.Ptr(s)
}

func (dur *TimeFrame) SetMilliseconds(m int) {
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Milliseconds = util.Ptr(m)
}

func (dur *TimeFrame) SetMinutes(m int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Minutes = util.Ptr(m)
}

func (dur *TimeFrame) SetHours(h int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Hours = util.Ptr(h)
}

func (dur *TimeFrame) SetDays(d int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Days = util.Ptr(d)
}

func (dur *TimeFrame) SetWeeks(w int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Schedule = nil
	dur.Weeks = util.Ptr(w)
}

func (dur *TimeFrame) SetSchedule(w string) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = util.Ptr(w)
}

func (dur TimeFrame) MarshalYAML() (interface{}, error) {
	if dur.Milliseconds == nil &&
		dur.Seconds == nil &&
		dur.Minutes == nil &&
		dur.Hours == nil &&
		dur.Days == nil &&
		dur.Weeks == nil &&
		dur.Schedule == nil {
		return 0, nil
	}

	type Alias TimeFrame

	return struct {
		Alias `yaml:",inline"`
	}{(Alias)(dur)}, nil
}

func (dur *TimeFrame) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var zero int

	err := unmarshal(&zero)
	if err == nil {
		return nil
	}

	type Alias *TimeFrame

	dur = &TimeFrame{}

	err = unmarshal(struct {
		A Alias `yaml:",inline"`
	}{(Alias)(dur)})

	return err
}

func (e *OsqueryEngine) IntegrityCheck(canInterrupt bool, logger *log.Entry) (deployedButNotEnabled []string, enabledButNotDeployed []string, err error) {
	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	if logger == nil {
		logger = log.WithFields(log.Fields{
			"detectionEngine": model.EngineNameSuricata,
		})
	}

	logger = logger.WithField("intCheckId", uuid.New().String())

	deployed, err := e.getDeployedPublicIds()
	if err != nil {
		logger.WithError(err).Error("unable to get deployed publicIds")
		return nil, nil, detections.ErrIntCheckFailed
	}

	logger.WithField("deployedPublicIdsCount", len(deployed)).Debug("deployed publicIds")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return nil, nil, detections.ErrIntCheckerStopped
	}

	ret, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameOsquery), model.WithEnabled(true))
	if err != nil {
		logger.WithError(err).Error("unable to query for enabled detections")
		return nil, nil, detections.ErrIntCheckFailed
	}

	enabled := make([]string, 0, len(ret))
	for pid := range ret {
		enabled = append(enabled, pid)
	}

	logger.WithField("enabledDetectionsCount", len(enabled)).Debug("enabled detections")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return nil, nil, detections.ErrIntCheckerStopped
	}

	deployedButNotEnabled, enabledButNotDeployed, _ = detections.DiffLists(deployed, enabled)

	intCheckReport := logger.WithFields(log.Fields{
		"deployedButNotEnabled":      detections.TruncateList(deployedButNotEnabled, 20),
		"enabledButNotDeployed":      detections.TruncateList(enabledButNotDeployed, 20),
		"deployedButNotEnabledCount": len(deployedButNotEnabled),
		"enabledButNotDeployedCount": len(enabledButNotDeployed),
	})

	if len(deployedButNotEnabled) > 0 || len(enabledButNotDeployed) > 0 {
		intCheckReport.Warn("integrity check failed")
		return deployedButNotEnabled, enabledButNotDeployed, detections.ErrIntCheckFailed
	}

	intCheckReport.Info("integrity check passed")

	return deployedButNotEnabled, enabledButNotDeployed, nil
}

func (e *OsqueryEngine) getDeployedPublicIds() (publicIds []string, err error) {
	files, err := e.ReadDir(e.elastAlertRulesFolder)
	if err != nil {
		return nil, fmt.Errorf("unable to read elastalert rules folder: %w", err)
	}

	publicIds = make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		ext := filepath.Ext(file.Name())

		_, ok := acceptedExtensions[strings.ToLower(ext)]
		if !ok {
			continue
		}

		pid := strings.TrimSuffix(file.Name(), ext)
		publicIds = append(publicIds, pid)
	}

	return publicIds, nil
}
