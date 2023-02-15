// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const i18n = {
  translations: {
    "en-US": {
      __missing__: '*Missing',
      accept: 'Accept',
      accepted: 'Accepted',
      acceptingMinionsTakesTime: 'Accepting new minions can take 1-2 minutes to complete.',
      access: 'Access Control',
      acknowledged: 'Acknowledged',
      ackMultipleTip: 'Acknowledging groups of alerts may take a while and will continue in the background.',
      ackPartialSuccess: 'The acknowledge request encountered an unexpected problem. Some events may not have been acknowledged.',
      ackSingleTip: 'Acknowledged alert and removed from view.',
      ackUndoMultipleTip: 'Reverting acknowledgment on groups of alerts may take a while and will continue in the background.',
      ackUndoSingleTip: 'Reverted acknowledgement and removed from view.',
      actions: 'Actions',
      actionAlert: 'Alert',
      actionAlertHelp: 'Create an alert for this event',
      actionCorrelate: 'Correlate',
      actionCorrelateHelp: 'Show related events',
      actionCyberChef: 'CyberChef',
      actionCyberChefHelp: 'Analyze this field using CyberChef',
      actionFailure: 'Action failed (check browser console for more error details): ',
      actionGoogle: 'Google',
      actionGoogleHelp: 'Perform a Google search on this field',
      actionHunt: 'Hunt',
      actionHuntHelp: 'Hunt for this field',
      actionPcap: 'PCAP',
      actionPcapHelp: 'Show PCAP for this event',
      actionSuccess: 'Action completed: ',
      actionVirusTotal: 'VirusTotal',
      actionVirusTotalHelp: 'Analyze this field at virustotal.com',
      active: 'Active',
      add: 'Add',
      addAttachmentHelp: 'Add a new attachment to this case',
      addCommentHelp: 'Add a new comment to this case',
      addObservableHelp: 'Add a new observable to this case',
      addObservable: 'Add as new observable...',
      addSuccessful: 'Added successfully!',
      address: 'Address',
      admin: 'Administration',
      advanced: 'Temporarily enable advanced interface features',
      alertAcknowledge: 'Acknowledge',
      alertEscalated: 'This alert has already been escalated',
      alertUndoAcknowledge: 'Undo Acknowledge',
      alerts: 'Alerts',
      all: 'All',
      analyze: 'Analyze',
      analyzers: 'Analyzers Processed', 
      analyzeHelp: 'Enqueues a new analyze job for this observable',
      analyzeJobEnqueued: 'A new analyze job has been enqueued; results will be available within the observable details, after the analysis completes.',
      analyzeJobs: 'Analyzer Results',
      analyzersUnavailable: 'No analyzers are applicable to this observable. This can also occur if there are applicable analyzers but they are not properly configured. Review the SOC logs for more information.',

      analyzer_result_none: 'No analyzers available',
      analyzer_result_unknown: 'Unable to conclusively determine threat level',
      analyzer_result_info: 'Informative data collected',
      analyzer_result_ok: 'No threat detected',
      analyzer_result_caution: 'Possible threat; manual review advised',
      analyzer_result_threat: 'Confirmed threat detected',

      analyzer_analysis_complete: 'Analysis complete',
      analyzer_excessive_usage: 'Excessive analyzer usage',
      analyzer_harmless: 'Harmless',
      analyzer_internal_failure: 'Internal analyzer failure',
      analyzer_invalid_input: 'Invalid input',
      analyzer_likely_harmless: 'Likely harmless',
      analyzer_malicious: 'Malicious',
      analyzer_no_results: 'No results found',
      analyzer_suspicious: 'Further investigation needed',
      analyzer_phishing: 'Phishing',
      analyzer_spam: 'Spam',
      analyzer_timeout: 'Remote host timed out',
      analyzer_urlhaus_invalid_url: 'Invalid URL',
      analyzer_urlhaus_malware_download: 'Malware download',
      
      artifactBulk: 'Bulk Add',
      artifactBulkHelp: 'Enable this checkbox to have a separate observable added for each line of the provided value above',
      artifactDescription: 'Description',
      artifactDescriptionHelp: 'Provide an optional description',
      artifactIoc: 'IOC',
      artifactIocHelp: 'Enable this field if this is an Indicator of Compromise',
      artifactGroupType: 'Group Type',
      artifactGroupId: 'Group ID',
      artifactDescription: 'Description',
      artifactType: 'Type',
      artifactTypeHelp: 'Select a type for classification purposes (Note: choose "file" type to upload a file)',
      artifactValue: 'Value (hash, filename, etc.)',
      artifactValueHelp: 'Specify the observed value',
      attachments: 'Attachments',
      attachmentAdd: 'Add Attachment',
      attachmentHelp: 'Click to attach a file to upload. (Note: max upload size is {maxUploadSizeBytes} bytes)',
      attempt: 'Attempt',
      author: 'Author',
      autohunt: 'Automatically apply filters, groupings, and date ranges',
      autoRefresh: 'Automatic refresh interval',
      beginTime: 'Filter Begin',
      beginTimeHelp: 'Filter start time in RFC 3339 format (Ex: 2020-10-16 13:00:00.230-04:00). Unused for imported PCAPs.',
      blog: 'Blog',
      bytes: 'Bytes',
      cancel: 'Cancel',
      case: 'Case',
      cases: 'Cases',
      caseAssignee: 'Assignee',
      caseAssigneeHelp: 'Designate the assignee for this case',
      caseCategory: 'Category',
      caseCategoryHelp: 'Category used for organizing and grouping similar cases',
      caseCreateFailed: 'Unable to create new case - request a system administrator review SOC logs',
      caseDefaultTitle: 'Case title not yet provided - click here to update this title',
      caseDefaultDescription: 'Case description not yet provided - click here to update this description',
      caseEscalatedDescription: 'Review escalated event details in the Events tab below. Click here to update this description.',
      caseEventIdAggregation: '(aggregation)',
      caseDescription: 'Description',
      caseDescriptionHelp: 'Detailed description of the case',
      caseHours: 'Time Spent',
      caseId: 'Case Id',
      casePap: 'PAP',
      casePapHelp: 'Permissible Actions Protocol',
      casePriority: 'Priority',
      casePriorityHelp: 'Lower values typically indicate increasing importance.',
      caseSeverity: 'Severity',
      caseSeverityHelp: 'The severity classification for this case',
      caseStatus: 'Status',
      caseStatusHelp: 'Indicates the state of the case',
      caseTags: 'Tags',
      caseTagsHelp: 'Annotate with multiple optional tags',
      caseTitle: 'Title',
      caseTitleHelp: 'Brief summary of the case',
      caseTlp: 'TLP',
      caseTlpHelp: 'Traffic Light Protocol',
      caseExcludeToggle: 'Exclude case data',
      category: 'Category',
      categoryHelp: 'Select a category to hide unrelated settings',
      changeStatus: 'Change Status',
      chartTitleBottom: 'Fewest Occurrences',
      chartTitleIncomplete: '(partial)',
      chartTitleTimeline: 'Timeline',
      chartTitleTop: 'Most Occurrences',
      cheatsheet: 'Cheat Sheet',
      clear: 'Clear',
      clickForMoreInformation: 'Click for more information',
      collapse: 'Collapse',
      collapseAll: 'Collapse All',
      collapseHelp: 'Collapse all packet data',
      comment: 'Comments',
      comments: 'Comments',
      commentAdd: 'Add Comment',
      commentDescription: 'Comment',
      commentDescriptionHelp: 'Provide follow-up information to this case',
      commentHours: 'Work Hours',
      commentHoursHelp: 'Hours spent working on this update (leave blank for 0 hours)',
      commentRequired: 'Comments cannot be empty.',
      completed: 'Completed',
      config: 'Configuration',
      configTitle: 'Grid Configuration',
      container: 'Container',
      containerStatus: 'Container Status',
      continue: 'Would you like to continue?',
      copyEventToClipboardAsJson: 'Copy full event as JSON',
      copyEventToClipboardAsKvp: 'Copy full event as field:value pairs',
      copyFieldToClipboard: 'Copy this value only',
      copyFieldValueToClipboard: 'Copy as field:value',
      copyToClipboard: 'Copy to clipboard',
      create: 'Create',
      custom: 'Custom',
      darkMode: 'Dark Mode',
      dashboards: 'Dashboards',
      dataset: 'Dataset',
      dataUrl: 'Data Url',
      dateClosed: 'Closed',
      dateCompleted: 'Date Completed',
      dateCreated: 'Created',
      dateDataEpoch: 'Earliest PCAP',
      dateFailed: 'Date Failed',
      dateModified: 'Updated',
      dateOnline: 'Online Since:',
      dateQueued: 'Date Queued',
      datePreselectToday: 'Today',
      datePreselectYesterday: 'Yesterday',
      datePreselectThisWeek: 'This Week',
      datePreselectLastWeek: 'Last Week',
      datePreselectThisMonth: 'This Month',
      datePreselectLastMonth: 'Last Month',
      datePreselectPrevious3d: 'Previous 3 Days',
      datePreselectPrevious4d: 'Previous 4 Days',
      datePreselectPrevious7d: 'Previous 7 Days',
      datePreselectPrevious30d: 'Previous 30 Days',
      datePreselect3dToNow: '3 Days ago to Now',
      datePreselect4dToNow: '4 Days ago to Now',
      datePreselect7dToNow: '7 Days ago to Now',
      datePreselect30dToNow: '30 Days ago to Now',
      dateTimeFormat: 'lll',
      dateUnknown: '',
      dateUpdated: 'Date Updated',
      days: 'days',
      defaults: 'Defaults',
      delete: 'Delete',
      deleteSuccessful: 'Deleted successfully',
      deleted: 'Deleted',
      deleteUserTitle: 'Delete User',
      deleteUserConfirm: 'You are about to permanently delete this user:',
      denied: 'Denied',
      description: 'Description',
      details: 'Details',
      disconnected: 'Disconnected from manager',
      downloads: 'Downloads',
      downloadsFirewallTip: 'When installing the Elastic Agent onto remote systems, be sure to allow network access through the firewall.',
      downloadsInfo: 'These <a href="/docs/elastic-agent.html">Elastic Agent</a> installers are customized for this specific <a href="/docs/elastic-fleet.html">Elastic Fleet</a> installation. These files are not signed. If you need signed non-customized Elastic Agent installers, you can get them from <a href="https://www.elastic.co/downloads/elastic-agent">elastic.co</a>.',
      downloadsElasticAgent: 'Elastic Agent Installers',
      downloadPackets: 'Download the packets as a PCAP file',
      dstIp: 'Destination IP',
      dstIpHelp: 'Optional destination IP address to include in this job filter',
      dstPort: 'Destination Port',
      dstPortHelp: 'Optional destination TCP port to include in this job filter',
      edit: 'Edit',
      edited: '(edited)',
      email: 'Email Address',
      emailHelp: 'Specify a valid email address. Contact your administrator for new account creation.',
      emailRequired: 'An email address must be specified.',
      endTime: 'Filter End',
      endTimeHelp: 'Filter end time in RFC 3339 format (Ex: 2020-10-16 15:30:00.230-04:00). Unused for imported PCAPs.',
      eps: 'EPS',
      epsProduction: 'Production EPS:',
      epsConsumption: 'Consumption EPS:',
      error: 'Error',
      errorHelp: 'See the Help section of the Security Onion documentation for additional troubleshooting guidance.',
      escalate: 'Escalate',
      escalationInvalid: 'Invalid alert - cannot escalate to a case due to insufficient alert information',
      escalateExistingCase: 'Attach event to a recently viewed case:',
      escalateExistingCaseHelp: 'Attach event to this existing case',
      escalateNewCase: 'Escalate to new case',
      escalateNewCaseHelp: 'Escalate this event to a new case (a new case will be created)',
      escalated: 'Escalated',
      escalatedEventTip: 'Escalated event(s).',
      escalatedMultipleTip: 'Escalating groups of alerts may take a while and will continue in the background.',
      escalatedSingleTip: 'Escalated alert and removed from view.',
      event: 'Event',
      events: 'Events',
      eventCaseTitle: 'Event Escalation from SOC',
      eventExpandHelp: 'Show all event fields',
      eventFetchTook: 'The backend data fetch took ',
      eventLookupFailed: 'The event lookup could not be completed.',
      eventRoundTripTook: 'The total round trip took ',
      eventTotal: 'Total Found: ',
      evidence: 'Observables',
      evidenceAdd: 'Add Observable',
      evidenceHelp: 'Important data relevant to this case',
      exceeded: 'Exceeded',
      expandAll: 'Expand All',
      expand: 'Expand',
      expandHelp: 'Expand and show detailed data',
      expired: 'Expired',
      incomplete: 'Incomplete',
      invalidHours: 'Hours are not valid. Ex: 1.5',
      failedEvents: 'Failed Events',
      fault: 'Fault',
      featureRequiresAppliance: 'Feature Unavailable',
      features: 'Features',
      fetchLimit: 'Fetch Limit',
      
      'field_case.createTime': 'Create Date',
      'field_case.severity': 'Severity',
      'field_case.status': 'Status',
      'field_case.title': 'Title',
      field_count: 'Count',
      field_soc_id: 'Event ID',
      field_soc_timestamp: 'Timestamp',

      filename: 'Filename',
      fileTooLarge: 'The chosen file is too large to upload; max file size is {maxUploadSizeBytes} bytes',
      fileEmpty: 'The chosen file appears to have no content; consider using a "filename" artifact instead',

      filter: 'Filter',
      filterHelp: 'Filter the items on this page by keyword',
      filterDrilldown: 'Drilldown',
      filterDrilldownHelp: 'Drilldown into this value',
      filterExact: 'Only',
      filterExactHelp: 'Filters for only this value',
      filterExclude: 'Exclude',
      filterExcludeHelp: 'Excludes this value from the search',
      filterInclude: 'Include',
      filterIncludeHelp: 'Adds this value as a required match in the search',
      filterResults: 'Filter Results',
      fingerprint: 'Fingerprint',
      firstName: 'First Name',
      flags: 'Flags',
      graphs: 'Graphs',
      grid: 'Grid',
      gridEps: 'Grid EPS:',
      gridMember: 'Review Grid Member',
      gridMemberHelp: 'Closely inspect pending grid members to ensure their identities match expected values. Only approve nodes that you confirm are legitimate.',
      gridMemberInput: 'Acceptance Inputs',
      gridMemberInputDescriptionHelp: 'User defined description of the new member node',
      gridMemberReview: 'Display member details and perform actions on this member',
      gridMemberReviewTitle: 'Review Grid Member',
      gridMembersAccepted: 'Accepted Members',
      gridMembersAcceptedHelp: 'Accepted members are trusted grid members',
      gridMembersDenied: 'Denied Members',
      gridMembersDeniedHelp: 'Denied nodes have been automatically rejected by the system, due to conflicting or missing information',
      gridMembersHelp: 'A distributed grid is made of up member nodes. Member nodes will request to join the grid and remain in a pending state until an administrator has accepted the node. If a pending member node is not yet listed as pending, then it\'s possible that the wrong manager host was provided during setup or there could be a connectivity problem.',
      gridMembersPending: 'Pending Members',
      gridMembersPendingHelp: 'This node is awaiting acceptance to join the grid',
      gridMembersRejected: 'Rejected Members',
      gridMembersRejectedHelp: 'Rejected nodes have been manually rejected by an administrator',
      gridMembers: 'Grid Members',
      groupedBy: 'Group:',
      groupByRemove: 'Remove this entire group',
      groupByRemoveField: 'Remove this column from the group',
      groupInclude: "Group By",
      groupIncludeHelp: "Group by this field",
      groupNew: "New Group By",
      groupNewHelp: "Group by this field in a new group",
      groups: 'Group Metrics',
      help: 'Help',
      hex: 'HEX',
      hexHelp: 'Include hexadecimal representation of packet data',
      hidden: 'Hidden',
      history: 'History',
      home: 'Overview',
      hours: 'hours',
      hunt: 'Hunt',
      huntForEvent: 'Hunt for this event',
      huntForFieldValue: 'Hunt for this field\'s value',
      huntForEvidence: 'Hunt for this observable value',
      huntHelp: 'Start a new hunt based on the current filters',
      id: 'ID',
      importId: 'Import ID',
      importIdHelp: 'UUID value that is output from so-import-pcap. Only needed for imported PCAPs.',
      index: "Index",
      interval0s: "Never",
      interval5s: "5 seconds",
      interval10s: "10 seconds",
      interval15s: "15 seconds",
      interval30s: "30 seconds",
      interval1m: "1 minute",
      interval2m: "2 minutes",
      interval5m: "5 minutes",
      interval10m: "10 minutes",
      interval15m: "15 minutes",
      interval30m: "30 minutes",
      interval1h: "1 hour",
      interval2h: "2 hours",
      interval5h: "5 hours",
      interval10h: "10 hours",
      interval24h: "24 hours",
      invalid: 'Invalid',
      job: 'Job',
      jobIncomplete: 'The job was unable to complete and will retry within a few minutes. Details are available below.',
      jobInProgress: 'This job is awaiting completion.',
      jobs: 'PCAP',
      kind: 'Kind',
      last: 'Last',
      lastName: 'Last Name',
      length: 'Length',
      license: 'License',
      licensee: 'Licensee',
      licenseEffective: 'Effective',
      licenseExpiration: 'Expiration',
      licenseId: 'ID',
      licensing: 'Licensing',
      licenseKey: 'License Key',
      licenseName: 'Type',
      licenseShort: 'ELv2',
      licenseStatus: 'Status',
      licenseTerms: 'License Terms',
      loading: 'Loading, please wait...',
      loadMore: 'Load More',
      lock: 'Lock User',
      login: 'Login',
      loginDisabled: 'Locked',
      loginEnabled: 'Unlocked',
      loginExpired: 'The login session has expired. Refresh, or wait for the page to refresh automatically, and then try again.',
      loginInvalid: 'The provided credentials are invalid. Please try again.',
      loginTitle: 'Login to Security Onion',
      logout: 'Logout',
      logoutFailure: 'Unable to initiate logout. Ensure server is accessible.',
      markdownFormattingSupported: 'Markdown formatting supported',
      maximize: 'Maximize View (ESC to cancel)',
      md5: 'MD5',
      message: 'Message',
      minutes: 'minutes',
      model: 'Model',
      module: 'Module',
      months: 'months',
      mruQuery: 'Recently Used',
      mruQueryHelp: 'This query is a user-defined query and is only available on this browser.',
      na: 'N/A',
      name: 'Name',
      no: 'No',
      noData: 'No information is currently available.',
      nodeDashboard: 'View Node Metrics',
      nodeExpandHelp: 'Show node details',
      nodeExpand: 'Expand',
      nodeImageUnavailable: 'Appliance images are only displayed for official Security Onion Solutions appliances.',
      nodeImages: 'Appliance Images',
      nodeLimit: 'Nodes',
      nodeStatus: 'Node Status',
      nodeStatusCode_1: 'Container Subsystem Error',
      nodeStatusCode_2: 'System appears to be restarting',
      nodeStatusCode_99: 'Installation has not yet completed',
      nodeStatusConnection: 'Connection Status:',
      nodeStatusProcess: 'Process Status:',
      nodeStatusRaid: 'RAID Status:',
      noSearchResults: 'No search results were found.',
      none: 'None',
      note: 'Note',
      notFound: 'The selected item no longer exists',
      number: 'Num',
      ok: 'OK',
      offline: 'Offline',
      online: 'Online',
      operation: 'Operation',
      options: 'Options',
      order: 'Order',
      other: 'Other',
      owner: 'Owner',
      packages: 'Packages',
      packets: 'Captured Packets',
      packetStreamHelp: 'Show all packet data instead of only the application-level data stream',
      password: 'Password',
      passwordConfirm: 'Confirm password',
      passwordHelp: 'Passwords must meet strength requirements',
      passwordInstructions: 'Update your password using the fields below. Note: InfluxDB passwords are not updated when using this self-service screen.',
      passwordMustMatch: 'Passwords must match',
      passwordChange: 'New password',
      passwordRequired: 'A password must be specified.',
      passwordReset: 'Change Password',
      passwordNeedsChanged: 'User has not yet changed their password',
      profileDetails: 'Profile Details',
      profileInstructions: 'You may be prompted to login again when updating your profile. This is a security measure to protect your account.',
      pcap: 'PCAP',
      pending: 'Pending',
      product: 'Security Onion',
      profile: 'Profile',
      queriesHelp: 'Choose from several pre-defined queries',
      queryHelp: 'Specify a query in Onion Query Language (OQL)',
      quickActions: 'Actions',
      quickDrilldown: 'Quick Drilldown',
      reason: 'Reason',
      reconnecting: 'Attempting to connect to manager',
      refresh: 'Refresh',
      refreshAttachmentsHelp: 'Refresh to view all recently added attachments for this case.',
      refreshCommentsHelp: 'Refresh to view all recently added comments for this case.',
      refreshObservablesHelp: 'Refresh to view all recently added observables for this case.',
      refreshEventsHelp: 'Refresh to view all recently escalated events for this case.',
      refreshHistoryHelp: 'Refresh to view the latest history for this case.',
      reject: 'Reject',
      rejected: 'Rejected',
      related: 'Events',
      relatedEventId: 'Related Event ID',
      relativeTimeHelp: 'Click the clock icon to change to absolute time',
      remove: 'Remove',
      required: 'Required.',
      reset: 'Reset',
      resetDefaults: 'Reset Defaults',
      resetDefaultsHint: 'Reset all local user SOC settings back to their original default values. This must be done on each browser or device that you have used with SOC.',
      results: 'Results',
      review: 'Review',
      role: 'Role',
      roles: 'Roles',
      roleAdmin: 'Administrator',
      roleAnalyst: 'Analyst',
      ruleMinLen: 'The provided value is too short',
      ruleMaxLen: 'The provided value is too long',
      rulePassBadChars: 'The password must not contain the following characters: " \' $ & !',
      save: 'Save',
      saveSuccess: 'Save successful!',
      seconds: 'seconds',
      security: 'Security',
      securityInstructions: 'You may be prompted to login again when updating your security settings. If submitting a new password, you will need to verify your identity first with the old password. This is a security measure to protect your account.',
      securityInstructionsTotp: 'IMPORTANT: If you changed your password recently you must logout and login again with the new password before attempting to activate MFA. Failure to relogin will result in the MFA validation failing. If this occurs you will need to remove the MFA code from your authenticator app, login to SOC with the new password, and then activate MFA again.',
      sensor: 'Sensor',
      sensorId: 'Sensor ID',
      sensorIdRequired: 'The Sensor ID must be entered before adding a new job.',
      sensorIdHelp: 'The sensor ID must match an actual sensor ID in order for this job to be processed.',
      settingCancelHelp: 'Cancel changes',
      settingCategory_general: 'General',
      settingCategory_ui: 'User Interface',
      settingConfirmCancel: 'Unsaved Changes',
      settingConfirmCancelHelp: 'Discard unsaved changes?',
      settingAdvanced: 'Provide optional, custom configuration in YAML format. Note that improper customizations often are the cause of grid malfunctions.',
      settingDefault: 'Default Value',
      settingDeleted: 'Setting deleted/reset successfully. Changes typically apply within 15 minutes.',
      settingDeleteError: 'Setting could not be deleted.',
      settingHelp: 'View documentation or related information for this setting',
      settingSelect: 'Select a setting from the tree view.',
      settingGlobal: 'Current Grid Value',
      settingIsModified: 'This setting has been modified to something other than the default.',
      settingIsModifiedHelp: 'Show all settings that have been modified to something other than the default.',
      settingHasNodeValues: 'This setting has unique values specified for one or more nodes in the grid.',
      settingHasNodeValuesHelp: 'Show all settings with unique values specified for one or more nodes in the grid.',
      settingMalformed: 'Malformed config setting',
      settingReadOnly: 'This is a read-only setting and cannot be modified.',
      settingReadOnlyHelp: 'Modifying this setting can cause severe problems within the grid, often requiring a full grid re-installation.',
      settingRemoveHelp: 'Remove this node override value',
      settingResetHelp: 'Reset global value to default',
      settingSaved: 'Setting saved successfully. Changes typically apply within 15 minutes.',
      settingSaveError: 'Setting could not be saved. Ensure the specified value is suitable for the given setting.',
      settingSaveHelp: 'Save changes',
      settingSelectNode: 'Select a node to modify',
      settingSelectNodeHelp: 'Select a node if a unique value is desired for that specific node',
      settingShowDefault: 'View Default',
      settingHideDefault: 'Hide Default',
      settingValidationFailed: 'The specified value is not valid.',
      settings: 'Settings',
      settingsAdvanced: 'Show all configurable settings, including advanced settings.',
      settingsAdvancedHelp: 'CAUTION! Changing advanced settings is unsupported and could result in requiring a full cluster re-installation.',
      settingsInvalid: 'Unable to save settings: ',
      settingsCustomized: 'Modified: ',
      settingsTitle: 'User Settings',
      settingsSynchronize: 'Synchronize Grid',
      settingsSynchronizeHelp: 'Manually synchronize the manager node. This can take several minutes to complete. The rest of the grid nodes will synchronize on their own schedule.',
      settingsSynchronized: 'Synchronization has been initiated in the background; this process can take several minutes to complete.',

      setting_fake_setting_foo: 'Fake Setting Translated',
      settingHelp_fake_setting_foo: 'This is a transalated fake setting description.',

      sha1: 'SHA1',
      sha256: 'SHA256',
      share: 'Clipboard',
      showAll: 'Show all...',
      'so-eval': 'Evaluation',
      'so-eval-keywords': 'Elastic, Elasticsearch, Fleet, Forward, Ingest, Manager, Master, Search, Sensor, Sensoroni, Soc, Stenographer, Web',
      'so-fleet': 'Fleet',
      'so-fleet-keywords': 'Fleet',
      'so-heavynode': 'Heavy',
      'so-heavynode-keywords': 'Elastic, Elasticsearch, Forward, Ingest, Search, Sensor, Sensoroni, Stenographer',
      'so-helix': 'Helix',
      'so-helix-keywords': 'Helix, Sensor, Sensoroni, Stenographer',
      'so-idh': 'Intrusion Detection Honeypot',
      'so-idh-keywords': 'IDH, Intrusion, Detection, Honeypot',      
      'so-import': 'Import',
      'so-import-keywords': 'Import, Manager, Master, Soc, Web',
      'so-managersearch': 'ManagerSearch',
      'so-managersearch-keywords': 'Elastic, Elasticsearch, Ingest, Manager, Master, Search, Soc, Web',
      'so-manager': 'Manager',
      'so-manager-keywords': 'Manager, Master, Soc',
      'so-node': 'Search',
      'so-node-keywords': 'Elastic, Elasticsearch, Ingest, Search',
      'so-receiver': 'Receiver',
      'so-receiver-keywords': 'Receiver',
      'so-search': 'Search',
      'so-search-keywords': 'Elastic, Elasticsearch, Ingest, Search',
      'so-sensor': 'Forward',
      'so-sensor-keywords': 'Forward, Sensor, Sensoroni, Stenographer',
      'so-standalone': 'Standalone',
      'so-standalone-keywords': 'Elastic, Elasticsearch, Fleet, Forward, Ingest, Manager, Master, Search, Sensor, Sensoroni, Soc, Stenographer, Web',
      showPieChart: 'Show pie chart',
      showBarChart: 'Show bar chart',
      showSankeyChart: 'Show Sankey diagram',
      showTable: 'Show table',
      socUrl: 'SOC Url',
      sortedBy: 'Sort:',
      sortInclude: "Sort By",
      sortIncludeHelp: "Add as a sort-by field",
      sponsorsIntro: 'Brought to you by:',
      srcIp: 'Source IP',
      srcIpHelp: 'Optional source IP address to include in this job filter',
      srcPort: 'Source Port',
      srcPortHelp: 'Optional source TCP port to include in this job filter',
      standardMetrics: 'Basic Metrics',
      status: 'Status',
      summary: 'Summary',
      time: 'Time',
      timePickerHelp: 'Choose the timespan to search, or click the calendar icon to switch to relative time',
      timePickerFormat: 'YYYY/MM/DD hh:mm:ss A',
      timePickerSample: '2006/01/02 3:04:05 PM',
      timestamp: 'Timestamp',
      timestampFormat: 'YYYY-MM-DD HH:mm:ss.SSS Z',
      timetracking: 'Time Tracking',
      timezone: 'Time Zone:',
      timezoneHelp: 'Time Zone',
      toggleLegend: 'Toggle Legend',
      toolCyberchef: 'CyberChef',
      toolCyberchefHelp: 'Data decoding and transformation tools',
      toolElasticFleet: 'Elastic Fleet',
      toolElasticFleetHelp: 'Elastic Fleet Management',
      toolOsqueryManager: 'Osquery Manager',
      toolOsqueryManagerHelp: 'Osquery Manager',
      toolInfluxDb: 'InfluxDB',
      toolInfluxDbHelp: 'Visualize Security Onion metrics',
      toolKibana: 'Kibana',
      toolKibanaHelp: 'Elasticsearch User Interface',
      toolNavigator: 'Navigator',
      toolNavigatorHelp: 'MITRE ATT@CK Navigator',
      toolPlaybook: 'Playbook',
      toolPlaybookHelp: 'Detection Playbook',
      toolTheHive: 'TheHive',
      toolTheHiveHelp: 'Case Management',
      totp: 'Multi-Factor Authentication (MFA)',
      totpActivate: 'Activate MFA',
      totpCodeHelp: 'Enter the multi-factor code from your authenticator app.',
      totpEnabled: 'Unlocked, with multi-factor authentication (MFA) enabled',
      totpQrInstructions: 'For increased security, activate multi-factor authentication (MFA) using an authenticator app, such as Google Authenticator. Using the app on your mobile device, scan the QR code shown below.',
      totpDeactivate: 'Deactivate MFA',
      totpSecretInstructions: 'If you are unable to scan the QR code, use the secret provided below instead.',
      totpUnlinkInstructions: 'If you no longer have access to your authenticator app, you can deactivate multi-factor authentication (MFA). This will reduce the security on your account until it is reactivated.',
      transcriptCyberChefHelp: 'Send the transcript to CyberChef',
      type: 'Type',
      unaccepted: 'Pending',
      unassigned: 'unassigned',
      unknown: 'unknown',
      unlimited: 'Unlimited',
      unlock: 'Unlock User',
      unlocked: 'Unlocked',
      unmatchedFilter: 'No items match the given filters.',
      unprovisioned: 'Unprovisioned',
      unwrapHelp: 'Unwrap packets from encapsulation (Ex: VXLAN)',
      update: 'Update',
      updateProfile: 'Update Profile',
      updateSettings: 'Settings',
      updateSuccessful: 'Update successful',
      uptime: 'Uptime',
      user: 'User Details',
      userAdded: 'User added successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userDeleted: 'User deleted successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userDisabled: 'User locked successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userEnabled: 'User unlocked successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userRoleAdded: 'User role added successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userRoleDeleted: 'User role deleted successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userPasswordChanged: 'User password changed successfully; Users will automatically synchronize across backend apps within 15 minutes.',
      userProfileUpdated: 'User profile updated successfully',
      username: 'User',
      userLimit: 'Users',
      users: 'Users',
      usersEnabled: 'Users Enabled:',
      usersSynchronize: 'Synchronize Users',
      usersSynchronizeHelp: 'Synchronize users across all backend applications. This can take several minutes to complete.',
      usersSynchronized: 'User synchronization successful.',
      value: 'Value',
      version: 'Version',
      view: 'View',
      viewCase: 'Case Details',
      weeks: 'weeks',
      whatsnew: 'What\'s New',
      yes: 'Yes',

      ERROR_CASE_EVENT_ALREADY_ATTACHED: 'The event is already attached to the selected case.',
      ERROR_CASE_MODULE_NOT_ENABLED: 'A case module has not been configured for this installation. Unable to proceed with request.',
      ERROR_QUERY_INVALID__GROUP_EMPTY: 'The search query has an empty group.',
      ERROR_QUERY_INVALID__GROUP_INCOMPLETE: 'The search query is missing an ending parenthesis.',
      ERROR_QUERY_INVALID__GROUP_NOT_STARTED: 'The search query has an extra parenthesis.',
      ERROR_QUERY_INVALID__GROUPBY_TERMS_MISSING: 'The search query has a malformed groupby segment.',
      ERROR_QUERY_INVALID__QUOTE_INCOMPLETE: 'The search query is missing an ending double quote.',
      ERROR_QUERY_INVALID__SEARCH_MISSING: 'The search query is missing the search criteria.',
      ERROR_QUERY_INVALID__SEARCH_TERMS_MISSING: 'The search query is missing search terms.',
      ERROR_QUERY_INVALID__SEGMENT_EMPTY: 'The search query has an incomplete segment (pipe) function.',
      ERROR_QUERY_INVALID__SEGMENT_UNSUPPORTED: 'The search query contains an unsupported segment (pipe) function.',
      ERROR_QUERY_INVALID__TERM_MISSING: 'The search query is incomplete.',
      ERROR_QUERY_FAILED_ELASTICSEARCH: 'The search query encountered a failure within the Elasticsearch cluster. Check SOC logs for details.',
      ERROR_SALT_MANAGE_MEMBER: 'Unable to manage minion; ensure that salt is running on the manager node and check salt logs.',
      ERROR_SALT_RELAY_DOWN: 'Failed to execute salt command; ensure salt-relay is running on the manager node.',
    },
  },

  getLocalizedTranslations(lang) {
    var trans = this.translations[lang];
    if (trans == undefined) trans = this.translations['en-US'];
    return trans;
  },
}

if (typeof global !== 'undefined') global.i18n = i18n;
