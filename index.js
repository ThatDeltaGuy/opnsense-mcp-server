#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { OPNsenseClient } from '@richard-stovall/opnsense-typescript-client';

// Embedded modular tool definitions
const TOOLS = [
  {
    "name": "core_read",
    "description": "Core read operations — 20 methods: backupBackups, backupDiff, backupDownload, backupProviders, dashboardGetDashboard, dashboardPicture...",
    "module": "core",
    "methods": [
      "backupBackups",
      "backupDiff",
      "backupDownload",
      "backupProviders",
      "dashboardGetDashboard",
      "dashboardPicture",
      "dashboardProductInfoFeed",
      "hasyncGet",
      "hasyncStatusRemoteService",
      "hasyncStatusServices",
      "hasyncStatusVersion",
      "menuSearch",
      "menuTree",
      "serviceSearch",
      "snapshotsGet",
      "snapshotsIsSupported",
      "snapshotsSearch",
      "systemStatus",
      "tunablesGet",
      "tunablesGetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "backupBackups",
            "backupDiff",
            "backupDownload",
            "backupProviders",
            "dashboardGetDashboard",
            "dashboardPicture",
            "dashboardProductInfoFeed",
            "hasyncGet",
            "hasyncStatusRemoteService",
            "hasyncStatusServices",
            "hasyncStatusVersion",
            "menuSearch",
            "menuTree",
            "serviceSearch",
            "snapshotsGet",
            "snapshotsIsSupported",
            "snapshotsSearch",
            "systemStatus",
            "tunablesGet",
            "tunablesGetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "core_write",
    "description": "Core write operations — 26 methods: backupDeleteBackup, backupRevertBackup, dashboardRestoreDefaults, dashboardSaveWidgets, hasyncReconfigure, hasyncSet...",
    "module": "core",
    "methods": [
      "backupDeleteBackup",
      "backupRevertBackup",
      "dashboardRestoreDefaults",
      "dashboardSaveWidgets",
      "hasyncReconfigure",
      "hasyncSet",
      "hasyncStatusRestart",
      "hasyncStatusRestartAll",
      "hasyncStatusStart",
      "hasyncStatusStop",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "snapshotsActivate",
      "snapshotsAdd",
      "snapshotsDel",
      "snapshotsSet",
      "systemDismissStatus",
      "systemHalt",
      "systemReboot",
      "tunablesAddItem",
      "tunablesDelItem",
      "tunablesReconfigure",
      "tunablesReset",
      "tunablesSet",
      "tunablesSetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "backupDeleteBackup",
            "backupRevertBackup",
            "dashboardRestoreDefaults",
            "dashboardSaveWidgets",
            "hasyncReconfigure",
            "hasyncSet",
            "hasyncStatusRestart",
            "hasyncStatusRestartAll",
            "hasyncStatusStart",
            "hasyncStatusStop",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "snapshotsActivate",
            "snapshotsAdd",
            "snapshotsDel",
            "snapshotsSet",
            "systemDismissStatus",
            "systemHalt",
            "systemReboot",
            "tunablesAddItem",
            "tunablesDelItem",
            "tunablesReconfigure",
            "tunablesReset",
            "tunablesSet",
            "tunablesSetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "firewall_read",
    "description": "Firewall read operations — 25 methods: aliasGet, aliasGetAliasUUID, aliasGetGeoIP, aliasGetItem, aliasGetTableSize, aliasListCategories...",
    "module": "firewall",
    "methods": [
      "aliasGet",
      "aliasGetAliasUUID",
      "aliasGetGeoIP",
      "aliasGetItem",
      "aliasGetTableSize",
      "aliasListCategories",
      "aliasListCountries",
      "aliasListNetworkAliases",
      "aliasListUserGroups",
      "aliasUtilAliases",
      "aliasUtilFindReferences",
      "aliasUtilList",
      "categoryGet",
      "categoryGetItem",
      "filterBaseGet",
      "filterBaseListCategories",
      "filterBaseListNetworkSelectOptions",
      "filterGetInterfaceList",
      "filterGetRule",
      "filterUtilRuleStats",
      "groupGet",
      "groupGetItem",
      "nptGetRule",
      "oneToOneGetRule",
      "sourceNatGetRule"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "aliasGet",
            "aliasGetAliasUUID",
            "aliasGetGeoIP",
            "aliasGetItem",
            "aliasGetTableSize",
            "aliasListCategories",
            "aliasListCountries",
            "aliasListNetworkAliases",
            "aliasListUserGroups",
            "aliasUtilAliases",
            "aliasUtilFindReferences",
            "aliasUtilList",
            "categoryGet",
            "categoryGetItem",
            "filterBaseGet",
            "filterBaseListCategories",
            "filterBaseListNetworkSelectOptions",
            "filterGetInterfaceList",
            "filterGetRule",
            "filterUtilRuleStats",
            "groupGet",
            "groupGetItem",
            "nptGetRule",
            "oneToOneGetRule",
            "sourceNatGetRule"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "firewall_write",
    "description": "Firewall write operations — 42 methods: aliasAddItem, aliasDelItem, aliasImport, aliasReconfigure, aliasSet, aliasSetItem...",
    "module": "firewall",
    "methods": [
      "aliasAddItem",
      "aliasDelItem",
      "aliasImport",
      "aliasReconfigure",
      "aliasSet",
      "aliasSetItem",
      "aliasToggleItem",
      "aliasUtilAdd",
      "aliasUtilDelete",
      "aliasUtilFlush",
      "aliasUtilUpdateBogons",
      "categoryAddItem",
      "categoryDelItem",
      "categorySet",
      "categorySetItem",
      "filterBaseApply",
      "filterBaseCancelRollback",
      "filterBaseRevert",
      "filterBaseSavepoint",
      "filterBaseSet",
      "filterAddRule",
      "filterDelRule",
      "filterMoveRuleBefore",
      "filterSetRule",
      "filterToggleRule",
      "groupAddItem",
      "groupDelItem",
      "groupReconfigure",
      "groupSet",
      "groupSetItem",
      "nptAddRule",
      "nptDelRule",
      "nptSetRule",
      "nptToggleRule",
      "oneToOneAddRule",
      "oneToOneDelRule",
      "oneToOneSetRule",
      "oneToOneToggleRule",
      "sourceNatAddRule",
      "sourceNatDelRule",
      "sourceNatSetRule",
      "sourceNatToggleRule"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "aliasAddItem",
            "aliasDelItem",
            "aliasImport",
            "aliasReconfigure",
            "aliasSet",
            "aliasSetItem",
            "aliasToggleItem",
            "aliasUtilAdd",
            "aliasUtilDelete",
            "aliasUtilFlush",
            "aliasUtilUpdateBogons",
            "categoryAddItem",
            "categoryDelItem",
            "categorySet",
            "categorySetItem",
            "filterBaseApply",
            "filterBaseCancelRollback",
            "filterBaseRevert",
            "filterBaseSavepoint",
            "filterBaseSet",
            "filterAddRule",
            "filterDelRule",
            "filterMoveRuleBefore",
            "filterSetRule",
            "filterToggleRule",
            "groupAddItem",
            "groupDelItem",
            "groupReconfigure",
            "groupSet",
            "groupSetItem",
            "nptAddRule",
            "nptDelRule",
            "nptSetRule",
            "nptToggleRule",
            "oneToOneAddRule",
            "oneToOneDelRule",
            "oneToOneSetRule",
            "oneToOneToggleRule",
            "sourceNatAddRule",
            "sourceNatDelRule",
            "sourceNatSetRule",
            "sourceNatToggleRule"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "auth_read",
    "description": "Auth read operations — 8 methods: groupGet, privGet, privGetItem, privSearch, userDownload, userGet...",
    "module": "auth",
    "methods": [
      "groupGet",
      "privGet",
      "privGetItem",
      "privSearch",
      "userDownload",
      "userGet",
      "userNewOtpSeed",
      "userSearchApiKey"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "groupGet",
            "privGet",
            "privGetItem",
            "privSearch",
            "userDownload",
            "userGet",
            "userNewOtpSeed",
            "userSearchApiKey"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "auth_write",
    "description": "Auth write operations — 11 methods: groupAdd, groupDel, groupSet, privSet, privSetItem, userAdd...",
    "module": "auth",
    "methods": [
      "groupAdd",
      "groupDel",
      "groupSet",
      "privSet",
      "privSetItem",
      "userAdd",
      "userAddApiKey",
      "userDel",
      "userDelApiKey",
      "userSet",
      "userUpload"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "groupAdd",
            "groupDel",
            "groupSet",
            "privSet",
            "privSetItem",
            "userAdd",
            "userAddApiKey",
            "userDel",
            "userDelApiKey",
            "userSet",
            "userUpload"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "interfaces_read",
    "description": "Interfaces read operations — 22 methods: gifSettingsGet, gifSettingsGetIfOptions, gifSettingsGetItem, greSettingsGet, greSettingsGetIfOptions, greSettingsGetItem...",
    "module": "interfaces",
    "methods": [
      "gifSettingsGet",
      "gifSettingsGetIfOptions",
      "gifSettingsGetItem",
      "greSettingsGet",
      "greSettingsGetIfOptions",
      "greSettingsGetItem",
      "laggSettingsGet",
      "laggSettingsGetItem",
      "loopbackSettingsGet",
      "loopbackSettingsGetItem",
      "neighborSettingsGet",
      "neighborSettingsGetItem",
      "overviewExport",
      "overviewGetInterface",
      "overviewInterfacesInfo",
      "vipSettingsGet",
      "vipSettingsGetItem",
      "vipSettingsGetUnusedVhid",
      "vlanSettingsGet",
      "vlanSettingsGetItem",
      "vxlanSettingsGet",
      "vxlanSettingsGetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "gifSettingsGet",
            "gifSettingsGetIfOptions",
            "gifSettingsGetItem",
            "greSettingsGet",
            "greSettingsGetIfOptions",
            "greSettingsGetItem",
            "laggSettingsGet",
            "laggSettingsGetItem",
            "loopbackSettingsGet",
            "loopbackSettingsGetItem",
            "neighborSettingsGet",
            "neighborSettingsGetItem",
            "overviewExport",
            "overviewGetInterface",
            "overviewInterfacesInfo",
            "vipSettingsGet",
            "vipSettingsGetItem",
            "vipSettingsGetUnusedVhid",
            "vlanSettingsGet",
            "vlanSettingsGetItem",
            "vxlanSettingsGet",
            "vxlanSettingsGetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "interfaces_write",
    "description": "Interfaces write operations — 41 methods: gifSettingsAddItem, gifSettingsDelItem, gifSettingsReconfigure, gifSettingsSet, gifSettingsSetItem, greSettingsAddItem...",
    "module": "interfaces",
    "methods": [
      "gifSettingsAddItem",
      "gifSettingsDelItem",
      "gifSettingsReconfigure",
      "gifSettingsSet",
      "gifSettingsSetItem",
      "greSettingsAddItem",
      "greSettingsDelItem",
      "greSettingsReconfigure",
      "greSettingsSet",
      "greSettingsSetItem",
      "laggSettingsAddItem",
      "laggSettingsDelItem",
      "laggSettingsReconfigure",
      "laggSettingsSet",
      "laggSettingsSetItem",
      "loopbackSettingsAddItem",
      "loopbackSettingsDelItem",
      "loopbackSettingsReconfigure",
      "loopbackSettingsSet",
      "loopbackSettingsSetItem",
      "neighborSettingsAddItem",
      "neighborSettingsDelItem",
      "neighborSettingsReconfigure",
      "neighborSettingsSet",
      "neighborSettingsSetItem",
      "overviewReloadInterface",
      "vipSettingsAddItem",
      "vipSettingsDelItem",
      "vipSettingsReconfigure",
      "vipSettingsSet",
      "vipSettingsSetItem",
      "vlanSettingsAddItem",
      "vlanSettingsDelItem",
      "vlanSettingsReconfigure",
      "vlanSettingsSet",
      "vlanSettingsSetItem",
      "vxlanSettingsAddItem",
      "vxlanSettingsDelItem",
      "vxlanSettingsReconfigure",
      "vxlanSettingsSet",
      "vxlanSettingsSetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "gifSettingsAddItem",
            "gifSettingsDelItem",
            "gifSettingsReconfigure",
            "gifSettingsSet",
            "gifSettingsSetItem",
            "greSettingsAddItem",
            "greSettingsDelItem",
            "greSettingsReconfigure",
            "greSettingsSet",
            "greSettingsSetItem",
            "laggSettingsAddItem",
            "laggSettingsDelItem",
            "laggSettingsReconfigure",
            "laggSettingsSet",
            "laggSettingsSetItem",
            "loopbackSettingsAddItem",
            "loopbackSettingsDelItem",
            "loopbackSettingsReconfigure",
            "loopbackSettingsSet",
            "loopbackSettingsSetItem",
            "neighborSettingsAddItem",
            "neighborSettingsDelItem",
            "neighborSettingsReconfigure",
            "neighborSettingsSet",
            "neighborSettingsSetItem",
            "overviewReloadInterface",
            "vipSettingsAddItem",
            "vipSettingsDelItem",
            "vipSettingsReconfigure",
            "vipSettingsSet",
            "vipSettingsSetItem",
            "vlanSettingsAddItem",
            "vlanSettingsDelItem",
            "vlanSettingsReconfigure",
            "vlanSettingsSet",
            "vlanSettingsSetItem",
            "vxlanSettingsAddItem",
            "vxlanSettingsDelItem",
            "vxlanSettingsReconfigure",
            "vxlanSettingsSet",
            "vxlanSettingsSetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "captiveportal_read",
    "description": "Captiveportal read operations — 18 methods: accessApi, accessLogoff, accessLogon, serviceGetTemplate, serviceSearchTemplates, sessionConnect...",
    "module": "captiveportal",
    "methods": [
      "accessApi",
      "accessLogoff",
      "accessLogon",
      "serviceGetTemplate",
      "serviceSearchTemplates",
      "sessionConnect",
      "sessionDisconnect",
      "sessionList",
      "sessionSearch",
      "sessionZones",
      "settingsGet",
      "settingsGetZone",
      "voucherDropExpiredVouchers",
      "voucherDropVoucherGroup",
      "voucherExpireVoucher",
      "voucherListProviders",
      "voucherListVoucherGroups",
      "voucherListVouchers"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "accessApi",
            "accessLogoff",
            "accessLogon",
            "serviceGetTemplate",
            "serviceSearchTemplates",
            "sessionConnect",
            "sessionDisconnect",
            "sessionList",
            "sessionSearch",
            "sessionZones",
            "settingsGet",
            "settingsGetZone",
            "voucherDropExpiredVouchers",
            "voucherDropVoucherGroup",
            "voucherExpireVoucher",
            "voucherListProviders",
            "voucherListVoucherGroups",
            "voucherListVouchers"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "captiveportal_write",
    "description": "Captiveportal write operations — 9 methods: serviceDelTemplate, serviceReconfigure, serviceSaveTemplate, settingsAddZone, settingsDelZone, settingsSet...",
    "module": "captiveportal",
    "methods": [
      "serviceDelTemplate",
      "serviceReconfigure",
      "serviceSaveTemplate",
      "settingsAddZone",
      "settingsDelZone",
      "settingsSet",
      "settingsSetZone",
      "settingsToggleZone",
      "voucherGenerateVouchers"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceDelTemplate",
            "serviceReconfigure",
            "serviceSaveTemplate",
            "settingsAddZone",
            "settingsDelZone",
            "settingsSet",
            "settingsSetZone",
            "settingsToggleZone",
            "voucherGenerateVouchers"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "cron_read",
    "description": "Cron read operations — 2 methods: settingsGet, settingsGetJob",
    "module": "cron",
    "methods": [
      "settingsGet",
      "settingsGetJob"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "settingsGet",
            "settingsGetJob"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "cron_write",
    "description": "Cron write operations — 6 methods: serviceReconfigure, settingsAddJob, settingsDelJob, settingsSet, settingsSetJob, settingsToggleJob",
    "module": "cron",
    "methods": [
      "serviceReconfigure",
      "settingsAddJob",
      "settingsDelJob",
      "settingsSet",
      "settingsSetJob",
      "settingsToggleJob"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "settingsAddJob",
            "settingsDelJob",
            "settingsSet",
            "settingsSetJob",
            "settingsToggleJob"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcpv4_read",
    "description": "Dhcpv4 read operations — 2 methods: leasesSearchLease, serviceStatus",
    "module": "dhcpv4",
    "methods": [
      "leasesSearchLease",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "leasesSearchLease",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcpv4_write",
    "description": "Dhcpv4 write operations — 5 methods: leasesDelLease, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "dhcpv4",
    "methods": [
      "leasesDelLease",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "leasesDelLease",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcpv6_read",
    "description": "Dhcpv6 read operations — 3 methods: leasesSearchLease, leasesSearchPrefix, serviceStatus",
    "module": "dhcpv6",
    "methods": [
      "leasesSearchLease",
      "leasesSearchPrefix",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "leasesSearchLease",
            "leasesSearchPrefix",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcpv6_write",
    "description": "Dhcpv6 write operations — 5 methods: leasesDelLease, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "dhcpv6",
    "methods": [
      "leasesDelLease",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "leasesDelLease",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcrelay_read",
    "description": "Dhcrelay read operations — 3 methods: settingsGet, settingsGetDest, settingsGetRelay",
    "module": "dhcrelay",
    "methods": [
      "settingsGet",
      "settingsGetDest",
      "settingsGetRelay"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "settingsGet",
            "settingsGetDest",
            "settingsGetRelay"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcrelay_write",
    "description": "Dhcrelay write operations — 9 methods: serviceReconfigure, settingsAddDest, settingsAddRelay, settingsDelDest, settingsDelRelay, settingsSet...",
    "module": "dhcrelay",
    "methods": [
      "serviceReconfigure",
      "settingsAddDest",
      "settingsAddRelay",
      "settingsDelDest",
      "settingsDelRelay",
      "settingsSet",
      "settingsSetDest",
      "settingsSetRelay",
      "settingsToggleRelay"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "settingsAddDest",
            "settingsAddRelay",
            "settingsDelDest",
            "settingsDelRelay",
            "settingsSet",
            "settingsSetDest",
            "settingsSetRelay",
            "settingsToggleRelay"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "diagnostics_read",
    "description": "Diagnostics read operations — 67 methods: activityGetActivity, cpuUsageGetCPUType, cpuUsageStream, dnsReverseLookup, dnsDiagnosticsGet, firewallListRuleIds...",
    "module": "diagnostics",
    "methods": [
      "activityGetActivity",
      "cpuUsageGetCPUType",
      "cpuUsageStream",
      "dnsReverseLookup",
      "dnsDiagnosticsGet",
      "firewallListRuleIds",
      "firewallLog",
      "firewallLogFilters",
      "firewallPfStates",
      "firewallPfStatistics",
      "firewallQueryPfTop",
      "firewallQueryStates",
      "firewallStats",
      "firewallStreamLog",
      "interfaceCarpStatus",
      "interfaceGetArp",
      "interfaceGetBpfStatistics",
      "interfaceGetInterfaceConfig",
      "interfaceGetInterfaceNames",
      "interfaceGetInterfaceStatistics",
      "interfaceGetMemoryStatistics",
      "interfaceGetNdp",
      "interfaceGetNetisrStatistics",
      "interfaceGetPfsyncNodes",
      "interfaceGetProtocolStatistics",
      "interfaceGetRoutes",
      "interfaceGetSocketStatistics",
      "interfaceGetVipStatus",
      "interfaceSearchArp",
      "interfaceSearchNdp",
      "lvtemplateGet",
      "lvtemplateGetItem",
      "netflowCacheStats",
      "netflowGetconfig",
      "netflowIsEnabled",
      "netflowStatus",
      "networkinsightExport",
      "networkinsightGetInterfaces",
      "networkinsightGetMetadata",
      "networkinsightGetProtocols",
      "networkinsightGetServices",
      "networkinsightTimeserie",
      "networkinsightTop",
      "packetCaptureDownload",
      "packetCaptureGet",
      "packetCaptureMacInfo",
      "packetCaptureSearchJobs",
      "packetCaptureView",
      "pingGet",
      "pingSearchJobs",
      "portprobeGet",
      "systemMemory",
      "systemSystemDisk",
      "systemSystemInformation",
      "systemSystemMbuf",
      "systemSystemResources",
      "systemSystemSwap",
      "systemSystemTemperature",
      "systemSystemTime",
      "systemhealthExportAsCSV",
      "systemhealthGetInterfaces",
      "systemhealthGetRRDlist",
      "systemhealthGetSystemHealth",
      "tracerouteGet",
      "trafficInterface",
      "trafficTop",
      "trafficStream"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "activityGetActivity",
            "cpuUsageGetCPUType",
            "cpuUsageStream",
            "dnsReverseLookup",
            "dnsDiagnosticsGet",
            "firewallListRuleIds",
            "firewallLog",
            "firewallLogFilters",
            "firewallPfStates",
            "firewallPfStatistics",
            "firewallQueryPfTop",
            "firewallQueryStates",
            "firewallStats",
            "firewallStreamLog",
            "interfaceCarpStatus",
            "interfaceGetArp",
            "interfaceGetBpfStatistics",
            "interfaceGetInterfaceConfig",
            "interfaceGetInterfaceNames",
            "interfaceGetInterfaceStatistics",
            "interfaceGetMemoryStatistics",
            "interfaceGetNdp",
            "interfaceGetNetisrStatistics",
            "interfaceGetPfsyncNodes",
            "interfaceGetProtocolStatistics",
            "interfaceGetRoutes",
            "interfaceGetSocketStatistics",
            "interfaceGetVipStatus",
            "interfaceSearchArp",
            "interfaceSearchNdp",
            "lvtemplateGet",
            "lvtemplateGetItem",
            "netflowCacheStats",
            "netflowGetconfig",
            "netflowIsEnabled",
            "netflowStatus",
            "networkinsightExport",
            "networkinsightGetInterfaces",
            "networkinsightGetMetadata",
            "networkinsightGetProtocols",
            "networkinsightGetServices",
            "networkinsightTimeserie",
            "networkinsightTop",
            "packetCaptureDownload",
            "packetCaptureGet",
            "packetCaptureMacInfo",
            "packetCaptureSearchJobs",
            "packetCaptureView",
            "pingGet",
            "pingSearchJobs",
            "portprobeGet",
            "systemMemory",
            "systemSystemDisk",
            "systemSystemInformation",
            "systemSystemMbuf",
            "systemSystemResources",
            "systemSystemSwap",
            "systemSystemTemperature",
            "systemSystemTime",
            "systemhealthExportAsCSV",
            "systemhealthGetInterfaces",
            "systemhealthGetRRDlist",
            "systemhealthGetSystemHealth",
            "tracerouteGet",
            "trafficInterface",
            "trafficTop",
            "trafficStream"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "diagnostics_write",
    "description": "Diagnostics write operations — 23 methods: dnsDiagnosticsSet, firewallDelState, firewallFlushSources, firewallFlushStates, firewallKillStates, interfaceDelRoute...",
    "module": "diagnostics",
    "methods": [
      "dnsDiagnosticsSet",
      "firewallDelState",
      "firewallFlushSources",
      "firewallFlushStates",
      "firewallKillStates",
      "interfaceDelRoute",
      "interfaceFlushArp",
      "lvtemplateAddItem",
      "lvtemplateDelItem",
      "lvtemplateSet",
      "lvtemplateSetItem",
      "netflowReconfigure",
      "netflowSetconfig",
      "packetCaptureRemove",
      "packetCaptureSet",
      "packetCaptureStart",
      "packetCaptureStop",
      "pingRemove",
      "pingSet",
      "pingStart",
      "pingStop",
      "portprobeSet",
      "tracerouteSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "dnsDiagnosticsSet",
            "firewallDelState",
            "firewallFlushSources",
            "firewallFlushStates",
            "firewallKillStates",
            "interfaceDelRoute",
            "interfaceFlushArp",
            "lvtemplateAddItem",
            "lvtemplateDelItem",
            "lvtemplateSet",
            "lvtemplateSetItem",
            "netflowReconfigure",
            "netflowSetconfig",
            "packetCaptureRemove",
            "packetCaptureSet",
            "packetCaptureStart",
            "packetCaptureStop",
            "pingRemove",
            "pingSet",
            "pingStart",
            "pingStop",
            "portprobeSet",
            "tracerouteSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dnsmasq_read",
    "description": "Dnsmasq read operations — 11 methods: leasesSearch, serviceStatus, settingsDownloadHosts, settingsGet, settingsGetBoot, settingsGetDomain...",
    "module": "dnsmasq",
    "methods": [
      "leasesSearch",
      "serviceStatus",
      "settingsDownloadHosts",
      "settingsGet",
      "settingsGetBoot",
      "settingsGetDomain",
      "settingsGetHost",
      "settingsGetOption",
      "settingsGetRange",
      "settingsGetTag",
      "settingsGetTagList"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "leasesSearch",
            "serviceStatus",
            "settingsDownloadHosts",
            "settingsGet",
            "settingsGetBoot",
            "settingsGetDomain",
            "settingsGetHost",
            "settingsGetOption",
            "settingsGetRange",
            "settingsGetTag",
            "settingsGetTagList"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dnsmasq_write",
    "description": "Dnsmasq write operations — 24 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsAddBoot, settingsAddDomain...",
    "module": "dnsmasq",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddBoot",
      "settingsAddDomain",
      "settingsAddHost",
      "settingsAddOption",
      "settingsAddRange",
      "settingsAddTag",
      "settingsDelBoot",
      "settingsDelDomain",
      "settingsDelHost",
      "settingsDelOption",
      "settingsDelRange",
      "settingsDelTag",
      "settingsSet",
      "settingsSetBoot",
      "settingsSetDomain",
      "settingsSetHost",
      "settingsSetOption",
      "settingsSetRange",
      "settingsSetTag",
      "settingsUploadHosts"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddBoot",
            "settingsAddDomain",
            "settingsAddHost",
            "settingsAddOption",
            "settingsAddRange",
            "settingsAddTag",
            "settingsDelBoot",
            "settingsDelDomain",
            "settingsDelHost",
            "settingsDelOption",
            "settingsDelRange",
            "settingsDelTag",
            "settingsSet",
            "settingsSetBoot",
            "settingsSetDomain",
            "settingsSetHost",
            "settingsSetOption",
            "settingsSetRange",
            "settingsSetTag",
            "settingsUploadHosts"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "firmware_read",
    "description": "Firmware read operations — 19 methods: firmwareAudit, firmwareChangelog, firmwareCheck, firmwareConnection, firmwareGet, firmwareGetOptions...",
    "module": "firmware",
    "methods": [
      "firmwareAudit",
      "firmwareChangelog",
      "firmwareCheck",
      "firmwareConnection",
      "firmwareGet",
      "firmwareGetOptions",
      "firmwareHealth",
      "firmwareInfo",
      "firmwareLog",
      "firmwareResyncPlugins",
      "firmwareRunning",
      "firmwareStatus",
      "firmwareSyncPlugins",
      "firmwareUpgrade",
      "firmwareUpgradestatus",
      "firmwareDetails",
      "firmwareLicense",
      "firmwareLock",
      "firmwareUnlock"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "firmwareAudit",
            "firmwareChangelog",
            "firmwareCheck",
            "firmwareConnection",
            "firmwareGet",
            "firmwareGetOptions",
            "firmwareHealth",
            "firmwareInfo",
            "firmwareLog",
            "firmwareResyncPlugins",
            "firmwareRunning",
            "firmwareStatus",
            "firmwareSyncPlugins",
            "firmwareUpgrade",
            "firmwareUpgradestatus",
            "firmwareDetails",
            "firmwareLicense",
            "firmwareLock",
            "firmwareUnlock"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "firmware_write",
    "description": "Firmware write operations — 7 methods: firmwarePoweroff, firmwareReboot, firmwareSet, firmwareUpdate, firmwareInstall, firmwareRemove...",
    "module": "firmware",
    "methods": [
      "firmwarePoweroff",
      "firmwareReboot",
      "firmwareSet",
      "firmwareUpdate",
      "firmwareInstall",
      "firmwareRemove",
      "firmwareReinstall"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "firmwarePoweroff",
            "firmwareReboot",
            "firmwareSet",
            "firmwareUpdate",
            "firmwareInstall",
            "firmwareRemove",
            "firmwareReinstall"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "ids_read",
    "description": "Ids read operations — 16 methods: serviceDropAlertLog, serviceGetAlertInfo, serviceGetAlertLogs, serviceQueryAlerts, serviceStatus, settingsCheckPolicyRule...",
    "module": "ids",
    "methods": [
      "serviceDropAlertLog",
      "serviceGetAlertInfo",
      "serviceGetAlertLogs",
      "serviceQueryAlerts",
      "serviceStatus",
      "settingsCheckPolicyRule",
      "settingsGet",
      "settingsGetPolicy",
      "settingsGetPolicyRule",
      "settingsGetRuleInfo",
      "settingsGetRuleset",
      "settingsGetRulesetproperties",
      "settingsGetUserRule",
      "settingsListRuleMetadata",
      "settingsListRulesets",
      "settingsSearchInstalledRules"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceDropAlertLog",
            "serviceGetAlertInfo",
            "serviceGetAlertLogs",
            "serviceQueryAlerts",
            "serviceStatus",
            "settingsCheckPolicyRule",
            "settingsGet",
            "settingsGetPolicy",
            "settingsGetPolicyRule",
            "settingsGetRuleInfo",
            "settingsGetRuleset",
            "settingsGetRulesetproperties",
            "settingsGetUserRule",
            "settingsListRuleMetadata",
            "settingsListRulesets",
            "settingsSearchInstalledRules"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "ids_write",
    "description": "Ids write operations — 24 methods: serviceReconfigure, serviceReloadRules, serviceRestart, serviceStart, serviceStop, serviceUpdateRules...",
    "module": "ids",
    "methods": [
      "serviceReconfigure",
      "serviceReloadRules",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "serviceUpdateRules",
      "settingsAddPolicy",
      "settingsAddPolicyRule",
      "settingsAddUserRule",
      "settingsDelPolicy",
      "settingsDelPolicyRule",
      "settingsDelUserRule",
      "settingsSet",
      "settingsSetPolicy",
      "settingsSetPolicyRule",
      "settingsSetRule",
      "settingsSetRuleset",
      "settingsSetRulesetproperties",
      "settingsSetUserRule",
      "settingsTogglePolicy",
      "settingsTogglePolicyRule",
      "settingsToggleRule",
      "settingsToggleRuleset",
      "settingsToggleUserRule"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceReloadRules",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "serviceUpdateRules",
            "settingsAddPolicy",
            "settingsAddPolicyRule",
            "settingsAddUserRule",
            "settingsDelPolicy",
            "settingsDelPolicyRule",
            "settingsDelUserRule",
            "settingsSet",
            "settingsSetPolicy",
            "settingsSetPolicyRule",
            "settingsSetRule",
            "settingsSetRuleset",
            "settingsSetRulesetproperties",
            "settingsSetUserRule",
            "settingsTogglePolicy",
            "settingsTogglePolicyRule",
            "settingsToggleRule",
            "settingsToggleRuleset",
            "settingsToggleUserRule"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "ipsec_read",
    "description": "Ipsec read operations — 28 methods: connectionsConnectionExists, connectionsGet, connectionsGetChild, connectionsGetConnection, connectionsGetLocal, connectionsGetRemote...",
    "module": "ipsec",
    "methods": [
      "connectionsConnectionExists",
      "connectionsGet",
      "connectionsGetChild",
      "connectionsGetConnection",
      "connectionsGetLocal",
      "connectionsGetRemote",
      "connectionsIsEnabled",
      "connectionsSwanctl",
      "keyPairsGet",
      "keyPairsGetItem",
      "leasesPools",
      "leasesSearch",
      "legacySubsystemStatus",
      "manualSpdGet",
      "poolsGet",
      "preSharedKeysGet",
      "preSharedKeysGetItem",
      "sadSearch",
      "serviceStatus",
      "sessionsConnect",
      "sessionsDisconnect",
      "sessionsSearchPhase1",
      "sessionsSearchPhase2",
      "settingsGet",
      "spdSearch",
      "tunnelSearchPhase1",
      "tunnelSearchPhase2",
      "vtiGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "connectionsConnectionExists",
            "connectionsGet",
            "connectionsGetChild",
            "connectionsGetConnection",
            "connectionsGetLocal",
            "connectionsGetRemote",
            "connectionsIsEnabled",
            "connectionsSwanctl",
            "keyPairsGet",
            "keyPairsGetItem",
            "leasesPools",
            "leasesSearch",
            "legacySubsystemStatus",
            "manualSpdGet",
            "poolsGet",
            "preSharedKeysGet",
            "preSharedKeysGetItem",
            "sadSearch",
            "serviceStatus",
            "sessionsConnect",
            "sessionsDisconnect",
            "sessionsSearchPhase1",
            "sessionsSearchPhase2",
            "settingsGet",
            "spdSearch",
            "tunnelSearchPhase1",
            "tunnelSearchPhase2",
            "vtiGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "ipsec_write",
    "description": "Ipsec write operations — 52 methods: connectionsAddChild, connectionsAddConnection, connectionsAddLocal, connectionsAddRemote, connectionsDelChild, connectionsDelConnection...",
    "module": "ipsec",
    "methods": [
      "connectionsAddChild",
      "connectionsAddConnection",
      "connectionsAddLocal",
      "connectionsAddRemote",
      "connectionsDelChild",
      "connectionsDelConnection",
      "connectionsDelLocal",
      "connectionsDelRemote",
      "connectionsSet",
      "connectionsSetChild",
      "connectionsSetConnection",
      "connectionsSetLocal",
      "connectionsSetRemote",
      "connectionsToggle",
      "connectionsToggleChild",
      "connectionsToggleConnection",
      "connectionsToggleLocal",
      "connectionsToggleRemote",
      "keyPairsAddItem",
      "keyPairsDelItem",
      "keyPairsGenKeyPair",
      "keyPairsSet",
      "keyPairsSetItem",
      "legacySubsystemApplyConfig",
      "manualSpdAdd",
      "manualSpdDel",
      "manualSpdSet",
      "manualSpdToggle",
      "poolsAdd",
      "poolsDel",
      "poolsSet",
      "poolsToggle",
      "preSharedKeysAddItem",
      "preSharedKeysDelItem",
      "preSharedKeysSet",
      "preSharedKeysSetItem",
      "sadDelete",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet",
      "spdDelete",
      "tunnelDelPhase1",
      "tunnelDelPhase2",
      "tunnelToggle",
      "tunnelTogglePhase1",
      "tunnelTogglePhase2",
      "vtiAdd",
      "vtiDel",
      "vtiSet",
      "vtiToggle"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "connectionsAddChild",
            "connectionsAddConnection",
            "connectionsAddLocal",
            "connectionsAddRemote",
            "connectionsDelChild",
            "connectionsDelConnection",
            "connectionsDelLocal",
            "connectionsDelRemote",
            "connectionsSet",
            "connectionsSetChild",
            "connectionsSetConnection",
            "connectionsSetLocal",
            "connectionsSetRemote",
            "connectionsToggle",
            "connectionsToggleChild",
            "connectionsToggleConnection",
            "connectionsToggleLocal",
            "connectionsToggleRemote",
            "keyPairsAddItem",
            "keyPairsDelItem",
            "keyPairsGenKeyPair",
            "keyPairsSet",
            "keyPairsSetItem",
            "legacySubsystemApplyConfig",
            "manualSpdAdd",
            "manualSpdDel",
            "manualSpdSet",
            "manualSpdToggle",
            "poolsAdd",
            "poolsDel",
            "poolsSet",
            "poolsToggle",
            "preSharedKeysAddItem",
            "preSharedKeysDelItem",
            "preSharedKeysSet",
            "preSharedKeysSetItem",
            "sadDelete",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet",
            "spdDelete",
            "tunnelDelPhase1",
            "tunnelDelPhase2",
            "tunnelToggle",
            "tunnelTogglePhase1",
            "tunnelTogglePhase2",
            "vtiAdd",
            "vtiDel",
            "vtiSet",
            "vtiToggle"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "kea_read",
    "description": "Kea read operations — 8 methods: ctrlAgentGet, dhcpv4DownloadReservations, dhcpv4Get, dhcpv4GetPeer, dhcpv4GetReservation, dhcpv4GetSubnet...",
    "module": "kea",
    "methods": [
      "ctrlAgentGet",
      "dhcpv4DownloadReservations",
      "dhcpv4Get",
      "dhcpv4GetPeer",
      "dhcpv4GetReservation",
      "dhcpv4GetSubnet",
      "leases4Search",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "ctrlAgentGet",
            "dhcpv4DownloadReservations",
            "dhcpv4Get",
            "dhcpv4GetPeer",
            "dhcpv4GetReservation",
            "dhcpv4GetSubnet",
            "leases4Search",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "kea_write",
    "description": "Kea write operations — 16 methods: ctrlAgentSet, dhcpv4AddPeer, dhcpv4AddReservation, dhcpv4AddSubnet, dhcpv4DelPeer, dhcpv4DelReservation...",
    "module": "kea",
    "methods": [
      "ctrlAgentSet",
      "dhcpv4AddPeer",
      "dhcpv4AddReservation",
      "dhcpv4AddSubnet",
      "dhcpv4DelPeer",
      "dhcpv4DelReservation",
      "dhcpv4DelSubnet",
      "dhcpv4Set",
      "dhcpv4SetPeer",
      "dhcpv4SetReservation",
      "dhcpv4SetSubnet",
      "dhcpv4UploadReservations",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "ctrlAgentSet",
            "dhcpv4AddPeer",
            "dhcpv4AddReservation",
            "dhcpv4AddSubnet",
            "dhcpv4DelPeer",
            "dhcpv4DelReservation",
            "dhcpv4DelSubnet",
            "dhcpv4Set",
            "dhcpv4SetPeer",
            "dhcpv4SetReservation",
            "dhcpv4SetSubnet",
            "dhcpv4UploadReservations",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "monit_read",
    "description": "Monit read operations — 9 methods: serviceCheck, serviceStatus, settingsDirty, settingsGet, settingsGetAlert, settingsGetGeneral...",
    "module": "monit",
    "methods": [
      "serviceCheck",
      "serviceStatus",
      "settingsDirty",
      "settingsGet",
      "settingsGetAlert",
      "settingsGetGeneral",
      "settingsGetService",
      "settingsGetTest",
      "statusGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceCheck",
            "serviceStatus",
            "settingsDirty",
            "settingsGet",
            "settingsGetAlert",
            "settingsGetGeneral",
            "settingsGetService",
            "settingsGetTest",
            "statusGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "monit_write",
    "description": "Monit write operations — 16 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsAddAlert, settingsAddService...",
    "module": "monit",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAlert",
      "settingsAddService",
      "settingsAddTest",
      "settingsDelAlert",
      "settingsDelService",
      "settingsDelTest",
      "settingsSet",
      "settingsSetAlert",
      "settingsSetService",
      "settingsSetTest",
      "settingsToggleAlert",
      "settingsToggleService"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddAlert",
            "settingsAddService",
            "settingsAddTest",
            "settingsDelAlert",
            "settingsDelService",
            "settingsDelTest",
            "settingsSet",
            "settingsSetAlert",
            "settingsSetService",
            "settingsSetTest",
            "settingsToggleAlert",
            "settingsToggleService"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "openvpn_read",
    "description": "Openvpn read operations — 10 methods: clientOverwritesGet, exportAccounts, exportDownload, exportProviders, exportTemplates, exportValidatePresets...",
    "module": "openvpn",
    "methods": [
      "clientOverwritesGet",
      "exportAccounts",
      "exportDownload",
      "exportProviders",
      "exportTemplates",
      "exportValidatePresets",
      "instancesGet",
      "instancesGetStaticKey",
      "serviceSearchRoutes",
      "serviceSearchSessions"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "clientOverwritesGet",
            "exportAccounts",
            "exportDownload",
            "exportProviders",
            "exportTemplates",
            "exportValidatePresets",
            "instancesGet",
            "instancesGetStaticKey",
            "serviceSearchRoutes",
            "serviceSearchSessions"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "openvpn_write",
    "description": "Openvpn write operations — 18 methods: clientOverwritesAdd, clientOverwritesDel, clientOverwritesSet, clientOverwritesToggle, exportStorePresets, instancesAdd...",
    "module": "openvpn",
    "methods": [
      "clientOverwritesAdd",
      "clientOverwritesDel",
      "clientOverwritesSet",
      "clientOverwritesToggle",
      "exportStorePresets",
      "instancesAdd",
      "instancesAddStaticKey",
      "instancesDel",
      "instancesDelStaticKey",
      "instancesGenKey",
      "instancesSet",
      "instancesSetStaticKey",
      "instancesToggle",
      "serviceKillSession",
      "serviceReconfigure",
      "serviceRestartService",
      "serviceStartService",
      "serviceStopService"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "clientOverwritesAdd",
            "clientOverwritesDel",
            "clientOverwritesSet",
            "clientOverwritesToggle",
            "exportStorePresets",
            "instancesAdd",
            "instancesAddStaticKey",
            "instancesDel",
            "instancesDelStaticKey",
            "instancesGenKey",
            "instancesSet",
            "instancesSetStaticKey",
            "instancesToggle",
            "serviceKillSession",
            "serviceReconfigure",
            "serviceRestartService",
            "serviceStartService",
            "serviceStopService"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "routes_read",
    "description": "Routes read operations — 3 methods: gatewayStatus, routesGet, routesGetroute",
    "module": "routes",
    "methods": [
      "gatewayStatus",
      "routesGet",
      "routesGetroute"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "gatewayStatus",
            "routesGet",
            "routesGetroute"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "routes_write",
    "description": "Routes write operations — 6 methods: routesAddroute, routesDelroute, routesReconfigure, routesSet, routesSetroute, routesToggleroute",
    "module": "routes",
    "methods": [
      "routesAddroute",
      "routesDelroute",
      "routesReconfigure",
      "routesSet",
      "routesSetroute",
      "routesToggleroute"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "routesAddroute",
            "routesDelroute",
            "routesReconfigure",
            "routesSet",
            "routesSetroute",
            "routesToggleroute"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "routing_read",
    "description": "Routing read operations — 3 methods: settingsGet, settingsGetGateway, settingsSearchGateway",
    "module": "routing",
    "methods": [
      "settingsGet",
      "settingsGetGateway",
      "settingsSearchGateway"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "settingsGet",
            "settingsGetGateway",
            "settingsSearchGateway"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "routing_write",
    "description": "Routing write operations — 6 methods: settingsAddGateway, settingsDelGateway, settingsReconfigure, settingsSet, settingsSetGateway, settingsToggleGateway",
    "module": "routing",
    "methods": [
      "settingsAddGateway",
      "settingsDelGateway",
      "settingsReconfigure",
      "settingsSet",
      "settingsSetGateway",
      "settingsToggleGateway"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "settingsAddGateway",
            "settingsDelGateway",
            "settingsReconfigure",
            "settingsSet",
            "settingsSetGateway",
            "settingsToggleGateway"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "syslog_read",
    "description": "Syslog read operations — 4 methods: serviceStats, serviceStatus, settingsGet, settingsGetDestination",
    "module": "syslog",
    "methods": [
      "serviceStats",
      "serviceStatus",
      "settingsGet",
      "settingsGetDestination"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStats",
            "serviceStatus",
            "settingsGet",
            "settingsGetDestination"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "syslog_write",
    "description": "Syslog write operations — 10 methods: serviceReconfigure, serviceReset, serviceRestart, serviceStart, serviceStop, settingsAddDestination...",
    "module": "syslog",
    "methods": [
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddDestination",
      "settingsDelDestination",
      "settingsSet",
      "settingsSetDestination",
      "settingsToggleDestination"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceReset",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddDestination",
            "settingsDelDestination",
            "settingsSet",
            "settingsSetDestination",
            "settingsToggleDestination"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "trafficshaper_read",
    "description": "Trafficshaper read operations — 6 methods: serviceFlushreload, serviceStatistics, settingsGet, settingsGetPipe, settingsGetQueue, settingsGetRule",
    "module": "trafficshaper",
    "methods": [
      "serviceFlushreload",
      "serviceStatistics",
      "settingsGet",
      "settingsGetPipe",
      "settingsGetQueue",
      "settingsGetRule"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceFlushreload",
            "serviceStatistics",
            "settingsGet",
            "settingsGetPipe",
            "settingsGetQueue",
            "settingsGetRule"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "trafficshaper_write",
    "description": "Trafficshaper write operations — 14 methods: serviceReconfigure, settingsAddPipe, settingsAddQueue, settingsAddRule, settingsDelPipe, settingsDelQueue...",
    "module": "trafficshaper",
    "methods": [
      "serviceReconfigure",
      "settingsAddPipe",
      "settingsAddQueue",
      "settingsAddRule",
      "settingsDelPipe",
      "settingsDelQueue",
      "settingsDelRule",
      "settingsSet",
      "settingsSetPipe",
      "settingsSetQueue",
      "settingsSetRule",
      "settingsTogglePipe",
      "settingsToggleQueue",
      "settingsToggleRule"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "settingsAddPipe",
            "settingsAddQueue",
            "settingsAddRule",
            "settingsDelPipe",
            "settingsDelQueue",
            "settingsDelRule",
            "settingsSet",
            "settingsSetPipe",
            "settingsSetQueue",
            "settingsSetRule",
            "settingsTogglePipe",
            "settingsToggleQueue",
            "settingsToggleRule"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "trust_read",
    "description": "Trust read operations — 14 methods: caCaInfo, caCaList, caGet, caRawDump, certCaInfo, certCaList...",
    "module": "trust",
    "methods": [
      "caCaInfo",
      "caCaList",
      "caGet",
      "caRawDump",
      "certCaInfo",
      "certCaList",
      "certGet",
      "certRawDump",
      "certUserList",
      "crlGet",
      "crlGetOcspInfoData",
      "crlRawDump",
      "crlSearch",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "caCaInfo",
            "caCaList",
            "caGet",
            "caRawDump",
            "certCaInfo",
            "certCaList",
            "certGet",
            "certRawDump",
            "certUserList",
            "crlGet",
            "crlGetOcspInfoData",
            "crlRawDump",
            "crlSearch",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "trust_write",
    "description": "Trust write operations — 11 methods: caDel, caGenerateFile, caSet, certAdd, certDel, certGenerateFile...",
    "module": "trust",
    "methods": [
      "caDel",
      "caGenerateFile",
      "caSet",
      "certAdd",
      "certDel",
      "certGenerateFile",
      "certSet",
      "crlDel",
      "crlSet",
      "settingsReconfigure",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "caDel",
            "caGenerateFile",
            "caSet",
            "certAdd",
            "certDel",
            "certGenerateFile",
            "certSet",
            "crlDel",
            "crlSet",
            "settingsReconfigure",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "unbound_read",
    "description": "Unbound read operations — 19 methods: diagnosticsDumpcache, diagnosticsDumpinfra, diagnosticsListinsecure, diagnosticsListlocaldata, diagnosticsListlocalzones, diagnosticsStats...",
    "module": "unbound",
    "methods": [
      "diagnosticsDumpcache",
      "diagnosticsDumpinfra",
      "diagnosticsListinsecure",
      "diagnosticsListlocaldata",
      "diagnosticsListlocalzones",
      "diagnosticsStats",
      "overviewRolling",
      "overviewIsBlockListEnabled",
      "overviewIsEnabled",
      "overviewSearchQueries",
      "overviewTotals",
      "serviceDnsbl",
      "serviceStatus",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetForward",
      "settingsGetHostAlias",
      "settingsGetHostOverride",
      "settingsGetNameservers"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "diagnosticsDumpcache",
            "diagnosticsDumpinfra",
            "diagnosticsListinsecure",
            "diagnosticsListlocaldata",
            "diagnosticsListlocalzones",
            "diagnosticsStats",
            "overviewRolling",
            "overviewIsBlockListEnabled",
            "overviewIsEnabled",
            "overviewSearchQueries",
            "overviewTotals",
            "serviceDnsbl",
            "serviceStatus",
            "settingsGet",
            "settingsGetAcl",
            "settingsGetForward",
            "settingsGetHostAlias",
            "settingsGetHostOverride",
            "settingsGetNameservers"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "unbound_write",
    "description": "Unbound write operations — 23 methods: serviceReconfigure, serviceReconfigureGeneral, serviceRestart, serviceStart, serviceStop, settingsAddAcl...",
    "module": "unbound",
    "methods": [
      "serviceReconfigure",
      "serviceReconfigureGeneral",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddForward",
      "settingsAddHostAlias",
      "settingsAddHostOverride",
      "settingsDelAcl",
      "settingsDelForward",
      "settingsDelHostAlias",
      "settingsDelHostOverride",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetForward",
      "settingsSetHostAlias",
      "settingsSetHostOverride",
      "settingsToggleAcl",
      "settingsToggleForward",
      "settingsToggleHostAlias",
      "settingsToggleHostOverride",
      "settingsUpdateBlocklist"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceReconfigureGeneral",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddAcl",
            "settingsAddForward",
            "settingsAddHostAlias",
            "settingsAddHostOverride",
            "settingsDelAcl",
            "settingsDelForward",
            "settingsDelHostAlias",
            "settingsDelHostOverride",
            "settingsSet",
            "settingsSetAcl",
            "settingsSetForward",
            "settingsSetHostAlias",
            "settingsSetHostOverride",
            "settingsToggleAcl",
            "settingsToggleForward",
            "settingsToggleHostAlias",
            "settingsToggleHostOverride",
            "settingsUpdateBlocklist"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "wireguard_read",
    "description": "Wireguard read operations — 12 methods: clientGet, clientGetClient, clientGetClientBuilder, clientGetServerInfo, clientListServers, clientPsk...",
    "module": "wireguard",
    "methods": [
      "clientGet",
      "clientGetClient",
      "clientGetClientBuilder",
      "clientGetServerInfo",
      "clientListServers",
      "clientPsk",
      "generalGet",
      "serverGet",
      "serverGetServer",
      "serverKeyPair",
      "serviceShow",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "clientGet",
            "clientGetClient",
            "clientGetClientBuilder",
            "clientGetServerInfo",
            "clientListServers",
            "clientPsk",
            "generalGet",
            "serverGet",
            "serverGetServer",
            "serverKeyPair",
            "serviceShow",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "wireguard_write",
    "description": "Wireguard write operations — 16 methods: clientAddClient, clientAddClientBuilder, clientDelClient, clientSet, clientSetClient, clientToggleClient...",
    "module": "wireguard",
    "methods": [
      "clientAddClient",
      "clientAddClientBuilder",
      "clientDelClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "clientAddClient",
            "clientAddClientBuilder",
            "clientDelClient",
            "clientSet",
            "clientSetClient",
            "clientToggleClient",
            "generalSet",
            "serverAddServer",
            "serverDelServer",
            "serverSet",
            "serverSetServer",
            "serverToggleServer",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_acmeclient_read",
    "description": "Acmeclient read operations — 17 methods: accountsGet, accountsRegister, actionsGet, actionsSftpGetIdentity, actionsSftpTestConnection, actionsSshGetIdentity...",
    "module": "plugins",
    "submodule": "acmeclient",
    "methods": [
      "accountsGet",
      "accountsRegister",
      "actionsGet",
      "actionsSftpGetIdentity",
      "actionsSftpTestConnection",
      "actionsSshGetIdentity",
      "actionsSshTestConnection",
      "certificatesAutomation",
      "certificatesGet",
      "serviceConfigtest",
      "serviceStatus",
      "settingsFetchCronIntegration",
      "settingsFetchHAProxyIntegration",
      "settingsGet",
      "settingsGetBindPluginStatus",
      "settingsGetGcloudPluginStatus",
      "validationsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "accountsGet",
            "accountsRegister",
            "actionsGet",
            "actionsSftpGetIdentity",
            "actionsSftpTestConnection",
            "actionsSshGetIdentity",
            "actionsSshTestConnection",
            "certificatesAutomation",
            "certificatesGet",
            "serviceConfigtest",
            "serviceStatus",
            "settingsFetchCronIntegration",
            "settingsFetchHAProxyIntegration",
            "settingsGet",
            "settingsGetBindPluginStatus",
            "settingsGetGcloudPluginStatus",
            "validationsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_acmeclient_write",
    "description": "Acmeclient write operations — 31 methods: accountsAdd, accountsDel, accountsSet, accountsToggle, accountsUpdate, actionsAdd...",
    "module": "plugins",
    "submodule": "acmeclient",
    "methods": [
      "accountsAdd",
      "accountsDel",
      "accountsSet",
      "accountsToggle",
      "accountsUpdate",
      "actionsAdd",
      "actionsDel",
      "actionsSet",
      "actionsToggle",
      "actionsUpdate",
      "certificatesAdd",
      "certificatesDel",
      "certificatesImport",
      "certificatesRemovekey",
      "certificatesRevoke",
      "certificatesSet",
      "certificatesSign",
      "certificatesToggle",
      "certificatesUpdate",
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceSignallcerts",
      "serviceStart",
      "serviceStop",
      "settingsSet",
      "validationsAdd",
      "validationsDel",
      "validationsSet",
      "validationsToggle",
      "validationsUpdate"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "accountsAdd",
            "accountsDel",
            "accountsSet",
            "accountsToggle",
            "accountsUpdate",
            "actionsAdd",
            "actionsDel",
            "actionsSet",
            "actionsToggle",
            "actionsUpdate",
            "certificatesAdd",
            "certificatesDel",
            "certificatesImport",
            "certificatesRemovekey",
            "certificatesRevoke",
            "certificatesSet",
            "certificatesSign",
            "certificatesToggle",
            "certificatesUpdate",
            "serviceReconfigure",
            "serviceReset",
            "serviceRestart",
            "serviceSignallcerts",
            "serviceStart",
            "serviceStop",
            "settingsSet",
            "validationsAdd",
            "validationsDel",
            "validationsSet",
            "validationsToggle",
            "validationsUpdate"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_apcupsd_read",
    "description": "Apcupsd read operations — 3 methods: serviceGetUpsStatus, serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "apcupsd",
    "methods": [
      "serviceGetUpsStatus",
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceGetUpsStatus",
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_apcupsd_write",
    "description": "Apcupsd write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "apcupsd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_bind_read",
    "description": "Bind read operations — 14 methods: aclGet, aclGetAcl, dnsblGet, domainGet, domainGetDomain, domainSearchMasterDomain...",
    "module": "plugins",
    "submodule": "bind",
    "methods": [
      "aclGet",
      "aclGetAcl",
      "dnsblGet",
      "domainGet",
      "domainGetDomain",
      "domainSearchMasterDomain",
      "domainSearchSlaveDomain",
      "generalGet",
      "generalZoneshow",
      "generalZonetest",
      "recordGet",
      "recordGetRecord",
      "serviceDnsbl",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "aclGet",
            "aclGetAcl",
            "dnsblGet",
            "domainGet",
            "domainGetDomain",
            "domainSearchMasterDomain",
            "domainSearchSlaveDomain",
            "generalGet",
            "generalZoneshow",
            "generalZonetest",
            "recordGet",
            "recordGetRecord",
            "serviceDnsbl",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_bind_write",
    "description": "Bind write operations — 22 methods: aclAddAcl, aclDelAcl, aclSet, aclSetAcl, aclToggleAcl, dnsblSet...",
    "module": "plugins",
    "submodule": "bind",
    "methods": [
      "aclAddAcl",
      "aclDelAcl",
      "aclSet",
      "aclSetAcl",
      "aclToggleAcl",
      "dnsblSet",
      "domainAddPrimaryDomain",
      "domainAddSecondaryDomain",
      "domainDelDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalSet",
      "recordAddRecord",
      "recordDelRecord",
      "recordSet",
      "recordSetRecord",
      "recordToggleRecord",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "aclAddAcl",
            "aclDelAcl",
            "aclSet",
            "aclSetAcl",
            "aclToggleAcl",
            "dnsblSet",
            "domainAddPrimaryDomain",
            "domainAddSecondaryDomain",
            "domainDelDomain",
            "domainSet",
            "domainSetDomain",
            "domainToggleDomain",
            "generalSet",
            "recordAddRecord",
            "recordDelRecord",
            "recordSet",
            "recordSetRecord",
            "recordToggleRecord",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_caddy_read",
    "description": "Caddy read operations — 16 methods: diagnosticsCaddyfile, diagnosticsConfig, diagnosticsGet, generalGet, reverseProxyGet, reverseProxyGetAccessList...",
    "module": "plugins",
    "submodule": "caddy",
    "methods": [
      "diagnosticsCaddyfile",
      "diagnosticsConfig",
      "diagnosticsGet",
      "generalGet",
      "reverseProxyGet",
      "reverseProxyGetAccessList",
      "reverseProxyGetAllReverseDomains",
      "reverseProxyGetBasicAuth",
      "reverseProxyGetHandle",
      "reverseProxyGetHeader",
      "reverseProxyGetLayer4",
      "reverseProxyGetLayer4Openvpn",
      "reverseProxyGetReverseProxy",
      "reverseProxyGetSubdomain",
      "serviceStatus",
      "serviceValidate"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "diagnosticsCaddyfile",
            "diagnosticsConfig",
            "diagnosticsGet",
            "generalGet",
            "reverseProxyGet",
            "reverseProxyGetAccessList",
            "reverseProxyGetAllReverseDomains",
            "reverseProxyGetBasicAuth",
            "reverseProxyGetHandle",
            "reverseProxyGetHeader",
            "reverseProxyGetLayer4",
            "reverseProxyGetLayer4Openvpn",
            "reverseProxyGetReverseProxy",
            "reverseProxyGetSubdomain",
            "serviceStatus",
            "serviceValidate"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_caddy_write",
    "description": "Caddy write operations — 36 methods: diagnosticsSet, generalSet, reverseProxyAddAccessList, reverseProxyAddBasicAuth, reverseProxyAddHandle, reverseProxyAddHeader...",
    "module": "plugins",
    "submodule": "caddy",
    "methods": [
      "diagnosticsSet",
      "generalSet",
      "reverseProxyAddAccessList",
      "reverseProxyAddBasicAuth",
      "reverseProxyAddHandle",
      "reverseProxyAddHeader",
      "reverseProxyAddLayer4",
      "reverseProxyAddLayer4Openvpn",
      "reverseProxyAddReverseProxy",
      "reverseProxyAddSubdomain",
      "reverseProxyDelAccessList",
      "reverseProxyDelBasicAuth",
      "reverseProxyDelHandle",
      "reverseProxyDelHeader",
      "reverseProxyDelLayer4",
      "reverseProxyDelLayer4Openvpn",
      "reverseProxyDelReverseProxy",
      "reverseProxyDelSubdomain",
      "reverseProxySet",
      "reverseProxySetAccessList",
      "reverseProxySetBasicAuth",
      "reverseProxySetHandle",
      "reverseProxySetHeader",
      "reverseProxySetLayer4",
      "reverseProxySetLayer4Openvpn",
      "reverseProxySetReverseProxy",
      "reverseProxySetSubdomain",
      "reverseProxyToggleHandle",
      "reverseProxyToggleLayer4",
      "reverseProxyToggleLayer4Openvpn",
      "reverseProxyToggleReverseProxy",
      "reverseProxyToggleSubdomain",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "diagnosticsSet",
            "generalSet",
            "reverseProxyAddAccessList",
            "reverseProxyAddBasicAuth",
            "reverseProxyAddHandle",
            "reverseProxyAddHeader",
            "reverseProxyAddLayer4",
            "reverseProxyAddLayer4Openvpn",
            "reverseProxyAddReverseProxy",
            "reverseProxyAddSubdomain",
            "reverseProxyDelAccessList",
            "reverseProxyDelBasicAuth",
            "reverseProxyDelHandle",
            "reverseProxyDelHeader",
            "reverseProxyDelLayer4",
            "reverseProxyDelLayer4Openvpn",
            "reverseProxyDelReverseProxy",
            "reverseProxyDelSubdomain",
            "reverseProxySet",
            "reverseProxySetAccessList",
            "reverseProxySetBasicAuth",
            "reverseProxySetHandle",
            "reverseProxySetHeader",
            "reverseProxySetLayer4",
            "reverseProxySetLayer4Openvpn",
            "reverseProxySetReverseProxy",
            "reverseProxySetSubdomain",
            "reverseProxyToggleHandle",
            "reverseProxyToggleLayer4",
            "reverseProxyToggleLayer4Openvpn",
            "reverseProxyToggleReverseProxy",
            "reverseProxyToggleSubdomain",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_chrony_read",
    "description": "Chrony read operations — 6 methods: generalGet, serviceChronyauthdata, serviceChronysources, serviceChronysourcestats, serviceChronytracking, serviceStatus",
    "module": "plugins",
    "submodule": "chrony",
    "methods": [
      "generalGet",
      "serviceChronyauthdata",
      "serviceChronysources",
      "serviceChronysourcestats",
      "serviceChronytracking",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceChronyauthdata",
            "serviceChronysources",
            "serviceChronysourcestats",
            "serviceChronytracking",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_chrony_write",
    "description": "Chrony write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "chrony",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_cicap_read",
    "description": "Cicap read operations — 4 methods: antivirusGet, generalGet, serviceCheckclamav, serviceStatus",
    "module": "plugins",
    "submodule": "cicap",
    "methods": [
      "antivirusGet",
      "generalGet",
      "serviceCheckclamav",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "antivirusGet",
            "generalGet",
            "serviceCheckclamav",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_cicap_write",
    "description": "Cicap write operations — 6 methods: antivirusSet, generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "cicap",
    "methods": [
      "antivirusSet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "antivirusSet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_clamav_read",
    "description": "Clamav read operations — 6 methods: generalGet, serviceFreshclam, serviceStatus, serviceVersion, urlGet, urlGetUrl",
    "module": "plugins",
    "submodule": "clamav",
    "methods": [
      "generalGet",
      "serviceFreshclam",
      "serviceStatus",
      "serviceVersion",
      "urlGet",
      "urlGetUrl"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceFreshclam",
            "serviceStatus",
            "serviceVersion",
            "urlGet",
            "urlGetUrl"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_clamav_write",
    "description": "Clamav write operations — 10 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop, urlAddUrl...",
    "module": "plugins",
    "submodule": "clamav",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "urlAddUrl",
      "urlDelUrl",
      "urlSet",
      "urlSetUrl",
      "urlToggleUrl"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "urlAddUrl",
            "urlDelUrl",
            "urlSet",
            "urlSetUrl",
            "urlToggleUrl"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_collectd_read",
    "description": "Collectd read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "collectd",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_collectd_write",
    "description": "Collectd write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "collectd",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_crowdsec_read",
    "description": "Crowdsec read operations — 9 methods: alertsGet, bouncersGet, decisionsGet, generalGet, hubGet, machinesGet...",
    "module": "plugins",
    "submodule": "crowdsec",
    "methods": [
      "alertsGet",
      "bouncersGet",
      "decisionsGet",
      "generalGet",
      "hubGet",
      "machinesGet",
      "serviceDebug",
      "serviceStatus",
      "versionGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "alertsGet",
            "bouncersGet",
            "decisionsGet",
            "generalGet",
            "hubGet",
            "machinesGet",
            "serviceDebug",
            "serviceStatus",
            "versionGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_crowdsec_write",
    "description": "Crowdsec write operations — 3 methods: decisionsDelete, generalSet, serviceReload",
    "module": "plugins",
    "submodule": "crowdsec",
    "methods": [
      "decisionsDelete",
      "generalSet",
      "serviceReload"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "decisionsDelete",
            "generalSet",
            "serviceReload"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dechw_read",
    "description": "Dechw read operations — 1 methods: infoPowerStatus",
    "module": "plugins",
    "submodule": "dechw",
    "methods": [
      "infoPowerStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "infoPowerStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_diagnostics_read",
    "description": "Diagnostics read operations — 1 methods: proofpointEtStatus",
    "module": "plugins",
    "submodule": "diagnostics",
    "methods": [
      "proofpointEtStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "proofpointEtStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dmidecode_read",
    "description": "Dmidecode read operations — 1 methods: serviceGet",
    "module": "plugins",
    "submodule": "dmidecode",
    "methods": [
      "serviceGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dnscryptproxy_read",
    "description": "Dnscryptproxy read operations — 12 methods: cloakGet, cloakGetCloak, dnsblGet, forwardGet, forwardGetForward, generalGet...",
    "module": "plugins",
    "submodule": "dnscryptproxy",
    "methods": [
      "cloakGet",
      "cloakGetCloak",
      "dnsblGet",
      "forwardGet",
      "forwardGetForward",
      "generalGet",
      "serverGet",
      "serverGetServer",
      "serviceDnsbl",
      "serviceStatus",
      "whitelistGet",
      "whitelistGetWhitelist"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "cloakGet",
            "cloakGetCloak",
            "dnsblGet",
            "forwardGet",
            "forwardGetForward",
            "generalGet",
            "serverGet",
            "serverGetServer",
            "serviceDnsbl",
            "serviceStatus",
            "whitelistGet",
            "whitelistGetWhitelist"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dnscryptproxy_write",
    "description": "Dnscryptproxy write operations — 26 methods: cloakAddCloak, cloakDelCloak, cloakSet, cloakSetCloak, cloakToggleCloak, dnsblSet...",
    "module": "plugins",
    "submodule": "dnscryptproxy",
    "methods": [
      "cloakAddCloak",
      "cloakDelCloak",
      "cloakSet",
      "cloakSetCloak",
      "cloakToggleCloak",
      "dnsblSet",
      "forwardAddForward",
      "forwardDelForward",
      "forwardSet",
      "forwardSetForward",
      "forwardToggleForward",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "whitelistAddWhitelist",
      "whitelistDelWhitelist",
      "whitelistSet",
      "whitelistSetWhitelist",
      "whitelistToggleWhitelist"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "cloakAddCloak",
            "cloakDelCloak",
            "cloakSet",
            "cloakSetCloak",
            "cloakToggleCloak",
            "dnsblSet",
            "forwardAddForward",
            "forwardDelForward",
            "forwardSet",
            "forwardSetForward",
            "forwardToggleForward",
            "generalSet",
            "serverAddServer",
            "serverDelServer",
            "serverSet",
            "serverSetServer",
            "serverToggleServer",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "whitelistAddWhitelist",
            "whitelistDelWhitelist",
            "whitelistSet",
            "whitelistSetWhitelist",
            "whitelistToggleWhitelist"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dyndns_read",
    "description": "Dyndns read operations — 4 methods: accountsGet, accountsGetItem, serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "dyndns",
    "methods": [
      "accountsGet",
      "accountsGetItem",
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "accountsGet",
            "accountsGetItem",
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dyndns_write",
    "description": "Dyndns write operations — 10 methods: accountsAddItem, accountsDelItem, accountsSet, accountsSetItem, accountsToggleItem, serviceReconfigure...",
    "module": "plugins",
    "submodule": "dyndns",
    "methods": [
      "accountsAddItem",
      "accountsDelItem",
      "accountsSet",
      "accountsSetItem",
      "accountsToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "accountsAddItem",
            "accountsDelItem",
            "accountsSet",
            "accountsSetItem",
            "accountsToggleItem",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_freeradius_read",
    "description": "Freeradius read operations — 23 methods: avpairGet, avpairGetAvpair, clientGet, clientGetClient, clientSearchClient, dhcpGet...",
    "module": "plugins",
    "submodule": "freeradius",
    "methods": [
      "avpairGet",
      "avpairGetAvpair",
      "clientGet",
      "clientGetClient",
      "clientSearchClient",
      "dhcpGet",
      "dhcpGetDhcp",
      "eapGet",
      "generalGet",
      "ldapGet",
      "leaseGet",
      "leaseGetLease",
      "proxyGet",
      "proxyGetHomeserver",
      "proxyGetHomeserverpool",
      "proxyGetRealm",
      "proxySearchHomeserver",
      "proxySearchHomeserverpool",
      "proxySearchRealm",
      "serviceStatus",
      "userGet",
      "userGetUser",
      "userSearchUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "avpairGet",
            "avpairGetAvpair",
            "clientGet",
            "clientGetClient",
            "clientSearchClient",
            "dhcpGet",
            "dhcpGetDhcp",
            "eapGet",
            "generalGet",
            "ldapGet",
            "leaseGet",
            "leaseGetLease",
            "proxyGet",
            "proxyGetHomeserver",
            "proxyGetHomeserverpool",
            "proxyGetRealm",
            "proxySearchHomeserver",
            "proxySearchHomeserverpool",
            "proxySearchRealm",
            "serviceStatus",
            "userGet",
            "userGetUser",
            "userSearchUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_freeradius_write",
    "description": "Freeradius write operations — 45 methods: avpairAddAvpair, avpairDelAvpair, avpairSet, avpairSetAvpair, avpairToggleAvpair, clientAddClient...",
    "module": "plugins",
    "submodule": "freeradius",
    "methods": [
      "avpairAddAvpair",
      "avpairDelAvpair",
      "avpairSet",
      "avpairSetAvpair",
      "avpairToggleAvpair",
      "clientAddClient",
      "clientDelClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "dhcpAddDhcp",
      "dhcpDelDhcp",
      "dhcpSet",
      "dhcpSetDhcp",
      "dhcpToggleDhcp",
      "eapSet",
      "generalSet",
      "ldapSet",
      "leaseAddLease",
      "leaseDelLease",
      "leaseSet",
      "leaseSetLease",
      "leaseToggleLease",
      "proxyAddHomeserver",
      "proxyAddHomeserverpool",
      "proxyAddRealm",
      "proxyDelHomeserver",
      "proxyDelHomeserverpool",
      "proxyDelRealm",
      "proxySet",
      "proxySetHomeserver",
      "proxySetHomeserverpool",
      "proxySetRealm",
      "proxyToggleHomeserver",
      "proxyToggleHomeserverpool",
      "proxyToggleRealm",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "avpairAddAvpair",
            "avpairDelAvpair",
            "avpairSet",
            "avpairSetAvpair",
            "avpairToggleAvpair",
            "clientAddClient",
            "clientDelClient",
            "clientSet",
            "clientSetClient",
            "clientToggleClient",
            "dhcpAddDhcp",
            "dhcpDelDhcp",
            "dhcpSet",
            "dhcpSetDhcp",
            "dhcpToggleDhcp",
            "eapSet",
            "generalSet",
            "ldapSet",
            "leaseAddLease",
            "leaseDelLease",
            "leaseSet",
            "leaseSetLease",
            "leaseToggleLease",
            "proxyAddHomeserver",
            "proxyAddHomeserverpool",
            "proxyAddRealm",
            "proxyDelHomeserver",
            "proxyDelHomeserverpool",
            "proxyDelRealm",
            "proxySet",
            "proxySetHomeserver",
            "proxySetHomeserverpool",
            "proxySetRealm",
            "proxyToggleHomeserver",
            "proxyToggleHomeserverpool",
            "proxyToggleRealm",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "userAddUser",
            "userDelUser",
            "userSet",
            "userSetUser",
            "userToggleUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ftpproxy_read",
    "description": "Ftpproxy read operations — 4 methods: serviceConfig, serviceStatus, settingsGetProxy, settingsSearchProxy",
    "module": "plugins",
    "submodule": "ftpproxy",
    "methods": [
      "serviceConfig",
      "serviceStatus",
      "settingsGetProxy",
      "settingsSearchProxy"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceConfig",
            "serviceStatus",
            "settingsGetProxy",
            "settingsSearchProxy"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ftpproxy_write",
    "description": "Ftpproxy write operations — 8 methods: serviceReload, serviceRestart, serviceStart, serviceStop, settingsAddProxy, settingsDelProxy...",
    "module": "plugins",
    "submodule": "ftpproxy",
    "methods": [
      "serviceReload",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddProxy",
      "settingsDelProxy",
      "settingsSetProxy",
      "settingsToggleProxy"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReload",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddProxy",
            "settingsDelProxy",
            "settingsSetProxy",
            "settingsToggleProxy"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_gridexample_read",
    "description": "Gridexample read operations — 2 methods: settingsGet, settingsGetItem",
    "module": "plugins",
    "submodule": "gridexample",
    "methods": [
      "settingsGet",
      "settingsGetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "settingsGet",
            "settingsGetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_gridexample_write",
    "description": "Gridexample write operations — 5 methods: settingsAddItem, settingsDelItem, settingsSet, settingsSetItem, settingsToggleItem",
    "module": "plugins",
    "submodule": "gridexample",
    "methods": [
      "settingsAddItem",
      "settingsDelItem",
      "settingsSet",
      "settingsSetItem",
      "settingsToggleItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "settingsAddItem",
            "settingsDelItem",
            "settingsSet",
            "settingsSetItem",
            "settingsToggleItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_haproxy_read",
    "description": "Haproxy read operations — 36 methods: exportConfig, exportDiff, exportDownload, maintenanceCertActions, maintenanceCertDiff, maintenanceCertSync...",
    "module": "plugins",
    "submodule": "haproxy",
    "methods": [
      "exportConfig",
      "exportDiff",
      "exportDownload",
      "maintenanceCertActions",
      "maintenanceCertDiff",
      "maintenanceCertSync",
      "maintenanceCertSyncBulk",
      "maintenanceFetchCronIntegration",
      "maintenanceGet",
      "maintenanceSearchCertificateDiff",
      "maintenanceSearchServer",
      "maintenanceServerState",
      "maintenanceServerStateBulk",
      "maintenanceServerWeight",
      "maintenanceServerWeightBulk",
      "serviceConfigtest",
      "serviceStatus",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetAction",
      "settingsGetBackend",
      "settingsGetCpu",
      "settingsGetErrorfile",
      "settingsGetFcgi",
      "settingsGetFrontend",
      "settingsGetGroup",
      "settingsGetHealthcheck",
      "settingsGetLua",
      "settingsGetMapfile",
      "settingsGetServer",
      "settingsGetUser",
      "settingsGetmailer",
      "settingsGetresolver",
      "statisticsCounters",
      "statisticsInfo",
      "statisticsTables"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "exportConfig",
            "exportDiff",
            "exportDownload",
            "maintenanceCertActions",
            "maintenanceCertDiff",
            "maintenanceCertSync",
            "maintenanceCertSyncBulk",
            "maintenanceFetchCronIntegration",
            "maintenanceGet",
            "maintenanceSearchCertificateDiff",
            "maintenanceSearchServer",
            "maintenanceServerState",
            "maintenanceServerStateBulk",
            "maintenanceServerWeight",
            "maintenanceServerWeightBulk",
            "serviceConfigtest",
            "serviceStatus",
            "settingsGet",
            "settingsGetAcl",
            "settingsGetAction",
            "settingsGetBackend",
            "settingsGetCpu",
            "settingsGetErrorfile",
            "settingsGetFcgi",
            "settingsGetFrontend",
            "settingsGetGroup",
            "settingsGetHealthcheck",
            "settingsGetLua",
            "settingsGetMapfile",
            "settingsGetServer",
            "settingsGetUser",
            "settingsGetmailer",
            "settingsGetresolver",
            "statisticsCounters",
            "statisticsInfo",
            "statisticsTables"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_haproxy_write",
    "description": "Haproxy write operations — 60 methods: maintenanceSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsAddAcl...",
    "module": "plugins",
    "submodule": "haproxy",
    "methods": [
      "maintenanceSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddAction",
      "settingsAddBackend",
      "settingsAddCpu",
      "settingsAddErrorfile",
      "settingsAddFcgi",
      "settingsAddFrontend",
      "settingsAddGroup",
      "settingsAddHealthcheck",
      "settingsAddLua",
      "settingsAddMapfile",
      "settingsAddServer",
      "settingsAddUser",
      "settingsAddmailer",
      "settingsAddresolver",
      "settingsDelAcl",
      "settingsDelAction",
      "settingsDelBackend",
      "settingsDelCpu",
      "settingsDelErrorfile",
      "settingsDelFcgi",
      "settingsDelFrontend",
      "settingsDelGroup",
      "settingsDelHealthcheck",
      "settingsDelLua",
      "settingsDelMapfile",
      "settingsDelServer",
      "settingsDelUser",
      "settingsDelmailer",
      "settingsDelresolver",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetAction",
      "settingsSetBackend",
      "settingsSetCpu",
      "settingsSetErrorfile",
      "settingsSetFcgi",
      "settingsSetFrontend",
      "settingsSetGroup",
      "settingsSetHealthcheck",
      "settingsSetLua",
      "settingsSetMapfile",
      "settingsSetServer",
      "settingsSetUser",
      "settingsSetmailer",
      "settingsSetresolver",
      "settingsToggleBackend",
      "settingsToggleCpu",
      "settingsToggleFrontend",
      "settingsToggleGroup",
      "settingsToggleLua",
      "settingsToggleServer",
      "settingsToggleUser",
      "settingsTogglemailer",
      "settingsToggleresolver"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "maintenanceSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddAcl",
            "settingsAddAction",
            "settingsAddBackend",
            "settingsAddCpu",
            "settingsAddErrorfile",
            "settingsAddFcgi",
            "settingsAddFrontend",
            "settingsAddGroup",
            "settingsAddHealthcheck",
            "settingsAddLua",
            "settingsAddMapfile",
            "settingsAddServer",
            "settingsAddUser",
            "settingsAddmailer",
            "settingsAddresolver",
            "settingsDelAcl",
            "settingsDelAction",
            "settingsDelBackend",
            "settingsDelCpu",
            "settingsDelErrorfile",
            "settingsDelFcgi",
            "settingsDelFrontend",
            "settingsDelGroup",
            "settingsDelHealthcheck",
            "settingsDelLua",
            "settingsDelMapfile",
            "settingsDelServer",
            "settingsDelUser",
            "settingsDelmailer",
            "settingsDelresolver",
            "settingsSet",
            "settingsSetAcl",
            "settingsSetAction",
            "settingsSetBackend",
            "settingsSetCpu",
            "settingsSetErrorfile",
            "settingsSetFcgi",
            "settingsSetFrontend",
            "settingsSetGroup",
            "settingsSetHealthcheck",
            "settingsSetLua",
            "settingsSetMapfile",
            "settingsSetServer",
            "settingsSetUser",
            "settingsSetmailer",
            "settingsSetresolver",
            "settingsToggleBackend",
            "settingsToggleCpu",
            "settingsToggleFrontend",
            "settingsToggleGroup",
            "settingsToggleLua",
            "settingsToggleServer",
            "settingsToggleUser",
            "settingsTogglemailer",
            "settingsToggleresolver"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_helloworld_read",
    "description": "Helloworld read operations — 2 methods: serviceTest, settingsGet",
    "module": "plugins",
    "submodule": "helloworld",
    "methods": [
      "serviceTest",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceTest",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_helloworld_write",
    "description": "Helloworld write operations — 2 methods: serviceReload, settingsSet",
    "module": "plugins",
    "submodule": "helloworld",
    "methods": [
      "serviceReload",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReload",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_hwprobe_read",
    "description": "Hwprobe read operations — 3 methods: generalGet, serviceReport, serviceStatus",
    "module": "plugins",
    "submodule": "hwprobe",
    "methods": [
      "generalGet",
      "serviceReport",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceReport",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_hwprobe_write",
    "description": "Hwprobe write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "hwprobe",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_iperf_read",
    "description": "Iperf read operations — 3 methods: instanceGet, instanceQuery, serviceStatus",
    "module": "plugins",
    "submodule": "iperf",
    "methods": [
      "instanceGet",
      "instanceQuery",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "instanceGet",
            "instanceQuery",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_iperf_write",
    "description": "Iperf write operations — 4 methods: instanceSet, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "iperf",
    "methods": [
      "instanceSet",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "instanceSet",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_lldpd_read",
    "description": "Lldpd read operations — 3 methods: generalGet, serviceNeighbor, serviceStatus",
    "module": "plugins",
    "submodule": "lldpd",
    "methods": [
      "generalGet",
      "serviceNeighbor",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceNeighbor",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_lldpd_write",
    "description": "Lldpd write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "lldpd",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_maltrail_read",
    "description": "Maltrail read operations — 5 methods: generalGet, sensorGet, serverGet, serverserviceStatus, serviceStatus",
    "module": "plugins",
    "submodule": "maltrail",
    "methods": [
      "generalGet",
      "sensorGet",
      "serverGet",
      "serverserviceStatus",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "sensorGet",
            "serverGet",
            "serverserviceStatus",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_maltrail_write",
    "description": "Maltrail write operations — 11 methods: generalSet, sensorSet, serverSet, serverserviceReconfigure, serverserviceRestart, serverserviceStart...",
    "module": "plugins",
    "submodule": "maltrail",
    "methods": [
      "generalSet",
      "sensorSet",
      "serverSet",
      "serverserviceReconfigure",
      "serverserviceRestart",
      "serverserviceStart",
      "serverserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "sensorSet",
            "serverSet",
            "serverserviceReconfigure",
            "serverserviceRestart",
            "serverserviceStart",
            "serverserviceStop",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_mdnsrepeater_read",
    "description": "Mdnsrepeater read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "mdnsrepeater",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_mdnsrepeater_write",
    "description": "Mdnsrepeater write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "mdnsrepeater",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_muninnode_read",
    "description": "Muninnode read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "muninnode",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_muninnode_write",
    "description": "Muninnode write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "muninnode",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ndproxy_read",
    "description": "Ndproxy read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "ndproxy",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ndproxy_write",
    "description": "Ndproxy write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "ndproxy",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_netdata_read",
    "description": "Netdata read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "netdata",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_netdata_write",
    "description": "Netdata write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "netdata",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_netsnmp_read",
    "description": "Netsnmp read operations — 4 methods: generalGet, serviceStatus, userGet, userGetUser",
    "module": "plugins",
    "submodule": "netsnmp",
    "methods": [
      "generalGet",
      "serviceStatus",
      "userGet",
      "userGetUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus",
            "userGet",
            "userGetUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_netsnmp_write",
    "description": "Netsnmp write operations — 10 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop, userAddUser...",
    "module": "plugins",
    "submodule": "netsnmp",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "userAddUser",
            "userDelUser",
            "userSet",
            "userSetUser",
            "userToggleUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nginx_read",
    "description": "Nginx read operations — 32 methods: bansGet, logsAccesses, logsErrors, logsStreamaccesses, logsStreamerrors, logsTlsHandshakes...",
    "module": "plugins",
    "submodule": "nginx",
    "methods": [
      "bansGet",
      "logsAccesses",
      "logsErrors",
      "logsStreamaccesses",
      "logsStreamerrors",
      "logsTlsHandshakes",
      "serviceStatus",
      "serviceVts",
      "settingsDownloadrules",
      "settingsGet",
      "settingsGetcachePath",
      "settingsGetcredential",
      "settingsGetcustompolicy",
      "settingsGeterrorpage",
      "settingsGethttprewrite",
      "settingsGethttpserver",
      "settingsGetipacl",
      "settingsGetlimitRequestConnection",
      "settingsGetlimitZone",
      "settingsGetlocation",
      "settingsGetnaxsirule",
      "settingsGetresolver",
      "settingsGetsecurityHeader",
      "settingsGetsnifwd",
      "settingsGetstreamserver",
      "settingsGetsyslogTarget",
      "settingsGettlsFingerprint",
      "settingsGetupstream",
      "settingsGetupstreamserver",
      "settingsGetuserlist",
      "settingsShowconfig",
      "settingsTestconfig"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "bansGet",
            "logsAccesses",
            "logsErrors",
            "logsStreamaccesses",
            "logsStreamerrors",
            "logsTlsHandshakes",
            "serviceStatus",
            "serviceVts",
            "settingsDownloadrules",
            "settingsGet",
            "settingsGetcachePath",
            "settingsGetcredential",
            "settingsGetcustompolicy",
            "settingsGeterrorpage",
            "settingsGethttprewrite",
            "settingsGethttpserver",
            "settingsGetipacl",
            "settingsGetlimitRequestConnection",
            "settingsGetlimitZone",
            "settingsGetlocation",
            "settingsGetnaxsirule",
            "settingsGetresolver",
            "settingsGetsecurityHeader",
            "settingsGetsnifwd",
            "settingsGetstreamserver",
            "settingsGetsyslogTarget",
            "settingsGettlsFingerprint",
            "settingsGetupstream",
            "settingsGetupstreamserver",
            "settingsGetuserlist",
            "settingsShowconfig",
            "settingsTestconfig"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nginx_write",
    "description": "Nginx write operations — 67 methods: bansDelban, bansSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop...",
    "module": "plugins",
    "submodule": "nginx",
    "methods": [
      "bansDelban",
      "bansSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddcachePath",
      "settingsAddcredential",
      "settingsAddcustompolicy",
      "settingsAdderrorpage",
      "settingsAddhttprewrite",
      "settingsAddhttpserver",
      "settingsAddipacl",
      "settingsAddlimitRequestConnection",
      "settingsAddlimitZone",
      "settingsAddlocation",
      "settingsAddnaxsirule",
      "settingsAddresolver",
      "settingsAddsecurityHeader",
      "settingsAddsnifwd",
      "settingsAddstreamserver",
      "settingsAddsyslogTarget",
      "settingsAddtlsFingerprint",
      "settingsAddupstream",
      "settingsAddupstreamserver",
      "settingsAdduserlist",
      "settingsDelcachePath",
      "settingsDelcredential",
      "settingsDelcustompolicy",
      "settingsDelerrorpage",
      "settingsDelhttprewrite",
      "settingsDelhttpserver",
      "settingsDelipacl",
      "settingsDellimitRequestConnection",
      "settingsDellimitZone",
      "settingsDellocation",
      "settingsDelnaxsirule",
      "settingsDelresolver",
      "settingsDelsecurityHeader",
      "settingsDelsnifwd",
      "settingsDelstreamserver",
      "settingsDelsyslogTarget",
      "settingsDeltlsFingerprint",
      "settingsDelupstream",
      "settingsDelupstreamserver",
      "settingsDeluserlist",
      "settingsSet",
      "settingsSetcachePath",
      "settingsSetcredential",
      "settingsSetcustompolicy",
      "settingsSeterrorpage",
      "settingsSethttprewrite",
      "settingsSethttpserver",
      "settingsSetipacl",
      "settingsSetlimitRequestConnection",
      "settingsSetlimitZone",
      "settingsSetlocation",
      "settingsSetnaxsirule",
      "settingsSetresolver",
      "settingsSetsecurityHeader",
      "settingsSetsnifwd",
      "settingsSetstreamserver",
      "settingsSetsyslogTarget",
      "settingsSettlsFingerprint",
      "settingsSetupstream",
      "settingsSetupstreamserver",
      "settingsSetuserlist"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "bansDelban",
            "bansSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddcachePath",
            "settingsAddcredential",
            "settingsAddcustompolicy",
            "settingsAdderrorpage",
            "settingsAddhttprewrite",
            "settingsAddhttpserver",
            "settingsAddipacl",
            "settingsAddlimitRequestConnection",
            "settingsAddlimitZone",
            "settingsAddlocation",
            "settingsAddnaxsirule",
            "settingsAddresolver",
            "settingsAddsecurityHeader",
            "settingsAddsnifwd",
            "settingsAddstreamserver",
            "settingsAddsyslogTarget",
            "settingsAddtlsFingerprint",
            "settingsAddupstream",
            "settingsAddupstreamserver",
            "settingsAdduserlist",
            "settingsDelcachePath",
            "settingsDelcredential",
            "settingsDelcustompolicy",
            "settingsDelerrorpage",
            "settingsDelhttprewrite",
            "settingsDelhttpserver",
            "settingsDelipacl",
            "settingsDellimitRequestConnection",
            "settingsDellimitZone",
            "settingsDellocation",
            "settingsDelnaxsirule",
            "settingsDelresolver",
            "settingsDelsecurityHeader",
            "settingsDelsnifwd",
            "settingsDelstreamserver",
            "settingsDelsyslogTarget",
            "settingsDeltlsFingerprint",
            "settingsDelupstream",
            "settingsDelupstreamserver",
            "settingsDeluserlist",
            "settingsSet",
            "settingsSetcachePath",
            "settingsSetcredential",
            "settingsSetcustompolicy",
            "settingsSeterrorpage",
            "settingsSethttprewrite",
            "settingsSethttpserver",
            "settingsSetipacl",
            "settingsSetlimitRequestConnection",
            "settingsSetlimitZone",
            "settingsSetlocation",
            "settingsSetnaxsirule",
            "settingsSetresolver",
            "settingsSetsecurityHeader",
            "settingsSetsnifwd",
            "settingsSetstreamserver",
            "settingsSetsyslogTarget",
            "settingsSettlsFingerprint",
            "settingsSetupstream",
            "settingsSetupstreamserver",
            "settingsSetuserlist"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nodeexporter_read",
    "description": "Nodeexporter read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "nodeexporter",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nodeexporter_write",
    "description": "Nodeexporter write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "nodeexporter",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nrpe_read",
    "description": "Nrpe read operations — 4 methods: commandGet, commandGetCommand, generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "nrpe",
    "methods": [
      "commandGet",
      "commandGetCommand",
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "commandGet",
            "commandGetCommand",
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nrpe_write",
    "description": "Nrpe write operations — 10 methods: commandAddCommand, commandDelCommand, commandSet, commandSetCommand, commandToggleCommand, generalSet...",
    "module": "plugins",
    "submodule": "nrpe",
    "methods": [
      "commandAddCommand",
      "commandDelCommand",
      "commandSet",
      "commandSetCommand",
      "commandToggleCommand",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "commandAddCommand",
            "commandDelCommand",
            "commandSet",
            "commandSetCommand",
            "commandToggleCommand",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ntopng_read",
    "description": "Ntopng read operations — 3 methods: generalGet, serviceCheckredis, serviceStatus",
    "module": "plugins",
    "submodule": "ntopng",
    "methods": [
      "generalGet",
      "serviceCheckredis",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceCheckredis",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ntopng_write",
    "description": "Ntopng write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "ntopng",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nut_read",
    "description": "Nut read operations — 3 methods: diagnosticsUpsstatus, serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "nut",
    "methods": [
      "diagnosticsUpsstatus",
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "diagnosticsUpsstatus",
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nut_write",
    "description": "Nut write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "nut",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_openconnect_read",
    "description": "Openconnect read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "openconnect",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_openconnect_write",
    "description": "Openconnect write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "openconnect",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_postfix_read",
    "description": "Postfix read operations — 20 methods: addressGet, addressGetAddress, antispamGet, domainGet, domainGetDomain, generalGet...",
    "module": "plugins",
    "submodule": "postfix",
    "methods": [
      "addressGet",
      "addressGetAddress",
      "antispamGet",
      "domainGet",
      "domainGetDomain",
      "generalGet",
      "headerchecksGet",
      "headerchecksGetHeadercheck",
      "recipientGet",
      "recipientGetRecipient",
      "recipientbccGet",
      "recipientbccGetRecipientbcc",
      "senderGet",
      "senderGetSender",
      "senderbccGet",
      "senderbccGetSenderbcc",
      "sendercanonicalGet",
      "sendercanonicalGetSendercanonical",
      "serviceCheckrspamd",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "addressGet",
            "addressGetAddress",
            "antispamGet",
            "domainGet",
            "domainGetDomain",
            "generalGet",
            "headerchecksGet",
            "headerchecksGetHeadercheck",
            "recipientGet",
            "recipientGetRecipient",
            "recipientbccGet",
            "recipientbccGetRecipientbcc",
            "senderGet",
            "senderGetSender",
            "senderbccGet",
            "senderbccGetSenderbcc",
            "sendercanonicalGet",
            "sendercanonicalGetSendercanonical",
            "serviceCheckrspamd",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_postfix_write",
    "description": "Postfix write operations — 46 methods: addressAddAddress, addressDelAddress, addressSet, addressSetAddress, addressToggleAddress, antispamSet...",
    "module": "plugins",
    "submodule": "postfix",
    "methods": [
      "addressAddAddress",
      "addressDelAddress",
      "addressSet",
      "addressSetAddress",
      "addressToggleAddress",
      "antispamSet",
      "domainAddDomain",
      "domainDelDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalSet",
      "headerchecksAddHeadercheck",
      "headerchecksDelHeadercheck",
      "headerchecksSet",
      "headerchecksSetHeadercheck",
      "headerchecksToggleHeadercheck",
      "recipientAddRecipient",
      "recipientDelRecipient",
      "recipientSet",
      "recipientSetRecipient",
      "recipientToggleRecipient",
      "recipientbccAddRecipientbcc",
      "recipientbccDelRecipientbcc",
      "recipientbccSet",
      "recipientbccSetRecipientbcc",
      "recipientbccToggleRecipientbcc",
      "senderAddSender",
      "senderDelSender",
      "senderSet",
      "senderSetSender",
      "senderToggleSender",
      "senderbccAddSenderbcc",
      "senderbccDelSenderbcc",
      "senderbccSet",
      "senderbccSetSenderbcc",
      "senderbccToggleSenderbcc",
      "sendercanonicalAddSendercanonical",
      "sendercanonicalDelSendercanonical",
      "sendercanonicalSet",
      "sendercanonicalSetSendercanonical",
      "sendercanonicalToggleSendercanonical",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "addressAddAddress",
            "addressDelAddress",
            "addressSet",
            "addressSetAddress",
            "addressToggleAddress",
            "antispamSet",
            "domainAddDomain",
            "domainDelDomain",
            "domainSet",
            "domainSetDomain",
            "domainToggleDomain",
            "generalSet",
            "headerchecksAddHeadercheck",
            "headerchecksDelHeadercheck",
            "headerchecksSet",
            "headerchecksSetHeadercheck",
            "headerchecksToggleHeadercheck",
            "recipientAddRecipient",
            "recipientDelRecipient",
            "recipientSet",
            "recipientSetRecipient",
            "recipientToggleRecipient",
            "recipientbccAddRecipientbcc",
            "recipientbccDelRecipientbcc",
            "recipientbccSet",
            "recipientbccSetRecipientbcc",
            "recipientbccToggleRecipientbcc",
            "senderAddSender",
            "senderDelSender",
            "senderSet",
            "senderSetSender",
            "senderToggleSender",
            "senderbccAddSenderbcc",
            "senderbccDelSenderbcc",
            "senderbccSet",
            "senderbccSetSenderbcc",
            "senderbccToggleSenderbcc",
            "sendercanonicalAddSendercanonical",
            "sendercanonicalDelSendercanonical",
            "sendercanonicalSet",
            "sendercanonicalSetSendercanonical",
            "sendercanonicalToggleSendercanonical",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_proxy_read",
    "description": "Proxy read operations — 15 methods: serviceDownloadacls, serviceFetchacls, serviceStatus, settingsFetchRBCron, settingsGet, settingsGetPACMatch...",
    "module": "plugins",
    "submodule": "proxy",
    "methods": [
      "serviceDownloadacls",
      "serviceFetchacls",
      "serviceStatus",
      "settingsFetchRBCron",
      "settingsGet",
      "settingsGetPACMatch",
      "settingsGetPACProxy",
      "settingsGetPACRule",
      "settingsGetRemoteBlacklist",
      "settingsSearchRemoteBlacklists",
      "templateGet",
      "aclGet",
      "aclGetCustomPolicy",
      "aclGetPolicy",
      "aclTest"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceDownloadacls",
            "serviceFetchacls",
            "serviceStatus",
            "settingsFetchRBCron",
            "settingsGet",
            "settingsGetPACMatch",
            "settingsGetPACProxy",
            "settingsGetPACRule",
            "settingsGetRemoteBlacklist",
            "settingsSearchRemoteBlacklists",
            "templateGet",
            "aclGet",
            "aclGetCustomPolicy",
            "aclGetPolicy",
            "aclTest"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_proxy_write",
    "description": "Proxy write operations — 33 methods: serviceReconfigure, serviceRefreshTemplate, serviceReset, serviceRestart, serviceStart, serviceStop...",
    "module": "plugins",
    "submodule": "proxy",
    "methods": [
      "serviceReconfigure",
      "serviceRefreshTemplate",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddPACMatch",
      "settingsAddPACProxy",
      "settingsAddPACRule",
      "settingsAddRemoteBlacklist",
      "settingsDelPACMatch",
      "settingsDelPACProxy",
      "settingsDelPACRule",
      "settingsDelRemoteBlacklist",
      "settingsSet",
      "settingsSetPACMatch",
      "settingsSetPACProxy",
      "settingsSetPACRule",
      "settingsSetRemoteBlacklist",
      "settingsTogglePACRule",
      "settingsToggleRemoteBlacklist",
      "templateReset",
      "templateSet",
      "aclAddCustomPolicy",
      "aclAddPolicy",
      "aclApply",
      "aclDelCustomPolicy",
      "aclDelPolicy",
      "aclSet",
      "aclSetCustomPolicy",
      "aclSetPolicy",
      "aclToggleCustomPolicy",
      "aclTogglePolicy"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRefreshTemplate",
            "serviceReset",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddPACMatch",
            "settingsAddPACProxy",
            "settingsAddPACRule",
            "settingsAddRemoteBlacklist",
            "settingsDelPACMatch",
            "settingsDelPACProxy",
            "settingsDelPACRule",
            "settingsDelRemoteBlacklist",
            "settingsSet",
            "settingsSetPACMatch",
            "settingsSetPACProxy",
            "settingsSetPACRule",
            "settingsSetRemoteBlacklist",
            "settingsTogglePACRule",
            "settingsToggleRemoteBlacklist",
            "templateReset",
            "templateSet",
            "aclAddCustomPolicy",
            "aclAddPolicy",
            "aclApply",
            "aclDelCustomPolicy",
            "aclDelPolicy",
            "aclSet",
            "aclSetCustomPolicy",
            "aclSetPolicy",
            "aclToggleCustomPolicy",
            "aclTogglePolicy"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_proxysso_read",
    "description": "Proxysso read operations — 4 methods: serviceGetCheckList, serviceShowkeytab, serviceTestkerblogin, settingsGet",
    "module": "plugins",
    "submodule": "proxysso",
    "methods": [
      "serviceGetCheckList",
      "serviceShowkeytab",
      "serviceTestkerblogin",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceGetCheckList",
            "serviceShowkeytab",
            "serviceTestkerblogin",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_proxysso_write",
    "description": "Proxysso write operations — 3 methods: serviceCreatekeytab, serviceDeletekeytab, settingsSet",
    "module": "plugins",
    "submodule": "proxysso",
    "methods": [
      "serviceCreatekeytab",
      "serviceDeletekeytab",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceCreatekeytab",
            "serviceDeletekeytab",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_puppetagent_read",
    "description": "Puppetagent read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "puppetagent",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_puppetagent_write",
    "description": "Puppetagent write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "puppetagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_qemuguestagent_read",
    "description": "Qemuguestagent read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "qemuguestagent",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_qemuguestagent_write",
    "description": "Qemuguestagent write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "qemuguestagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_quagga_read",
    "description": "Quagga read operations — 46 methods: bfdGet, bfdGetNeighbor, bgpGet, bgpGetAspath, bgpGetCommunitylist, bgpGetNeighbor...",
    "module": "plugins",
    "submodule": "quagga",
    "methods": [
      "bfdGet",
      "bfdGetNeighbor",
      "bgpGet",
      "bgpGetAspath",
      "bgpGetCommunitylist",
      "bgpGetNeighbor",
      "bgpGetPeergroup",
      "bgpGetPrefixlist",
      "bgpGetRedistribution",
      "bgpGetRoutemap",
      "diagnosticsBfdcounters",
      "diagnosticsBfdneighbors",
      "diagnosticsBfdsummary",
      "diagnosticsBgpneighbors",
      "diagnosticsBgpsummary",
      "diagnosticsGeneralrunningconfig",
      "diagnosticsOspfdatabase",
      "diagnosticsOspfinterface",
      "diagnosticsOspfoverview",
      "diagnosticsOspfv3interface",
      "diagnosticsOspfv3overview",
      "diagnosticsSearchBgproute4",
      "diagnosticsSearchBgproute6",
      "diagnosticsSearchGeneralroute4",
      "diagnosticsSearchGeneralroute6",
      "diagnosticsSearchOspfneighbor",
      "diagnosticsSearchOspfroute",
      "diagnosticsSearchOspfv3database",
      "diagnosticsSearchOspfv3route",
      "generalGet",
      "ospf6settingsGet",
      "ospf6settingsGetInterface",
      "ospf6settingsGetNetwork",
      "ospf6settingsGetPrefixlist",
      "ospf6settingsGetRedistribution",
      "ospf6settingsGetRoutemap",
      "ospfsettingsGet",
      "ospfsettingsGetInterface",
      "ospfsettingsGetNetwork",
      "ospfsettingsGetPrefixlist",
      "ospfsettingsGetRedistribution",
      "ospfsettingsGetRoutemap",
      "ripGet",
      "serviceStatus",
      "staticGet",
      "staticGetRoute"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "bfdGet",
            "bfdGetNeighbor",
            "bgpGet",
            "bgpGetAspath",
            "bgpGetCommunitylist",
            "bgpGetNeighbor",
            "bgpGetPeergroup",
            "bgpGetPrefixlist",
            "bgpGetRedistribution",
            "bgpGetRoutemap",
            "diagnosticsBfdcounters",
            "diagnosticsBfdneighbors",
            "diagnosticsBfdsummary",
            "diagnosticsBgpneighbors",
            "diagnosticsBgpsummary",
            "diagnosticsGeneralrunningconfig",
            "diagnosticsOspfdatabase",
            "diagnosticsOspfinterface",
            "diagnosticsOspfoverview",
            "diagnosticsOspfv3interface",
            "diagnosticsOspfv3overview",
            "diagnosticsSearchBgproute4",
            "diagnosticsSearchBgproute6",
            "diagnosticsSearchGeneralroute4",
            "diagnosticsSearchGeneralroute6",
            "diagnosticsSearchOspfneighbor",
            "diagnosticsSearchOspfroute",
            "diagnosticsSearchOspfv3database",
            "diagnosticsSearchOspfv3route",
            "generalGet",
            "ospf6settingsGet",
            "ospf6settingsGetInterface",
            "ospf6settingsGetNetwork",
            "ospf6settingsGetPrefixlist",
            "ospf6settingsGetRedistribution",
            "ospf6settingsGetRoutemap",
            "ospfsettingsGet",
            "ospfsettingsGetInterface",
            "ospfsettingsGetNetwork",
            "ospfsettingsGetPrefixlist",
            "ospfsettingsGetRedistribution",
            "ospfsettingsGetRoutemap",
            "ripGet",
            "serviceStatus",
            "staticGet",
            "staticGetRoute"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_quagga_write",
    "description": "Quagga write operations — 87 methods: bfdAddNeighbor, bfdDelNeighbor, bfdSet, bfdSetNeighbor, bfdToggleNeighbor, bgpAddAspath...",
    "module": "plugins",
    "submodule": "quagga",
    "methods": [
      "bfdAddNeighbor",
      "bfdDelNeighbor",
      "bfdSet",
      "bfdSetNeighbor",
      "bfdToggleNeighbor",
      "bgpAddAspath",
      "bgpAddCommunitylist",
      "bgpAddNeighbor",
      "bgpAddPeergroup",
      "bgpAddPrefixlist",
      "bgpAddRedistribution",
      "bgpAddRoutemap",
      "bgpDelAspath",
      "bgpDelCommunitylist",
      "bgpDelNeighbor",
      "bgpDelPeergroup",
      "bgpDelPrefixlist",
      "bgpDelRedistribution",
      "bgpDelRoutemap",
      "bgpSet",
      "bgpSetAspath",
      "bgpSetCommunitylist",
      "bgpSetNeighbor",
      "bgpSetPeergroup",
      "bgpSetPrefixlist",
      "bgpSetRedistribution",
      "bgpSetRoutemap",
      "bgpToggleAspath",
      "bgpToggleCommunitylist",
      "bgpToggleNeighbor",
      "bgpTogglePeergroup",
      "bgpTogglePrefixlist",
      "bgpToggleRedistribution",
      "bgpToggleRoutemap",
      "generalSet",
      "ospf6settingsAddInterface",
      "ospf6settingsAddNetwork",
      "ospf6settingsAddPrefixlist",
      "ospf6settingsAddRedistribution",
      "ospf6settingsAddRoutemap",
      "ospf6settingsDelInterface",
      "ospf6settingsDelNetwork",
      "ospf6settingsDelPrefixlist",
      "ospf6settingsDelRedistribution",
      "ospf6settingsDelRoutemap",
      "ospf6settingsSet",
      "ospf6settingsSetInterface",
      "ospf6settingsSetNetwork",
      "ospf6settingsSetPrefixlist",
      "ospf6settingsSetRedistribution",
      "ospf6settingsSetRoutemap",
      "ospf6settingsToggleInterface",
      "ospf6settingsToggleNetwork",
      "ospf6settingsTogglePrefixlist",
      "ospf6settingsToggleRedistribution",
      "ospf6settingsToggleRoutemap",
      "ospfsettingsAddInterface",
      "ospfsettingsAddNetwork",
      "ospfsettingsAddPrefixlist",
      "ospfsettingsAddRedistribution",
      "ospfsettingsAddRoutemap",
      "ospfsettingsDelInterface",
      "ospfsettingsDelNetwork",
      "ospfsettingsDelPrefixlist",
      "ospfsettingsDelRedistribution",
      "ospfsettingsDelRoutemap",
      "ospfsettingsSet",
      "ospfsettingsSetInterface",
      "ospfsettingsSetNetwork",
      "ospfsettingsSetPrefixlist",
      "ospfsettingsSetRedistribution",
      "ospfsettingsSetRoutemap",
      "ospfsettingsToggleInterface",
      "ospfsettingsToggleNetwork",
      "ospfsettingsTogglePrefixlist",
      "ospfsettingsToggleRedistribution",
      "ospfsettingsToggleRoutemap",
      "ripSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "staticAddRoute",
      "staticDelRoute",
      "staticSet",
      "staticSetRoute",
      "staticToggleRoute"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "bfdAddNeighbor",
            "bfdDelNeighbor",
            "bfdSet",
            "bfdSetNeighbor",
            "bfdToggleNeighbor",
            "bgpAddAspath",
            "bgpAddCommunitylist",
            "bgpAddNeighbor",
            "bgpAddPeergroup",
            "bgpAddPrefixlist",
            "bgpAddRedistribution",
            "bgpAddRoutemap",
            "bgpDelAspath",
            "bgpDelCommunitylist",
            "bgpDelNeighbor",
            "bgpDelPeergroup",
            "bgpDelPrefixlist",
            "bgpDelRedistribution",
            "bgpDelRoutemap",
            "bgpSet",
            "bgpSetAspath",
            "bgpSetCommunitylist",
            "bgpSetNeighbor",
            "bgpSetPeergroup",
            "bgpSetPrefixlist",
            "bgpSetRedistribution",
            "bgpSetRoutemap",
            "bgpToggleAspath",
            "bgpToggleCommunitylist",
            "bgpToggleNeighbor",
            "bgpTogglePeergroup",
            "bgpTogglePrefixlist",
            "bgpToggleRedistribution",
            "bgpToggleRoutemap",
            "generalSet",
            "ospf6settingsAddInterface",
            "ospf6settingsAddNetwork",
            "ospf6settingsAddPrefixlist",
            "ospf6settingsAddRedistribution",
            "ospf6settingsAddRoutemap",
            "ospf6settingsDelInterface",
            "ospf6settingsDelNetwork",
            "ospf6settingsDelPrefixlist",
            "ospf6settingsDelRedistribution",
            "ospf6settingsDelRoutemap",
            "ospf6settingsSet",
            "ospf6settingsSetInterface",
            "ospf6settingsSetNetwork",
            "ospf6settingsSetPrefixlist",
            "ospf6settingsSetRedistribution",
            "ospf6settingsSetRoutemap",
            "ospf6settingsToggleInterface",
            "ospf6settingsToggleNetwork",
            "ospf6settingsTogglePrefixlist",
            "ospf6settingsToggleRedistribution",
            "ospf6settingsToggleRoutemap",
            "ospfsettingsAddInterface",
            "ospfsettingsAddNetwork",
            "ospfsettingsAddPrefixlist",
            "ospfsettingsAddRedistribution",
            "ospfsettingsAddRoutemap",
            "ospfsettingsDelInterface",
            "ospfsettingsDelNetwork",
            "ospfsettingsDelPrefixlist",
            "ospfsettingsDelRedistribution",
            "ospfsettingsDelRoutemap",
            "ospfsettingsSet",
            "ospfsettingsSetInterface",
            "ospfsettingsSetNetwork",
            "ospfsettingsSetPrefixlist",
            "ospfsettingsSetRedistribution",
            "ospfsettingsSetRoutemap",
            "ospfsettingsToggleInterface",
            "ospfsettingsToggleNetwork",
            "ospfsettingsTogglePrefixlist",
            "ospfsettingsToggleRedistribution",
            "ospfsettingsToggleRoutemap",
            "ripSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "staticAddRoute",
            "staticDelRoute",
            "staticSet",
            "staticSetRoute",
            "staticToggleRoute"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_radsecproxy_read",
    "description": "Radsecproxy read operations — 12 methods: clientsGet, clientsGetItem, generalGet, realmsGet, realmsGetItem, rewritesGet...",
    "module": "plugins",
    "submodule": "radsecproxy",
    "methods": [
      "clientsGet",
      "clientsGetItem",
      "generalGet",
      "realmsGet",
      "realmsGetItem",
      "rewritesGet",
      "rewritesGetItem",
      "serversGet",
      "serversGetItem",
      "serviceStatus",
      "tlsGet",
      "tlsGetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "clientsGet",
            "clientsGetItem",
            "generalGet",
            "realmsGet",
            "realmsGetItem",
            "rewritesGet",
            "rewritesGetItem",
            "serversGet",
            "serversGetItem",
            "serviceStatus",
            "tlsGet",
            "tlsGetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_radsecproxy_write",
    "description": "Radsecproxy write operations — 30 methods: clientsAddItem, clientsDelItem, clientsSet, clientsSetItem, clientsToggleItem, generalSet...",
    "module": "plugins",
    "submodule": "radsecproxy",
    "methods": [
      "clientsAddItem",
      "clientsDelItem",
      "clientsSet",
      "clientsSetItem",
      "clientsToggleItem",
      "generalSet",
      "realmsAddItem",
      "realmsDelItem",
      "realmsSet",
      "realmsSetItem",
      "realmsToggleItem",
      "rewritesAddItem",
      "rewritesDelItem",
      "rewritesSet",
      "rewritesSetItem",
      "rewritesToggleItem",
      "serversAddItem",
      "serversDelItem",
      "serversSet",
      "serversSetItem",
      "serversToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "tlsAddItem",
      "tlsDelItem",
      "tlsSet",
      "tlsSetItem",
      "tlsToggleItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "clientsAddItem",
            "clientsDelItem",
            "clientsSet",
            "clientsSetItem",
            "clientsToggleItem",
            "generalSet",
            "realmsAddItem",
            "realmsDelItem",
            "realmsSet",
            "realmsSetItem",
            "realmsToggleItem",
            "rewritesAddItem",
            "rewritesDelItem",
            "rewritesSet",
            "rewritesSetItem",
            "rewritesToggleItem",
            "serversAddItem",
            "serversDelItem",
            "serversSet",
            "serversSetItem",
            "serversToggleItem",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "tlsAddItem",
            "tlsDelItem",
            "tlsSet",
            "tlsSetItem",
            "tlsToggleItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_redis_read",
    "description": "Redis read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "redis",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_redis_write",
    "description": "Redis write operations — 6 methods: serviceReconfigure, serviceResetdb, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "redis",
    "methods": [
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceResetdb",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_relayd_read",
    "description": "Relayd read operations — 6 methods: serviceConfigtest, serviceStatus, settingsDirty, settingsGet, settingsSearch, statusSum",
    "module": "plugins",
    "submodule": "relayd",
    "methods": [
      "serviceConfigtest",
      "serviceStatus",
      "settingsDirty",
      "settingsGet",
      "settingsSearch",
      "statusSum"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceConfigtest",
            "serviceStatus",
            "settingsDirty",
            "settingsGet",
            "settingsSearch",
            "statusSum"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_relayd_write",
    "description": "Relayd write operations — 8 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsDel, settingsSet...",
    "module": "plugins",
    "submodule": "relayd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsDel",
      "settingsSet",
      "settingsToggle",
      "statusToggle"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsDel",
            "settingsSet",
            "settingsToggle",
            "statusToggle"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_rspamd_read",
    "description": "Rspamd read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "rspamd",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_rspamd_write",
    "description": "Rspamd write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "rspamd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_shadowsocks_read",
    "description": "Shadowsocks read operations — 4 methods: generalGet, localGet, localserviceStatus, serviceStatus",
    "module": "plugins",
    "submodule": "shadowsocks",
    "methods": [
      "generalGet",
      "localGet",
      "localserviceStatus",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "localGet",
            "localserviceStatus",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_shadowsocks_write",
    "description": "Shadowsocks write operations — 10 methods: generalSet, localSet, localserviceReconfigure, localserviceRestart, localserviceStart, localserviceStop...",
    "module": "plugins",
    "submodule": "shadowsocks",
    "methods": [
      "generalSet",
      "localSet",
      "localserviceReconfigure",
      "localserviceRestart",
      "localserviceStart",
      "localserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "localSet",
            "localserviceReconfigure",
            "localserviceRestart",
            "localserviceStart",
            "localserviceStop",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_siproxd_read",
    "description": "Siproxd read operations — 9 methods: domainGet, domainGetDomain, domainSearchDomain, generalGet, serviceShowregistrations, serviceStatus...",
    "module": "plugins",
    "submodule": "siproxd",
    "methods": [
      "domainGet",
      "domainGetDomain",
      "domainSearchDomain",
      "generalGet",
      "serviceShowregistrations",
      "serviceStatus",
      "userGet",
      "userGetUser",
      "userSearchUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "domainGet",
            "domainGetDomain",
            "domainSearchDomain",
            "generalGet",
            "serviceShowregistrations",
            "serviceStatus",
            "userGet",
            "userGetUser",
            "userSearchUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_siproxd_write",
    "description": "Siproxd write operations — 15 methods: domainAddDomain, domainDelDomain, domainSet, domainSetDomain, domainToggleDomain, generalSet...",
    "module": "plugins",
    "submodule": "siproxd",
    "methods": [
      "domainAddDomain",
      "domainDelDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "domainAddDomain",
            "domainDelDomain",
            "domainSet",
            "domainSetDomain",
            "domainToggleDomain",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "userAddUser",
            "userDelUser",
            "userSet",
            "userSetUser",
            "userToggleUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_smart_read",
    "description": "Smart read operations — 5 methods: serviceAbort, serviceInfo, serviceList, serviceLogs, serviceTest",
    "module": "plugins",
    "submodule": "smart",
    "methods": [
      "serviceAbort",
      "serviceInfo",
      "serviceList",
      "serviceLogs",
      "serviceTest"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceAbort",
            "serviceInfo",
            "serviceList",
            "serviceLogs",
            "serviceTest"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_softether_read",
    "description": "Softether read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "softether",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_softether_write",
    "description": "Softether write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "softether",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_sslh_read",
    "description": "Sslh read operations — 3 methods: serviceStatus, settingsGet, settingsIndex",
    "module": "plugins",
    "submodule": "sslh",
    "methods": [
      "serviceStatus",
      "settingsGet",
      "settingsIndex"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet",
            "settingsIndex"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_sslh_write",
    "description": "Sslh write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "sslh",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_stunnel_read",
    "description": "Stunnel read operations — 3 methods: serviceStatus, servicesGet, servicesGetItem",
    "module": "plugins",
    "submodule": "stunnel",
    "methods": [
      "serviceStatus",
      "servicesGet",
      "servicesGetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "servicesGet",
            "servicesGetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_stunnel_write",
    "description": "Stunnel write operations — 9 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, servicesAddItem, servicesDelItem...",
    "module": "plugins",
    "submodule": "stunnel",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "servicesAddItem",
      "servicesDelItem",
      "servicesSet",
      "servicesSetItem",
      "servicesToggleItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "servicesAddItem",
            "servicesDelItem",
            "servicesSet",
            "servicesSetItem",
            "servicesToggleItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tailscale_read",
    "description": "Tailscale read operations — 8 methods: authenticationGet, serviceStatus, settingsGet, settingsGetSubnet, statusGet, statusIp...",
    "module": "plugins",
    "submodule": "tailscale",
    "methods": [
      "authenticationGet",
      "serviceStatus",
      "settingsGet",
      "settingsGetSubnet",
      "statusGet",
      "statusIp",
      "statusNet",
      "status"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "authenticationGet",
            "serviceStatus",
            "settingsGet",
            "settingsGetSubnet",
            "statusGet",
            "statusIp",
            "statusNet",
            "status"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tailscale_write",
    "description": "Tailscale write operations — 11 methods: authenticationSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsAddSubnet...",
    "module": "plugins",
    "submodule": "tailscale",
    "methods": [
      "authenticationSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddSubnet",
      "settingsDelSubnet",
      "settingsReload",
      "settingsSet",
      "settingsSetSubnet",
      "statusSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "authenticationSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddSubnet",
            "settingsDelSubnet",
            "settingsReload",
            "settingsSet",
            "settingsSetSubnet",
            "statusSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tayga_read",
    "description": "Tayga read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "tayga",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tayga_write",
    "description": "Tayga write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "tayga",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_telegraf_read",
    "description": "Telegraf read operations — 6 methods: generalGet, inputGet, keyGet, keyGetKey, outputGet, serviceStatus",
    "module": "plugins",
    "submodule": "telegraf",
    "methods": [
      "generalGet",
      "inputGet",
      "keyGet",
      "keyGetKey",
      "outputGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "inputGet",
            "keyGet",
            "keyGetKey",
            "outputGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_telegraf_write",
    "description": "Telegraf write operations — 12 methods: generalSet, inputSet, keyAddKey, keyDelKey, keySet, keySetKey...",
    "module": "plugins",
    "submodule": "telegraf",
    "methods": [
      "generalSet",
      "inputSet",
      "keyAddKey",
      "keyDelKey",
      "keySet",
      "keySetKey",
      "keyToggleKey",
      "outputSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "inputSet",
            "keyAddKey",
            "keyDelKey",
            "keySet",
            "keySetKey",
            "keyToggleKey",
            "outputSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tftp_read",
    "description": "Tftp read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "tftp",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tftp_write",
    "description": "Tftp write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "tftp",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tinc_read",
    "description": "Tinc read operations — 5 methods: settingsGet, settingsGetHost, settingsGetNetwork, settingsSearchHost, settingsSearchNetwork",
    "module": "plugins",
    "submodule": "tinc",
    "methods": [
      "settingsGet",
      "settingsGetHost",
      "settingsGetNetwork",
      "settingsSearchHost",
      "settingsSearchNetwork"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "settingsGet",
            "settingsGetHost",
            "settingsGetNetwork",
            "settingsSearchHost",
            "settingsSearchNetwork"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tinc_write",
    "description": "Tinc write operations — 11 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsDelHost, settingsDelNetwork...",
    "module": "plugins",
    "submodule": "tinc",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsDelHost",
      "settingsDelNetwork",
      "settingsSet",
      "settingsSetHost",
      "settingsSetNetwork",
      "settingsToggleHost",
      "settingsToggleNetwork"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsDelHost",
            "settingsDelNetwork",
            "settingsSet",
            "settingsSetHost",
            "settingsSetNetwork",
            "settingsToggleHost",
            "settingsToggleNetwork"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tor_read",
    "description": "Tor read operations — 15 methods: exitaclGet, exitaclGetacl, generalGet, generalGethidservauth, hiddenserviceGet, hiddenserviceGetservice...",
    "module": "plugins",
    "submodule": "tor",
    "methods": [
      "exitaclGet",
      "exitaclGetacl",
      "generalGet",
      "generalGethidservauth",
      "hiddenserviceGet",
      "hiddenserviceGetservice",
      "hiddenserviceaclGet",
      "hiddenserviceaclGetacl",
      "relayGet",
      "serviceCircuits",
      "serviceGetHiddenServices",
      "serviceStatus",
      "serviceStreams",
      "socksaclGet",
      "socksaclGetacl"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "exitaclGet",
            "exitaclGetacl",
            "generalGet",
            "generalGethidservauth",
            "hiddenserviceGet",
            "hiddenserviceGetservice",
            "hiddenserviceaclGet",
            "hiddenserviceaclGetacl",
            "relayGet",
            "serviceCircuits",
            "serviceGetHiddenServices",
            "serviceStatus",
            "serviceStreams",
            "socksaclGet",
            "socksaclGetacl"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tor_write",
    "description": "Tor write operations — 30 methods: exitaclAddacl, exitaclDelacl, exitaclSet, exitaclSetacl, exitaclToggleacl, generalAddhidservauth...",
    "module": "plugins",
    "submodule": "tor",
    "methods": [
      "exitaclAddacl",
      "exitaclDelacl",
      "exitaclSet",
      "exitaclSetacl",
      "exitaclToggleacl",
      "generalAddhidservauth",
      "generalDelhidservauth",
      "generalSet",
      "generalSethidservauth",
      "generalTogglehidservauth",
      "hiddenserviceAddservice",
      "hiddenserviceDelservice",
      "hiddenserviceSet",
      "hiddenserviceSetservice",
      "hiddenserviceToggleservice",
      "hiddenserviceaclAddacl",
      "hiddenserviceaclDelacl",
      "hiddenserviceaclSet",
      "hiddenserviceaclSetacl",
      "hiddenserviceaclToggleacl",
      "relaySet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "socksaclAddacl",
      "socksaclDelacl",
      "socksaclSet",
      "socksaclSetacl",
      "socksaclToggleacl"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "exitaclAddacl",
            "exitaclDelacl",
            "exitaclSet",
            "exitaclSetacl",
            "exitaclToggleacl",
            "generalAddhidservauth",
            "generalDelhidservauth",
            "generalSet",
            "generalSethidservauth",
            "generalTogglehidservauth",
            "hiddenserviceAddservice",
            "hiddenserviceDelservice",
            "hiddenserviceSet",
            "hiddenserviceSetservice",
            "hiddenserviceToggleservice",
            "hiddenserviceaclAddacl",
            "hiddenserviceaclDelacl",
            "hiddenserviceaclSet",
            "hiddenserviceaclSetacl",
            "hiddenserviceaclToggleacl",
            "relaySet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "socksaclAddacl",
            "socksaclDelacl",
            "socksaclSet",
            "socksaclSetacl",
            "socksaclToggleacl"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_turnserver_read",
    "description": "Turnserver read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "turnserver",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_turnserver_write",
    "description": "Turnserver write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "turnserver",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_udpbroadcastrelay_read",
    "description": "Udpbroadcastrelay read operations — 6 methods: serviceConfig, serviceGet, serviceStatus, settingsGet, settingsGetRelay, settingsSearchRelay",
    "module": "plugins",
    "submodule": "udpbroadcastrelay",
    "methods": [
      "serviceConfig",
      "serviceGet",
      "serviceStatus",
      "settingsGet",
      "settingsGetRelay",
      "settingsSearchRelay"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceConfig",
            "serviceGet",
            "serviceStatus",
            "settingsGet",
            "settingsGetRelay",
            "settingsSearchRelay"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_udpbroadcastrelay_write",
    "description": "Udpbroadcastrelay write operations — 10 methods: serviceReload, serviceRestart, serviceSet, serviceStart, serviceStop, settingsAddRelay...",
    "module": "plugins",
    "submodule": "udpbroadcastrelay",
    "methods": [
      "serviceReload",
      "serviceRestart",
      "serviceSet",
      "serviceStart",
      "serviceStop",
      "settingsAddRelay",
      "settingsDelRelay",
      "settingsSet",
      "settingsSetRelay",
      "settingsToggleRelay"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReload",
            "serviceRestart",
            "serviceSet",
            "serviceStart",
            "serviceStop",
            "settingsAddRelay",
            "settingsDelRelay",
            "settingsSet",
            "settingsSetRelay",
            "settingsToggleRelay"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_vnstat_read",
    "description": "Vnstat read operations — 6 methods: generalGet, serviceDaily, serviceHourly, serviceMonthly, serviceStatus, serviceYearly",
    "module": "plugins",
    "submodule": "vnstat",
    "methods": [
      "generalGet",
      "serviceDaily",
      "serviceHourly",
      "serviceMonthly",
      "serviceStatus",
      "serviceYearly"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceDaily",
            "serviceHourly",
            "serviceMonthly",
            "serviceStatus",
            "serviceYearly"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_vnstat_write",
    "description": "Vnstat write operations — 6 methods: generalSet, serviceReconfigure, serviceResetdb, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "vnstat",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceResetdb",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_wazuhagent_read",
    "description": "Wazuhagent read operations — 2 methods: serviceStatus, settingsGet",
    "module": "plugins",
    "submodule": "wazuhagent",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_wazuhagent_write",
    "description": "Wazuhagent write operations — 5 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsSet",
    "module": "plugins",
    "submodule": "wazuhagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_wol_read",
    "description": "Wol read operations — 4 methods: wolGet, wolGetHost, wolGetwake, wolWakeall",
    "module": "plugins",
    "submodule": "wol",
    "methods": [
      "wolGet",
      "wolGetHost",
      "wolGetwake",
      "wolWakeall"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "wolGet",
            "wolGetHost",
            "wolGetwake",
            "wolWakeall"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_wol_write",
    "description": "Wol write operations — 4 methods: wolAddHost, wolDelHost, wolSet, wolSetHost",
    "module": "plugins",
    "submodule": "wol",
    "methods": [
      "wolAddHost",
      "wolDelHost",
      "wolSet",
      "wolSetHost"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "wolAddHost",
            "wolDelHost",
            "wolSet",
            "wolSetHost"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zabbixagent_read",
    "description": "Zabbixagent read operations — 4 methods: serviceStatus, settingsGet, settingsGetAlias, settingsGetUserparameter",
    "module": "plugins",
    "submodule": "zabbixagent",
    "methods": [
      "serviceStatus",
      "settingsGet",
      "settingsGetAlias",
      "settingsGetUserparameter"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "serviceStatus",
            "settingsGet",
            "settingsGetAlias",
            "settingsGetUserparameter"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zabbixagent_write",
    "description": "Zabbixagent write operations — 13 methods: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsAddAlias, settingsAddUserparameter...",
    "module": "plugins",
    "submodule": "zabbixagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAlias",
      "settingsAddUserparameter",
      "settingsDelAlias",
      "settingsDelUserparameter",
      "settingsSet",
      "settingsSetAlias",
      "settingsSetUserparameter",
      "settingsToggleAlias",
      "settingsToggleUserparameter"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsAddAlias",
            "settingsAddUserparameter",
            "settingsDelAlias",
            "settingsDelUserparameter",
            "settingsSet",
            "settingsSetAlias",
            "settingsSetUserparameter",
            "settingsToggleAlias",
            "settingsToggleUserparameter"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zabbixproxy_read",
    "description": "Zabbixproxy read operations — 2 methods: generalGet, serviceStatus",
    "module": "plugins",
    "submodule": "zabbixproxy",
    "methods": [
      "generalGet",
      "serviceStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "generalGet",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zabbixproxy_write",
    "description": "Zabbixproxy write operations — 5 methods: generalSet, serviceReconfigure, serviceRestart, serviceStart, serviceStop",
    "module": "plugins",
    "submodule": "zabbixproxy",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zerotier_read",
    "description": "Zerotier read operations — 5 methods: networkGet, networkInfo, networkSearch, settingsGet, settingsStatus",
    "module": "plugins",
    "submodule": "zerotier",
    "methods": [
      "networkGet",
      "networkInfo",
      "networkSearch",
      "settingsGet",
      "settingsStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The read method to call (non-mutating)",
          "enum": [
            "networkGet",
            "networkInfo",
            "networkSearch",
            "settingsGet",
            "settingsStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For search: {searchPhrase: \"...\", current: 1, rowCount: 20}. For get: {uuid: \"...\"}. Many read methods take no params.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Page number (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Results per page (for search operations)",
              "default": 20
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zerotier_write",
    "description": "Zerotier write operations — 5 methods: networkAdd, networkDel, networkSet, networkToggle, settingsSet",
    "module": "plugins",
    "submodule": "zerotier",
    "methods": [
      "networkAdd",
      "networkDel",
      "networkSet",
      "networkToggle",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The write method to call (modifies state)",
          "enum": [
            "networkAdd",
            "networkDel",
            "networkSet",
            "networkToggle",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: \"...\"}. For apply/reconfigure/service methods params is usually empty.",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for set/del/toggle operations)"
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  }
];

// Method documentation for help
const METHOD_DOCS = {
  "core_read": {
    "toolName": "core_read",
    "module": "core",
    "methods": [
      "backupBackups",
      "backupDiff",
      "backupDownload",
      "backupProviders",
      "dashboardGetDashboard",
      "dashboardPicture",
      "dashboardProductInfoFeed",
      "hasyncGet",
      "hasyncStatusRemoteService",
      "hasyncStatusServices",
      "hasyncStatusVersion",
      "menuSearch",
      "menuTree",
      "serviceSearch",
      "snapshotsGet",
      "snapshotsIsSupported",
      "snapshotsSearch",
      "systemStatus",
      "tunablesGet",
      "tunablesGetItem"
    ]
  },
  "core_write": {
    "toolName": "core_write",
    "module": "core",
    "methods": [
      "backupDeleteBackup",
      "backupRevertBackup",
      "dashboardRestoreDefaults",
      "dashboardSaveWidgets",
      "hasyncReconfigure",
      "hasyncSet",
      "hasyncStatusRestart",
      "hasyncStatusRestartAll",
      "hasyncStatusStart",
      "hasyncStatusStop",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "snapshotsActivate",
      "snapshotsAdd",
      "snapshotsDel",
      "snapshotsSet",
      "systemDismissStatus",
      "systemHalt",
      "systemReboot",
      "tunablesAddItem",
      "tunablesDelItem",
      "tunablesReconfigure",
      "tunablesReset",
      "tunablesSet",
      "tunablesSetItem"
    ]
  },
  "firewall_read": {
    "toolName": "firewall_read",
    "module": "firewall",
    "methods": [
      "aliasGet",
      "aliasGetAliasUUID",
      "aliasGetGeoIP",
      "aliasGetItem",
      "aliasGetTableSize",
      "aliasListCategories",
      "aliasListCountries",
      "aliasListNetworkAliases",
      "aliasListUserGroups",
      "aliasUtilAliases",
      "aliasUtilFindReferences",
      "aliasUtilList",
      "categoryGet",
      "categoryGetItem",
      "filterBaseGet",
      "filterBaseListCategories",
      "filterBaseListNetworkSelectOptions",
      "filterGetInterfaceList",
      "filterGetRule",
      "filterUtilRuleStats",
      "groupGet",
      "groupGetItem",
      "nptGetRule",
      "oneToOneGetRule",
      "sourceNatGetRule"
    ]
  },
  "firewall_write": {
    "toolName": "firewall_write",
    "module": "firewall",
    "methods": [
      "aliasAddItem",
      "aliasDelItem",
      "aliasImport",
      "aliasReconfigure",
      "aliasSet",
      "aliasSetItem",
      "aliasToggleItem",
      "aliasUtilAdd",
      "aliasUtilDelete",
      "aliasUtilFlush",
      "aliasUtilUpdateBogons",
      "categoryAddItem",
      "categoryDelItem",
      "categorySet",
      "categorySetItem",
      "filterBaseApply",
      "filterBaseCancelRollback",
      "filterBaseRevert",
      "filterBaseSavepoint",
      "filterBaseSet",
      "filterAddRule",
      "filterDelRule",
      "filterMoveRuleBefore",
      "filterSetRule",
      "filterToggleRule",
      "groupAddItem",
      "groupDelItem",
      "groupReconfigure",
      "groupSet",
      "groupSetItem",
      "nptAddRule",
      "nptDelRule",
      "nptSetRule",
      "nptToggleRule",
      "oneToOneAddRule",
      "oneToOneDelRule",
      "oneToOneSetRule",
      "oneToOneToggleRule",
      "sourceNatAddRule",
      "sourceNatDelRule",
      "sourceNatSetRule",
      "sourceNatToggleRule"
    ]
  },
  "auth_read": {
    "toolName": "auth_read",
    "module": "auth",
    "methods": [
      "groupGet",
      "privGet",
      "privGetItem",
      "privSearch",
      "userDownload",
      "userGet",
      "userNewOtpSeed",
      "userSearchApiKey"
    ]
  },
  "auth_write": {
    "toolName": "auth_write",
    "module": "auth",
    "methods": [
      "groupAdd",
      "groupDel",
      "groupSet",
      "privSet",
      "privSetItem",
      "userAdd",
      "userAddApiKey",
      "userDel",
      "userDelApiKey",
      "userSet",
      "userUpload"
    ]
  },
  "interfaces_read": {
    "toolName": "interfaces_read",
    "module": "interfaces",
    "methods": [
      "gifSettingsGet",
      "gifSettingsGetIfOptions",
      "gifSettingsGetItem",
      "greSettingsGet",
      "greSettingsGetIfOptions",
      "greSettingsGetItem",
      "laggSettingsGet",
      "laggSettingsGetItem",
      "loopbackSettingsGet",
      "loopbackSettingsGetItem",
      "neighborSettingsGet",
      "neighborSettingsGetItem",
      "overviewExport",
      "overviewGetInterface",
      "overviewInterfacesInfo",
      "vipSettingsGet",
      "vipSettingsGetItem",
      "vipSettingsGetUnusedVhid",
      "vlanSettingsGet",
      "vlanSettingsGetItem",
      "vxlanSettingsGet",
      "vxlanSettingsGetItem"
    ]
  },
  "interfaces_write": {
    "toolName": "interfaces_write",
    "module": "interfaces",
    "methods": [
      "gifSettingsAddItem",
      "gifSettingsDelItem",
      "gifSettingsReconfigure",
      "gifSettingsSet",
      "gifSettingsSetItem",
      "greSettingsAddItem",
      "greSettingsDelItem",
      "greSettingsReconfigure",
      "greSettingsSet",
      "greSettingsSetItem",
      "laggSettingsAddItem",
      "laggSettingsDelItem",
      "laggSettingsReconfigure",
      "laggSettingsSet",
      "laggSettingsSetItem",
      "loopbackSettingsAddItem",
      "loopbackSettingsDelItem",
      "loopbackSettingsReconfigure",
      "loopbackSettingsSet",
      "loopbackSettingsSetItem",
      "neighborSettingsAddItem",
      "neighborSettingsDelItem",
      "neighborSettingsReconfigure",
      "neighborSettingsSet",
      "neighborSettingsSetItem",
      "overviewReloadInterface",
      "vipSettingsAddItem",
      "vipSettingsDelItem",
      "vipSettingsReconfigure",
      "vipSettingsSet",
      "vipSettingsSetItem",
      "vlanSettingsAddItem",
      "vlanSettingsDelItem",
      "vlanSettingsReconfigure",
      "vlanSettingsSet",
      "vlanSettingsSetItem",
      "vxlanSettingsAddItem",
      "vxlanSettingsDelItem",
      "vxlanSettingsReconfigure",
      "vxlanSettingsSet",
      "vxlanSettingsSetItem"
    ]
  },
  "captiveportal_read": {
    "toolName": "captiveportal_read",
    "module": "captiveportal",
    "methods": [
      "accessApi",
      "accessLogoff",
      "accessLogon",
      "serviceGetTemplate",
      "serviceSearchTemplates",
      "sessionConnect",
      "sessionDisconnect",
      "sessionList",
      "sessionSearch",
      "sessionZones",
      "settingsGet",
      "settingsGetZone",
      "voucherDropExpiredVouchers",
      "voucherDropVoucherGroup",
      "voucherExpireVoucher",
      "voucherListProviders",
      "voucherListVoucherGroups",
      "voucherListVouchers"
    ]
  },
  "captiveportal_write": {
    "toolName": "captiveportal_write",
    "module": "captiveportal",
    "methods": [
      "serviceDelTemplate",
      "serviceReconfigure",
      "serviceSaveTemplate",
      "settingsAddZone",
      "settingsDelZone",
      "settingsSet",
      "settingsSetZone",
      "settingsToggleZone",
      "voucherGenerateVouchers"
    ]
  },
  "cron_read": {
    "toolName": "cron_read",
    "module": "cron",
    "methods": [
      "settingsGet",
      "settingsGetJob"
    ]
  },
  "cron_write": {
    "toolName": "cron_write",
    "module": "cron",
    "methods": [
      "serviceReconfigure",
      "settingsAddJob",
      "settingsDelJob",
      "settingsSet",
      "settingsSetJob",
      "settingsToggleJob"
    ]
  },
  "dhcpv4_read": {
    "toolName": "dhcpv4_read",
    "module": "dhcpv4",
    "methods": [
      "leasesSearchLease",
      "serviceStatus"
    ]
  },
  "dhcpv4_write": {
    "toolName": "dhcpv4_write",
    "module": "dhcpv4",
    "methods": [
      "leasesDelLease",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "dhcpv6_read": {
    "toolName": "dhcpv6_read",
    "module": "dhcpv6",
    "methods": [
      "leasesSearchLease",
      "leasesSearchPrefix",
      "serviceStatus"
    ]
  },
  "dhcpv6_write": {
    "toolName": "dhcpv6_write",
    "module": "dhcpv6",
    "methods": [
      "leasesDelLease",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "dhcrelay_read": {
    "toolName": "dhcrelay_read",
    "module": "dhcrelay",
    "methods": [
      "settingsGet",
      "settingsGetDest",
      "settingsGetRelay"
    ]
  },
  "dhcrelay_write": {
    "toolName": "dhcrelay_write",
    "module": "dhcrelay",
    "methods": [
      "serviceReconfigure",
      "settingsAddDest",
      "settingsAddRelay",
      "settingsDelDest",
      "settingsDelRelay",
      "settingsSet",
      "settingsSetDest",
      "settingsSetRelay",
      "settingsToggleRelay"
    ]
  },
  "diagnostics_read": {
    "toolName": "diagnostics_read",
    "module": "diagnostics",
    "methods": [
      "activityGetActivity",
      "cpuUsageGetCPUType",
      "cpuUsageStream",
      "dnsReverseLookup",
      "dnsDiagnosticsGet",
      "firewallListRuleIds",
      "firewallLog",
      "firewallLogFilters",
      "firewallPfStates",
      "firewallPfStatistics",
      "firewallQueryPfTop",
      "firewallQueryStates",
      "firewallStats",
      "firewallStreamLog",
      "interfaceCarpStatus",
      "interfaceGetArp",
      "interfaceGetBpfStatistics",
      "interfaceGetInterfaceConfig",
      "interfaceGetInterfaceNames",
      "interfaceGetInterfaceStatistics",
      "interfaceGetMemoryStatistics",
      "interfaceGetNdp",
      "interfaceGetNetisrStatistics",
      "interfaceGetPfsyncNodes",
      "interfaceGetProtocolStatistics",
      "interfaceGetRoutes",
      "interfaceGetSocketStatistics",
      "interfaceGetVipStatus",
      "interfaceSearchArp",
      "interfaceSearchNdp",
      "lvtemplateGet",
      "lvtemplateGetItem",
      "netflowCacheStats",
      "netflowGetconfig",
      "netflowIsEnabled",
      "netflowStatus",
      "networkinsightExport",
      "networkinsightGetInterfaces",
      "networkinsightGetMetadata",
      "networkinsightGetProtocols",
      "networkinsightGetServices",
      "networkinsightTimeserie",
      "networkinsightTop",
      "packetCaptureDownload",
      "packetCaptureGet",
      "packetCaptureMacInfo",
      "packetCaptureSearchJobs",
      "packetCaptureView",
      "pingGet",
      "pingSearchJobs",
      "portprobeGet",
      "systemMemory",
      "systemSystemDisk",
      "systemSystemInformation",
      "systemSystemMbuf",
      "systemSystemResources",
      "systemSystemSwap",
      "systemSystemTemperature",
      "systemSystemTime",
      "systemhealthExportAsCSV",
      "systemhealthGetInterfaces",
      "systemhealthGetRRDlist",
      "systemhealthGetSystemHealth",
      "tracerouteGet",
      "trafficInterface",
      "trafficTop",
      "trafficStream"
    ]
  },
  "diagnostics_write": {
    "toolName": "diagnostics_write",
    "module": "diagnostics",
    "methods": [
      "dnsDiagnosticsSet",
      "firewallDelState",
      "firewallFlushSources",
      "firewallFlushStates",
      "firewallKillStates",
      "interfaceDelRoute",
      "interfaceFlushArp",
      "lvtemplateAddItem",
      "lvtemplateDelItem",
      "lvtemplateSet",
      "lvtemplateSetItem",
      "netflowReconfigure",
      "netflowSetconfig",
      "packetCaptureRemove",
      "packetCaptureSet",
      "packetCaptureStart",
      "packetCaptureStop",
      "pingRemove",
      "pingSet",
      "pingStart",
      "pingStop",
      "portprobeSet",
      "tracerouteSet"
    ]
  },
  "dnsmasq_read": {
    "toolName": "dnsmasq_read",
    "module": "dnsmasq",
    "methods": [
      "leasesSearch",
      "serviceStatus",
      "settingsDownloadHosts",
      "settingsGet",
      "settingsGetBoot",
      "settingsGetDomain",
      "settingsGetHost",
      "settingsGetOption",
      "settingsGetRange",
      "settingsGetTag",
      "settingsGetTagList"
    ]
  },
  "dnsmasq_write": {
    "toolName": "dnsmasq_write",
    "module": "dnsmasq",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddBoot",
      "settingsAddDomain",
      "settingsAddHost",
      "settingsAddOption",
      "settingsAddRange",
      "settingsAddTag",
      "settingsDelBoot",
      "settingsDelDomain",
      "settingsDelHost",
      "settingsDelOption",
      "settingsDelRange",
      "settingsDelTag",
      "settingsSet",
      "settingsSetBoot",
      "settingsSetDomain",
      "settingsSetHost",
      "settingsSetOption",
      "settingsSetRange",
      "settingsSetTag",
      "settingsUploadHosts"
    ]
  },
  "firmware_read": {
    "toolName": "firmware_read",
    "module": "firmware",
    "methods": [
      "firmwareAudit",
      "firmwareChangelog",
      "firmwareCheck",
      "firmwareConnection",
      "firmwareGet",
      "firmwareGetOptions",
      "firmwareHealth",
      "firmwareInfo",
      "firmwareLog",
      "firmwareResyncPlugins",
      "firmwareRunning",
      "firmwareStatus",
      "firmwareSyncPlugins",
      "firmwareUpgrade",
      "firmwareUpgradestatus",
      "firmwareDetails",
      "firmwareLicense",
      "firmwareLock",
      "firmwareUnlock"
    ]
  },
  "firmware_write": {
    "toolName": "firmware_write",
    "module": "firmware",
    "methods": [
      "firmwarePoweroff",
      "firmwareReboot",
      "firmwareSet",
      "firmwareUpdate",
      "firmwareInstall",
      "firmwareRemove",
      "firmwareReinstall"
    ]
  },
  "ids_read": {
    "toolName": "ids_read",
    "module": "ids",
    "methods": [
      "serviceDropAlertLog",
      "serviceGetAlertInfo",
      "serviceGetAlertLogs",
      "serviceQueryAlerts",
      "serviceStatus",
      "settingsCheckPolicyRule",
      "settingsGet",
      "settingsGetPolicy",
      "settingsGetPolicyRule",
      "settingsGetRuleInfo",
      "settingsGetRuleset",
      "settingsGetRulesetproperties",
      "settingsGetUserRule",
      "settingsListRuleMetadata",
      "settingsListRulesets",
      "settingsSearchInstalledRules"
    ]
  },
  "ids_write": {
    "toolName": "ids_write",
    "module": "ids",
    "methods": [
      "serviceReconfigure",
      "serviceReloadRules",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "serviceUpdateRules",
      "settingsAddPolicy",
      "settingsAddPolicyRule",
      "settingsAddUserRule",
      "settingsDelPolicy",
      "settingsDelPolicyRule",
      "settingsDelUserRule",
      "settingsSet",
      "settingsSetPolicy",
      "settingsSetPolicyRule",
      "settingsSetRule",
      "settingsSetRuleset",
      "settingsSetRulesetproperties",
      "settingsSetUserRule",
      "settingsTogglePolicy",
      "settingsTogglePolicyRule",
      "settingsToggleRule",
      "settingsToggleRuleset",
      "settingsToggleUserRule"
    ]
  },
  "ipsec_read": {
    "toolName": "ipsec_read",
    "module": "ipsec",
    "methods": [
      "connectionsConnectionExists",
      "connectionsGet",
      "connectionsGetChild",
      "connectionsGetConnection",
      "connectionsGetLocal",
      "connectionsGetRemote",
      "connectionsIsEnabled",
      "connectionsSwanctl",
      "keyPairsGet",
      "keyPairsGetItem",
      "leasesPools",
      "leasesSearch",
      "legacySubsystemStatus",
      "manualSpdGet",
      "poolsGet",
      "preSharedKeysGet",
      "preSharedKeysGetItem",
      "sadSearch",
      "serviceStatus",
      "sessionsConnect",
      "sessionsDisconnect",
      "sessionsSearchPhase1",
      "sessionsSearchPhase2",
      "settingsGet",
      "spdSearch",
      "tunnelSearchPhase1",
      "tunnelSearchPhase2",
      "vtiGet"
    ]
  },
  "ipsec_write": {
    "toolName": "ipsec_write",
    "module": "ipsec",
    "methods": [
      "connectionsAddChild",
      "connectionsAddConnection",
      "connectionsAddLocal",
      "connectionsAddRemote",
      "connectionsDelChild",
      "connectionsDelConnection",
      "connectionsDelLocal",
      "connectionsDelRemote",
      "connectionsSet",
      "connectionsSetChild",
      "connectionsSetConnection",
      "connectionsSetLocal",
      "connectionsSetRemote",
      "connectionsToggle",
      "connectionsToggleChild",
      "connectionsToggleConnection",
      "connectionsToggleLocal",
      "connectionsToggleRemote",
      "keyPairsAddItem",
      "keyPairsDelItem",
      "keyPairsGenKeyPair",
      "keyPairsSet",
      "keyPairsSetItem",
      "legacySubsystemApplyConfig",
      "manualSpdAdd",
      "manualSpdDel",
      "manualSpdSet",
      "manualSpdToggle",
      "poolsAdd",
      "poolsDel",
      "poolsSet",
      "poolsToggle",
      "preSharedKeysAddItem",
      "preSharedKeysDelItem",
      "preSharedKeysSet",
      "preSharedKeysSetItem",
      "sadDelete",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet",
      "spdDelete",
      "tunnelDelPhase1",
      "tunnelDelPhase2",
      "tunnelToggle",
      "tunnelTogglePhase1",
      "tunnelTogglePhase2",
      "vtiAdd",
      "vtiDel",
      "vtiSet",
      "vtiToggle"
    ]
  },
  "kea_read": {
    "toolName": "kea_read",
    "module": "kea",
    "methods": [
      "ctrlAgentGet",
      "dhcpv4DownloadReservations",
      "dhcpv4Get",
      "dhcpv4GetPeer",
      "dhcpv4GetReservation",
      "dhcpv4GetSubnet",
      "leases4Search",
      "serviceStatus"
    ]
  },
  "kea_write": {
    "toolName": "kea_write",
    "module": "kea",
    "methods": [
      "ctrlAgentSet",
      "dhcpv4AddPeer",
      "dhcpv4AddReservation",
      "dhcpv4AddSubnet",
      "dhcpv4DelPeer",
      "dhcpv4DelReservation",
      "dhcpv4DelSubnet",
      "dhcpv4Set",
      "dhcpv4SetPeer",
      "dhcpv4SetReservation",
      "dhcpv4SetSubnet",
      "dhcpv4UploadReservations",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "monit_read": {
    "toolName": "monit_read",
    "module": "monit",
    "methods": [
      "serviceCheck",
      "serviceStatus",
      "settingsDirty",
      "settingsGet",
      "settingsGetAlert",
      "settingsGetGeneral",
      "settingsGetService",
      "settingsGetTest",
      "statusGet"
    ]
  },
  "monit_write": {
    "toolName": "monit_write",
    "module": "monit",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAlert",
      "settingsAddService",
      "settingsAddTest",
      "settingsDelAlert",
      "settingsDelService",
      "settingsDelTest",
      "settingsSet",
      "settingsSetAlert",
      "settingsSetService",
      "settingsSetTest",
      "settingsToggleAlert",
      "settingsToggleService"
    ]
  },
  "openvpn_read": {
    "toolName": "openvpn_read",
    "module": "openvpn",
    "methods": [
      "clientOverwritesGet",
      "exportAccounts",
      "exportDownload",
      "exportProviders",
      "exportTemplates",
      "exportValidatePresets",
      "instancesGet",
      "instancesGetStaticKey",
      "serviceSearchRoutes",
      "serviceSearchSessions"
    ]
  },
  "openvpn_write": {
    "toolName": "openvpn_write",
    "module": "openvpn",
    "methods": [
      "clientOverwritesAdd",
      "clientOverwritesDel",
      "clientOverwritesSet",
      "clientOverwritesToggle",
      "exportStorePresets",
      "instancesAdd",
      "instancesAddStaticKey",
      "instancesDel",
      "instancesDelStaticKey",
      "instancesGenKey",
      "instancesSet",
      "instancesSetStaticKey",
      "instancesToggle",
      "serviceKillSession",
      "serviceReconfigure",
      "serviceRestartService",
      "serviceStartService",
      "serviceStopService"
    ]
  },
  "routes_read": {
    "toolName": "routes_read",
    "module": "routes",
    "methods": [
      "gatewayStatus",
      "routesGet",
      "routesGetroute"
    ]
  },
  "routes_write": {
    "toolName": "routes_write",
    "module": "routes",
    "methods": [
      "routesAddroute",
      "routesDelroute",
      "routesReconfigure",
      "routesSet",
      "routesSetroute",
      "routesToggleroute"
    ]
  },
  "routing_read": {
    "toolName": "routing_read",
    "module": "routing",
    "methods": [
      "settingsGet",
      "settingsGetGateway",
      "settingsSearchGateway"
    ]
  },
  "routing_write": {
    "toolName": "routing_write",
    "module": "routing",
    "methods": [
      "settingsAddGateway",
      "settingsDelGateway",
      "settingsReconfigure",
      "settingsSet",
      "settingsSetGateway",
      "settingsToggleGateway"
    ]
  },
  "syslog_read": {
    "toolName": "syslog_read",
    "module": "syslog",
    "methods": [
      "serviceStats",
      "serviceStatus",
      "settingsGet",
      "settingsGetDestination"
    ]
  },
  "syslog_write": {
    "toolName": "syslog_write",
    "module": "syslog",
    "methods": [
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddDestination",
      "settingsDelDestination",
      "settingsSet",
      "settingsSetDestination",
      "settingsToggleDestination"
    ]
  },
  "trafficshaper_read": {
    "toolName": "trafficshaper_read",
    "module": "trafficshaper",
    "methods": [
      "serviceFlushreload",
      "serviceStatistics",
      "settingsGet",
      "settingsGetPipe",
      "settingsGetQueue",
      "settingsGetRule"
    ]
  },
  "trafficshaper_write": {
    "toolName": "trafficshaper_write",
    "module": "trafficshaper",
    "methods": [
      "serviceReconfigure",
      "settingsAddPipe",
      "settingsAddQueue",
      "settingsAddRule",
      "settingsDelPipe",
      "settingsDelQueue",
      "settingsDelRule",
      "settingsSet",
      "settingsSetPipe",
      "settingsSetQueue",
      "settingsSetRule",
      "settingsTogglePipe",
      "settingsToggleQueue",
      "settingsToggleRule"
    ]
  },
  "trust_read": {
    "toolName": "trust_read",
    "module": "trust",
    "methods": [
      "caCaInfo",
      "caCaList",
      "caGet",
      "caRawDump",
      "certCaInfo",
      "certCaList",
      "certGet",
      "certRawDump",
      "certUserList",
      "crlGet",
      "crlGetOcspInfoData",
      "crlRawDump",
      "crlSearch",
      "settingsGet"
    ]
  },
  "trust_write": {
    "toolName": "trust_write",
    "module": "trust",
    "methods": [
      "caDel",
      "caGenerateFile",
      "caSet",
      "certAdd",
      "certDel",
      "certGenerateFile",
      "certSet",
      "crlDel",
      "crlSet",
      "settingsReconfigure",
      "settingsSet"
    ]
  },
  "unbound_read": {
    "toolName": "unbound_read",
    "module": "unbound",
    "methods": [
      "diagnosticsDumpcache",
      "diagnosticsDumpinfra",
      "diagnosticsListinsecure",
      "diagnosticsListlocaldata",
      "diagnosticsListlocalzones",
      "diagnosticsStats",
      "overviewRolling",
      "overviewIsBlockListEnabled",
      "overviewIsEnabled",
      "overviewSearchQueries",
      "overviewTotals",
      "serviceDnsbl",
      "serviceStatus",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetForward",
      "settingsGetHostAlias",
      "settingsGetHostOverride",
      "settingsGetNameservers"
    ]
  },
  "unbound_write": {
    "toolName": "unbound_write",
    "module": "unbound",
    "methods": [
      "serviceReconfigure",
      "serviceReconfigureGeneral",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddForward",
      "settingsAddHostAlias",
      "settingsAddHostOverride",
      "settingsDelAcl",
      "settingsDelForward",
      "settingsDelHostAlias",
      "settingsDelHostOverride",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetForward",
      "settingsSetHostAlias",
      "settingsSetHostOverride",
      "settingsToggleAcl",
      "settingsToggleForward",
      "settingsToggleHostAlias",
      "settingsToggleHostOverride",
      "settingsUpdateBlocklist"
    ]
  },
  "wireguard_read": {
    "toolName": "wireguard_read",
    "module": "wireguard",
    "methods": [
      "clientGet",
      "clientGetClient",
      "clientGetClientBuilder",
      "clientGetServerInfo",
      "clientListServers",
      "clientPsk",
      "generalGet",
      "serverGet",
      "serverGetServer",
      "serverKeyPair",
      "serviceShow",
      "serviceStatus"
    ]
  },
  "wireguard_write": {
    "toolName": "wireguard_write",
    "module": "wireguard",
    "methods": [
      "clientAddClient",
      "clientAddClientBuilder",
      "clientDelClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_acmeclient_read": {
    "toolName": "plugin_acmeclient_read",
    "module": "plugins",
    "submodule": "acmeclient",
    "methods": [
      "accountsGet",
      "accountsRegister",
      "actionsGet",
      "actionsSftpGetIdentity",
      "actionsSftpTestConnection",
      "actionsSshGetIdentity",
      "actionsSshTestConnection",
      "certificatesAutomation",
      "certificatesGet",
      "serviceConfigtest",
      "serviceStatus",
      "settingsFetchCronIntegration",
      "settingsFetchHAProxyIntegration",
      "settingsGet",
      "settingsGetBindPluginStatus",
      "settingsGetGcloudPluginStatus",
      "validationsGet"
    ]
  },
  "plugin_acmeclient_write": {
    "toolName": "plugin_acmeclient_write",
    "module": "plugins",
    "submodule": "acmeclient",
    "methods": [
      "accountsAdd",
      "accountsDel",
      "accountsSet",
      "accountsToggle",
      "accountsUpdate",
      "actionsAdd",
      "actionsDel",
      "actionsSet",
      "actionsToggle",
      "actionsUpdate",
      "certificatesAdd",
      "certificatesDel",
      "certificatesImport",
      "certificatesRemovekey",
      "certificatesRevoke",
      "certificatesSet",
      "certificatesSign",
      "certificatesToggle",
      "certificatesUpdate",
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceSignallcerts",
      "serviceStart",
      "serviceStop",
      "settingsSet",
      "validationsAdd",
      "validationsDel",
      "validationsSet",
      "validationsToggle",
      "validationsUpdate"
    ]
  },
  "plugin_apcupsd_read": {
    "toolName": "plugin_apcupsd_read",
    "module": "plugins",
    "submodule": "apcupsd",
    "methods": [
      "serviceGetUpsStatus",
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_apcupsd_write": {
    "toolName": "plugin_apcupsd_write",
    "module": "plugins",
    "submodule": "apcupsd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_bind_read": {
    "toolName": "plugin_bind_read",
    "module": "plugins",
    "submodule": "bind",
    "methods": [
      "aclGet",
      "aclGetAcl",
      "dnsblGet",
      "domainGet",
      "domainGetDomain",
      "domainSearchMasterDomain",
      "domainSearchSlaveDomain",
      "generalGet",
      "generalZoneshow",
      "generalZonetest",
      "recordGet",
      "recordGetRecord",
      "serviceDnsbl",
      "serviceStatus"
    ]
  },
  "plugin_bind_write": {
    "toolName": "plugin_bind_write",
    "module": "plugins",
    "submodule": "bind",
    "methods": [
      "aclAddAcl",
      "aclDelAcl",
      "aclSet",
      "aclSetAcl",
      "aclToggleAcl",
      "dnsblSet",
      "domainAddPrimaryDomain",
      "domainAddSecondaryDomain",
      "domainDelDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalSet",
      "recordAddRecord",
      "recordDelRecord",
      "recordSet",
      "recordSetRecord",
      "recordToggleRecord",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_caddy_read": {
    "toolName": "plugin_caddy_read",
    "module": "plugins",
    "submodule": "caddy",
    "methods": [
      "diagnosticsCaddyfile",
      "diagnosticsConfig",
      "diagnosticsGet",
      "generalGet",
      "reverseProxyGet",
      "reverseProxyGetAccessList",
      "reverseProxyGetAllReverseDomains",
      "reverseProxyGetBasicAuth",
      "reverseProxyGetHandle",
      "reverseProxyGetHeader",
      "reverseProxyGetLayer4",
      "reverseProxyGetLayer4Openvpn",
      "reverseProxyGetReverseProxy",
      "reverseProxyGetSubdomain",
      "serviceStatus",
      "serviceValidate"
    ]
  },
  "plugin_caddy_write": {
    "toolName": "plugin_caddy_write",
    "module": "plugins",
    "submodule": "caddy",
    "methods": [
      "diagnosticsSet",
      "generalSet",
      "reverseProxyAddAccessList",
      "reverseProxyAddBasicAuth",
      "reverseProxyAddHandle",
      "reverseProxyAddHeader",
      "reverseProxyAddLayer4",
      "reverseProxyAddLayer4Openvpn",
      "reverseProxyAddReverseProxy",
      "reverseProxyAddSubdomain",
      "reverseProxyDelAccessList",
      "reverseProxyDelBasicAuth",
      "reverseProxyDelHandle",
      "reverseProxyDelHeader",
      "reverseProxyDelLayer4",
      "reverseProxyDelLayer4Openvpn",
      "reverseProxyDelReverseProxy",
      "reverseProxyDelSubdomain",
      "reverseProxySet",
      "reverseProxySetAccessList",
      "reverseProxySetBasicAuth",
      "reverseProxySetHandle",
      "reverseProxySetHeader",
      "reverseProxySetLayer4",
      "reverseProxySetLayer4Openvpn",
      "reverseProxySetReverseProxy",
      "reverseProxySetSubdomain",
      "reverseProxyToggleHandle",
      "reverseProxyToggleLayer4",
      "reverseProxyToggleLayer4Openvpn",
      "reverseProxyToggleReverseProxy",
      "reverseProxyToggleSubdomain",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_chrony_read": {
    "toolName": "plugin_chrony_read",
    "module": "plugins",
    "submodule": "chrony",
    "methods": [
      "generalGet",
      "serviceChronyauthdata",
      "serviceChronysources",
      "serviceChronysourcestats",
      "serviceChronytracking",
      "serviceStatus"
    ]
  },
  "plugin_chrony_write": {
    "toolName": "plugin_chrony_write",
    "module": "plugins",
    "submodule": "chrony",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_cicap_read": {
    "toolName": "plugin_cicap_read",
    "module": "plugins",
    "submodule": "cicap",
    "methods": [
      "antivirusGet",
      "generalGet",
      "serviceCheckclamav",
      "serviceStatus"
    ]
  },
  "plugin_cicap_write": {
    "toolName": "plugin_cicap_write",
    "module": "plugins",
    "submodule": "cicap",
    "methods": [
      "antivirusSet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_clamav_read": {
    "toolName": "plugin_clamav_read",
    "module": "plugins",
    "submodule": "clamav",
    "methods": [
      "generalGet",
      "serviceFreshclam",
      "serviceStatus",
      "serviceVersion",
      "urlGet",
      "urlGetUrl"
    ]
  },
  "plugin_clamav_write": {
    "toolName": "plugin_clamav_write",
    "module": "plugins",
    "submodule": "clamav",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "urlAddUrl",
      "urlDelUrl",
      "urlSet",
      "urlSetUrl",
      "urlToggleUrl"
    ]
  },
  "plugin_collectd_read": {
    "toolName": "plugin_collectd_read",
    "module": "plugins",
    "submodule": "collectd",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_collectd_write": {
    "toolName": "plugin_collectd_write",
    "module": "plugins",
    "submodule": "collectd",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_crowdsec_read": {
    "toolName": "plugin_crowdsec_read",
    "module": "plugins",
    "submodule": "crowdsec",
    "methods": [
      "alertsGet",
      "bouncersGet",
      "decisionsGet",
      "generalGet",
      "hubGet",
      "machinesGet",
      "serviceDebug",
      "serviceStatus",
      "versionGet"
    ]
  },
  "plugin_crowdsec_write": {
    "toolName": "plugin_crowdsec_write",
    "module": "plugins",
    "submodule": "crowdsec",
    "methods": [
      "decisionsDelete",
      "generalSet",
      "serviceReload"
    ]
  },
  "plugin_dechw_read": {
    "toolName": "plugin_dechw_read",
    "module": "plugins",
    "submodule": "dechw",
    "methods": [
      "infoPowerStatus"
    ]
  },
  "plugin_diagnostics_read": {
    "toolName": "plugin_diagnostics_read",
    "module": "plugins",
    "submodule": "diagnostics",
    "methods": [
      "proofpointEtStatus"
    ]
  },
  "plugin_dmidecode_read": {
    "toolName": "plugin_dmidecode_read",
    "module": "plugins",
    "submodule": "dmidecode",
    "methods": [
      "serviceGet"
    ]
  },
  "plugin_dnscryptproxy_read": {
    "toolName": "plugin_dnscryptproxy_read",
    "module": "plugins",
    "submodule": "dnscryptproxy",
    "methods": [
      "cloakGet",
      "cloakGetCloak",
      "dnsblGet",
      "forwardGet",
      "forwardGetForward",
      "generalGet",
      "serverGet",
      "serverGetServer",
      "serviceDnsbl",
      "serviceStatus",
      "whitelistGet",
      "whitelistGetWhitelist"
    ]
  },
  "plugin_dnscryptproxy_write": {
    "toolName": "plugin_dnscryptproxy_write",
    "module": "plugins",
    "submodule": "dnscryptproxy",
    "methods": [
      "cloakAddCloak",
      "cloakDelCloak",
      "cloakSet",
      "cloakSetCloak",
      "cloakToggleCloak",
      "dnsblSet",
      "forwardAddForward",
      "forwardDelForward",
      "forwardSet",
      "forwardSetForward",
      "forwardToggleForward",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "whitelistAddWhitelist",
      "whitelistDelWhitelist",
      "whitelistSet",
      "whitelistSetWhitelist",
      "whitelistToggleWhitelist"
    ]
  },
  "plugin_dyndns_read": {
    "toolName": "plugin_dyndns_read",
    "module": "plugins",
    "submodule": "dyndns",
    "methods": [
      "accountsGet",
      "accountsGetItem",
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_dyndns_write": {
    "toolName": "plugin_dyndns_write",
    "module": "plugins",
    "submodule": "dyndns",
    "methods": [
      "accountsAddItem",
      "accountsDelItem",
      "accountsSet",
      "accountsSetItem",
      "accountsToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_freeradius_read": {
    "toolName": "plugin_freeradius_read",
    "module": "plugins",
    "submodule": "freeradius",
    "methods": [
      "avpairGet",
      "avpairGetAvpair",
      "clientGet",
      "clientGetClient",
      "clientSearchClient",
      "dhcpGet",
      "dhcpGetDhcp",
      "eapGet",
      "generalGet",
      "ldapGet",
      "leaseGet",
      "leaseGetLease",
      "proxyGet",
      "proxyGetHomeserver",
      "proxyGetHomeserverpool",
      "proxyGetRealm",
      "proxySearchHomeserver",
      "proxySearchHomeserverpool",
      "proxySearchRealm",
      "serviceStatus",
      "userGet",
      "userGetUser",
      "userSearchUser"
    ]
  },
  "plugin_freeradius_write": {
    "toolName": "plugin_freeradius_write",
    "module": "plugins",
    "submodule": "freeradius",
    "methods": [
      "avpairAddAvpair",
      "avpairDelAvpair",
      "avpairSet",
      "avpairSetAvpair",
      "avpairToggleAvpair",
      "clientAddClient",
      "clientDelClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "dhcpAddDhcp",
      "dhcpDelDhcp",
      "dhcpSet",
      "dhcpSetDhcp",
      "dhcpToggleDhcp",
      "eapSet",
      "generalSet",
      "ldapSet",
      "leaseAddLease",
      "leaseDelLease",
      "leaseSet",
      "leaseSetLease",
      "leaseToggleLease",
      "proxyAddHomeserver",
      "proxyAddHomeserverpool",
      "proxyAddRealm",
      "proxyDelHomeserver",
      "proxyDelHomeserverpool",
      "proxyDelRealm",
      "proxySet",
      "proxySetHomeserver",
      "proxySetHomeserverpool",
      "proxySetRealm",
      "proxyToggleHomeserver",
      "proxyToggleHomeserverpool",
      "proxyToggleRealm",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ]
  },
  "plugin_ftpproxy_read": {
    "toolName": "plugin_ftpproxy_read",
    "module": "plugins",
    "submodule": "ftpproxy",
    "methods": [
      "serviceConfig",
      "serviceStatus",
      "settingsGetProxy",
      "settingsSearchProxy"
    ]
  },
  "plugin_ftpproxy_write": {
    "toolName": "plugin_ftpproxy_write",
    "module": "plugins",
    "submodule": "ftpproxy",
    "methods": [
      "serviceReload",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddProxy",
      "settingsDelProxy",
      "settingsSetProxy",
      "settingsToggleProxy"
    ]
  },
  "plugin_gridexample_read": {
    "toolName": "plugin_gridexample_read",
    "module": "plugins",
    "submodule": "gridexample",
    "methods": [
      "settingsGet",
      "settingsGetItem"
    ]
  },
  "plugin_gridexample_write": {
    "toolName": "plugin_gridexample_write",
    "module": "plugins",
    "submodule": "gridexample",
    "methods": [
      "settingsAddItem",
      "settingsDelItem",
      "settingsSet",
      "settingsSetItem",
      "settingsToggleItem"
    ]
  },
  "plugin_haproxy_read": {
    "toolName": "plugin_haproxy_read",
    "module": "plugins",
    "submodule": "haproxy",
    "methods": [
      "exportConfig",
      "exportDiff",
      "exportDownload",
      "maintenanceCertActions",
      "maintenanceCertDiff",
      "maintenanceCertSync",
      "maintenanceCertSyncBulk",
      "maintenanceFetchCronIntegration",
      "maintenanceGet",
      "maintenanceSearchCertificateDiff",
      "maintenanceSearchServer",
      "maintenanceServerState",
      "maintenanceServerStateBulk",
      "maintenanceServerWeight",
      "maintenanceServerWeightBulk",
      "serviceConfigtest",
      "serviceStatus",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetAction",
      "settingsGetBackend",
      "settingsGetCpu",
      "settingsGetErrorfile",
      "settingsGetFcgi",
      "settingsGetFrontend",
      "settingsGetGroup",
      "settingsGetHealthcheck",
      "settingsGetLua",
      "settingsGetMapfile",
      "settingsGetServer",
      "settingsGetUser",
      "settingsGetmailer",
      "settingsGetresolver",
      "statisticsCounters",
      "statisticsInfo",
      "statisticsTables"
    ]
  },
  "plugin_haproxy_write": {
    "toolName": "plugin_haproxy_write",
    "module": "plugins",
    "submodule": "haproxy",
    "methods": [
      "maintenanceSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddAction",
      "settingsAddBackend",
      "settingsAddCpu",
      "settingsAddErrorfile",
      "settingsAddFcgi",
      "settingsAddFrontend",
      "settingsAddGroup",
      "settingsAddHealthcheck",
      "settingsAddLua",
      "settingsAddMapfile",
      "settingsAddServer",
      "settingsAddUser",
      "settingsAddmailer",
      "settingsAddresolver",
      "settingsDelAcl",
      "settingsDelAction",
      "settingsDelBackend",
      "settingsDelCpu",
      "settingsDelErrorfile",
      "settingsDelFcgi",
      "settingsDelFrontend",
      "settingsDelGroup",
      "settingsDelHealthcheck",
      "settingsDelLua",
      "settingsDelMapfile",
      "settingsDelServer",
      "settingsDelUser",
      "settingsDelmailer",
      "settingsDelresolver",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetAction",
      "settingsSetBackend",
      "settingsSetCpu",
      "settingsSetErrorfile",
      "settingsSetFcgi",
      "settingsSetFrontend",
      "settingsSetGroup",
      "settingsSetHealthcheck",
      "settingsSetLua",
      "settingsSetMapfile",
      "settingsSetServer",
      "settingsSetUser",
      "settingsSetmailer",
      "settingsSetresolver",
      "settingsToggleBackend",
      "settingsToggleCpu",
      "settingsToggleFrontend",
      "settingsToggleGroup",
      "settingsToggleLua",
      "settingsToggleServer",
      "settingsToggleUser",
      "settingsTogglemailer",
      "settingsToggleresolver"
    ]
  },
  "plugin_helloworld_read": {
    "toolName": "plugin_helloworld_read",
    "module": "plugins",
    "submodule": "helloworld",
    "methods": [
      "serviceTest",
      "settingsGet"
    ]
  },
  "plugin_helloworld_write": {
    "toolName": "plugin_helloworld_write",
    "module": "plugins",
    "submodule": "helloworld",
    "methods": [
      "serviceReload",
      "settingsSet"
    ]
  },
  "plugin_hwprobe_read": {
    "toolName": "plugin_hwprobe_read",
    "module": "plugins",
    "submodule": "hwprobe",
    "methods": [
      "generalGet",
      "serviceReport",
      "serviceStatus"
    ]
  },
  "plugin_hwprobe_write": {
    "toolName": "plugin_hwprobe_write",
    "module": "plugins",
    "submodule": "hwprobe",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_iperf_read": {
    "toolName": "plugin_iperf_read",
    "module": "plugins",
    "submodule": "iperf",
    "methods": [
      "instanceGet",
      "instanceQuery",
      "serviceStatus"
    ]
  },
  "plugin_iperf_write": {
    "toolName": "plugin_iperf_write",
    "module": "plugins",
    "submodule": "iperf",
    "methods": [
      "instanceSet",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_lldpd_read": {
    "toolName": "plugin_lldpd_read",
    "module": "plugins",
    "submodule": "lldpd",
    "methods": [
      "generalGet",
      "serviceNeighbor",
      "serviceStatus"
    ]
  },
  "plugin_lldpd_write": {
    "toolName": "plugin_lldpd_write",
    "module": "plugins",
    "submodule": "lldpd",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_maltrail_read": {
    "toolName": "plugin_maltrail_read",
    "module": "plugins",
    "submodule": "maltrail",
    "methods": [
      "generalGet",
      "sensorGet",
      "serverGet",
      "serverserviceStatus",
      "serviceStatus"
    ]
  },
  "plugin_maltrail_write": {
    "toolName": "plugin_maltrail_write",
    "module": "plugins",
    "submodule": "maltrail",
    "methods": [
      "generalSet",
      "sensorSet",
      "serverSet",
      "serverserviceReconfigure",
      "serverserviceRestart",
      "serverserviceStart",
      "serverserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_mdnsrepeater_read": {
    "toolName": "plugin_mdnsrepeater_read",
    "module": "plugins",
    "submodule": "mdnsrepeater",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_mdnsrepeater_write": {
    "toolName": "plugin_mdnsrepeater_write",
    "module": "plugins",
    "submodule": "mdnsrepeater",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_muninnode_read": {
    "toolName": "plugin_muninnode_read",
    "module": "plugins",
    "submodule": "muninnode",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_muninnode_write": {
    "toolName": "plugin_muninnode_write",
    "module": "plugins",
    "submodule": "muninnode",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_ndproxy_read": {
    "toolName": "plugin_ndproxy_read",
    "module": "plugins",
    "submodule": "ndproxy",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_ndproxy_write": {
    "toolName": "plugin_ndproxy_write",
    "module": "plugins",
    "submodule": "ndproxy",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_netdata_read": {
    "toolName": "plugin_netdata_read",
    "module": "plugins",
    "submodule": "netdata",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_netdata_write": {
    "toolName": "plugin_netdata_write",
    "module": "plugins",
    "submodule": "netdata",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_netsnmp_read": {
    "toolName": "plugin_netsnmp_read",
    "module": "plugins",
    "submodule": "netsnmp",
    "methods": [
      "generalGet",
      "serviceStatus",
      "userGet",
      "userGetUser"
    ]
  },
  "plugin_netsnmp_write": {
    "toolName": "plugin_netsnmp_write",
    "module": "plugins",
    "submodule": "netsnmp",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ]
  },
  "plugin_nginx_read": {
    "toolName": "plugin_nginx_read",
    "module": "plugins",
    "submodule": "nginx",
    "methods": [
      "bansGet",
      "logsAccesses",
      "logsErrors",
      "logsStreamaccesses",
      "logsStreamerrors",
      "logsTlsHandshakes",
      "serviceStatus",
      "serviceVts",
      "settingsDownloadrules",
      "settingsGet",
      "settingsGetcachePath",
      "settingsGetcredential",
      "settingsGetcustompolicy",
      "settingsGeterrorpage",
      "settingsGethttprewrite",
      "settingsGethttpserver",
      "settingsGetipacl",
      "settingsGetlimitRequestConnection",
      "settingsGetlimitZone",
      "settingsGetlocation",
      "settingsGetnaxsirule",
      "settingsGetresolver",
      "settingsGetsecurityHeader",
      "settingsGetsnifwd",
      "settingsGetstreamserver",
      "settingsGetsyslogTarget",
      "settingsGettlsFingerprint",
      "settingsGetupstream",
      "settingsGetupstreamserver",
      "settingsGetuserlist",
      "settingsShowconfig",
      "settingsTestconfig"
    ]
  },
  "plugin_nginx_write": {
    "toolName": "plugin_nginx_write",
    "module": "plugins",
    "submodule": "nginx",
    "methods": [
      "bansDelban",
      "bansSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddcachePath",
      "settingsAddcredential",
      "settingsAddcustompolicy",
      "settingsAdderrorpage",
      "settingsAddhttprewrite",
      "settingsAddhttpserver",
      "settingsAddipacl",
      "settingsAddlimitRequestConnection",
      "settingsAddlimitZone",
      "settingsAddlocation",
      "settingsAddnaxsirule",
      "settingsAddresolver",
      "settingsAddsecurityHeader",
      "settingsAddsnifwd",
      "settingsAddstreamserver",
      "settingsAddsyslogTarget",
      "settingsAddtlsFingerprint",
      "settingsAddupstream",
      "settingsAddupstreamserver",
      "settingsAdduserlist",
      "settingsDelcachePath",
      "settingsDelcredential",
      "settingsDelcustompolicy",
      "settingsDelerrorpage",
      "settingsDelhttprewrite",
      "settingsDelhttpserver",
      "settingsDelipacl",
      "settingsDellimitRequestConnection",
      "settingsDellimitZone",
      "settingsDellocation",
      "settingsDelnaxsirule",
      "settingsDelresolver",
      "settingsDelsecurityHeader",
      "settingsDelsnifwd",
      "settingsDelstreamserver",
      "settingsDelsyslogTarget",
      "settingsDeltlsFingerprint",
      "settingsDelupstream",
      "settingsDelupstreamserver",
      "settingsDeluserlist",
      "settingsSet",
      "settingsSetcachePath",
      "settingsSetcredential",
      "settingsSetcustompolicy",
      "settingsSeterrorpage",
      "settingsSethttprewrite",
      "settingsSethttpserver",
      "settingsSetipacl",
      "settingsSetlimitRequestConnection",
      "settingsSetlimitZone",
      "settingsSetlocation",
      "settingsSetnaxsirule",
      "settingsSetresolver",
      "settingsSetsecurityHeader",
      "settingsSetsnifwd",
      "settingsSetstreamserver",
      "settingsSetsyslogTarget",
      "settingsSettlsFingerprint",
      "settingsSetupstream",
      "settingsSetupstreamserver",
      "settingsSetuserlist"
    ]
  },
  "plugin_nodeexporter_read": {
    "toolName": "plugin_nodeexporter_read",
    "module": "plugins",
    "submodule": "nodeexporter",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_nodeexporter_write": {
    "toolName": "plugin_nodeexporter_write",
    "module": "plugins",
    "submodule": "nodeexporter",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_nrpe_read": {
    "toolName": "plugin_nrpe_read",
    "module": "plugins",
    "submodule": "nrpe",
    "methods": [
      "commandGet",
      "commandGetCommand",
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_nrpe_write": {
    "toolName": "plugin_nrpe_write",
    "module": "plugins",
    "submodule": "nrpe",
    "methods": [
      "commandAddCommand",
      "commandDelCommand",
      "commandSet",
      "commandSetCommand",
      "commandToggleCommand",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_ntopng_read": {
    "toolName": "plugin_ntopng_read",
    "module": "plugins",
    "submodule": "ntopng",
    "methods": [
      "generalGet",
      "serviceCheckredis",
      "serviceStatus"
    ]
  },
  "plugin_ntopng_write": {
    "toolName": "plugin_ntopng_write",
    "module": "plugins",
    "submodule": "ntopng",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_nut_read": {
    "toolName": "plugin_nut_read",
    "module": "plugins",
    "submodule": "nut",
    "methods": [
      "diagnosticsUpsstatus",
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_nut_write": {
    "toolName": "plugin_nut_write",
    "module": "plugins",
    "submodule": "nut",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_openconnect_read": {
    "toolName": "plugin_openconnect_read",
    "module": "plugins",
    "submodule": "openconnect",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_openconnect_write": {
    "toolName": "plugin_openconnect_write",
    "module": "plugins",
    "submodule": "openconnect",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_postfix_read": {
    "toolName": "plugin_postfix_read",
    "module": "plugins",
    "submodule": "postfix",
    "methods": [
      "addressGet",
      "addressGetAddress",
      "antispamGet",
      "domainGet",
      "domainGetDomain",
      "generalGet",
      "headerchecksGet",
      "headerchecksGetHeadercheck",
      "recipientGet",
      "recipientGetRecipient",
      "recipientbccGet",
      "recipientbccGetRecipientbcc",
      "senderGet",
      "senderGetSender",
      "senderbccGet",
      "senderbccGetSenderbcc",
      "sendercanonicalGet",
      "sendercanonicalGetSendercanonical",
      "serviceCheckrspamd",
      "serviceStatus"
    ]
  },
  "plugin_postfix_write": {
    "toolName": "plugin_postfix_write",
    "module": "plugins",
    "submodule": "postfix",
    "methods": [
      "addressAddAddress",
      "addressDelAddress",
      "addressSet",
      "addressSetAddress",
      "addressToggleAddress",
      "antispamSet",
      "domainAddDomain",
      "domainDelDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalSet",
      "headerchecksAddHeadercheck",
      "headerchecksDelHeadercheck",
      "headerchecksSet",
      "headerchecksSetHeadercheck",
      "headerchecksToggleHeadercheck",
      "recipientAddRecipient",
      "recipientDelRecipient",
      "recipientSet",
      "recipientSetRecipient",
      "recipientToggleRecipient",
      "recipientbccAddRecipientbcc",
      "recipientbccDelRecipientbcc",
      "recipientbccSet",
      "recipientbccSetRecipientbcc",
      "recipientbccToggleRecipientbcc",
      "senderAddSender",
      "senderDelSender",
      "senderSet",
      "senderSetSender",
      "senderToggleSender",
      "senderbccAddSenderbcc",
      "senderbccDelSenderbcc",
      "senderbccSet",
      "senderbccSetSenderbcc",
      "senderbccToggleSenderbcc",
      "sendercanonicalAddSendercanonical",
      "sendercanonicalDelSendercanonical",
      "sendercanonicalSet",
      "sendercanonicalSetSendercanonical",
      "sendercanonicalToggleSendercanonical",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_proxy_read": {
    "toolName": "plugin_proxy_read",
    "module": "plugins",
    "submodule": "proxy",
    "methods": [
      "serviceDownloadacls",
      "serviceFetchacls",
      "serviceStatus",
      "settingsFetchRBCron",
      "settingsGet",
      "settingsGetPACMatch",
      "settingsGetPACProxy",
      "settingsGetPACRule",
      "settingsGetRemoteBlacklist",
      "settingsSearchRemoteBlacklists",
      "templateGet",
      "aclGet",
      "aclGetCustomPolicy",
      "aclGetPolicy",
      "aclTest"
    ]
  },
  "plugin_proxy_write": {
    "toolName": "plugin_proxy_write",
    "module": "plugins",
    "submodule": "proxy",
    "methods": [
      "serviceReconfigure",
      "serviceRefreshTemplate",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddPACMatch",
      "settingsAddPACProxy",
      "settingsAddPACRule",
      "settingsAddRemoteBlacklist",
      "settingsDelPACMatch",
      "settingsDelPACProxy",
      "settingsDelPACRule",
      "settingsDelRemoteBlacklist",
      "settingsSet",
      "settingsSetPACMatch",
      "settingsSetPACProxy",
      "settingsSetPACRule",
      "settingsSetRemoteBlacklist",
      "settingsTogglePACRule",
      "settingsToggleRemoteBlacklist",
      "templateReset",
      "templateSet",
      "aclAddCustomPolicy",
      "aclAddPolicy",
      "aclApply",
      "aclDelCustomPolicy",
      "aclDelPolicy",
      "aclSet",
      "aclSetCustomPolicy",
      "aclSetPolicy",
      "aclToggleCustomPolicy",
      "aclTogglePolicy"
    ]
  },
  "plugin_proxysso_read": {
    "toolName": "plugin_proxysso_read",
    "module": "plugins",
    "submodule": "proxysso",
    "methods": [
      "serviceGetCheckList",
      "serviceShowkeytab",
      "serviceTestkerblogin",
      "settingsGet"
    ]
  },
  "plugin_proxysso_write": {
    "toolName": "plugin_proxysso_write",
    "module": "plugins",
    "submodule": "proxysso",
    "methods": [
      "serviceCreatekeytab",
      "serviceDeletekeytab",
      "settingsSet"
    ]
  },
  "plugin_puppetagent_read": {
    "toolName": "plugin_puppetagent_read",
    "module": "plugins",
    "submodule": "puppetagent",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_puppetagent_write": {
    "toolName": "plugin_puppetagent_write",
    "module": "plugins",
    "submodule": "puppetagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_qemuguestagent_read": {
    "toolName": "plugin_qemuguestagent_read",
    "module": "plugins",
    "submodule": "qemuguestagent",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_qemuguestagent_write": {
    "toolName": "plugin_qemuguestagent_write",
    "module": "plugins",
    "submodule": "qemuguestagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_quagga_read": {
    "toolName": "plugin_quagga_read",
    "module": "plugins",
    "submodule": "quagga",
    "methods": [
      "bfdGet",
      "bfdGetNeighbor",
      "bgpGet",
      "bgpGetAspath",
      "bgpGetCommunitylist",
      "bgpGetNeighbor",
      "bgpGetPeergroup",
      "bgpGetPrefixlist",
      "bgpGetRedistribution",
      "bgpGetRoutemap",
      "diagnosticsBfdcounters",
      "diagnosticsBfdneighbors",
      "diagnosticsBfdsummary",
      "diagnosticsBgpneighbors",
      "diagnosticsBgpsummary",
      "diagnosticsGeneralrunningconfig",
      "diagnosticsOspfdatabase",
      "diagnosticsOspfinterface",
      "diagnosticsOspfoverview",
      "diagnosticsOspfv3interface",
      "diagnosticsOspfv3overview",
      "diagnosticsSearchBgproute4",
      "diagnosticsSearchBgproute6",
      "diagnosticsSearchGeneralroute4",
      "diagnosticsSearchGeneralroute6",
      "diagnosticsSearchOspfneighbor",
      "diagnosticsSearchOspfroute",
      "diagnosticsSearchOspfv3database",
      "diagnosticsSearchOspfv3route",
      "generalGet",
      "ospf6settingsGet",
      "ospf6settingsGetInterface",
      "ospf6settingsGetNetwork",
      "ospf6settingsGetPrefixlist",
      "ospf6settingsGetRedistribution",
      "ospf6settingsGetRoutemap",
      "ospfsettingsGet",
      "ospfsettingsGetInterface",
      "ospfsettingsGetNetwork",
      "ospfsettingsGetPrefixlist",
      "ospfsettingsGetRedistribution",
      "ospfsettingsGetRoutemap",
      "ripGet",
      "serviceStatus",
      "staticGet",
      "staticGetRoute"
    ]
  },
  "plugin_quagga_write": {
    "toolName": "plugin_quagga_write",
    "module": "plugins",
    "submodule": "quagga",
    "methods": [
      "bfdAddNeighbor",
      "bfdDelNeighbor",
      "bfdSet",
      "bfdSetNeighbor",
      "bfdToggleNeighbor",
      "bgpAddAspath",
      "bgpAddCommunitylist",
      "bgpAddNeighbor",
      "bgpAddPeergroup",
      "bgpAddPrefixlist",
      "bgpAddRedistribution",
      "bgpAddRoutemap",
      "bgpDelAspath",
      "bgpDelCommunitylist",
      "bgpDelNeighbor",
      "bgpDelPeergroup",
      "bgpDelPrefixlist",
      "bgpDelRedistribution",
      "bgpDelRoutemap",
      "bgpSet",
      "bgpSetAspath",
      "bgpSetCommunitylist",
      "bgpSetNeighbor",
      "bgpSetPeergroup",
      "bgpSetPrefixlist",
      "bgpSetRedistribution",
      "bgpSetRoutemap",
      "bgpToggleAspath",
      "bgpToggleCommunitylist",
      "bgpToggleNeighbor",
      "bgpTogglePeergroup",
      "bgpTogglePrefixlist",
      "bgpToggleRedistribution",
      "bgpToggleRoutemap",
      "generalSet",
      "ospf6settingsAddInterface",
      "ospf6settingsAddNetwork",
      "ospf6settingsAddPrefixlist",
      "ospf6settingsAddRedistribution",
      "ospf6settingsAddRoutemap",
      "ospf6settingsDelInterface",
      "ospf6settingsDelNetwork",
      "ospf6settingsDelPrefixlist",
      "ospf6settingsDelRedistribution",
      "ospf6settingsDelRoutemap",
      "ospf6settingsSet",
      "ospf6settingsSetInterface",
      "ospf6settingsSetNetwork",
      "ospf6settingsSetPrefixlist",
      "ospf6settingsSetRedistribution",
      "ospf6settingsSetRoutemap",
      "ospf6settingsToggleInterface",
      "ospf6settingsToggleNetwork",
      "ospf6settingsTogglePrefixlist",
      "ospf6settingsToggleRedistribution",
      "ospf6settingsToggleRoutemap",
      "ospfsettingsAddInterface",
      "ospfsettingsAddNetwork",
      "ospfsettingsAddPrefixlist",
      "ospfsettingsAddRedistribution",
      "ospfsettingsAddRoutemap",
      "ospfsettingsDelInterface",
      "ospfsettingsDelNetwork",
      "ospfsettingsDelPrefixlist",
      "ospfsettingsDelRedistribution",
      "ospfsettingsDelRoutemap",
      "ospfsettingsSet",
      "ospfsettingsSetInterface",
      "ospfsettingsSetNetwork",
      "ospfsettingsSetPrefixlist",
      "ospfsettingsSetRedistribution",
      "ospfsettingsSetRoutemap",
      "ospfsettingsToggleInterface",
      "ospfsettingsToggleNetwork",
      "ospfsettingsTogglePrefixlist",
      "ospfsettingsToggleRedistribution",
      "ospfsettingsToggleRoutemap",
      "ripSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "staticAddRoute",
      "staticDelRoute",
      "staticSet",
      "staticSetRoute",
      "staticToggleRoute"
    ]
  },
  "plugin_radsecproxy_read": {
    "toolName": "plugin_radsecproxy_read",
    "module": "plugins",
    "submodule": "radsecproxy",
    "methods": [
      "clientsGet",
      "clientsGetItem",
      "generalGet",
      "realmsGet",
      "realmsGetItem",
      "rewritesGet",
      "rewritesGetItem",
      "serversGet",
      "serversGetItem",
      "serviceStatus",
      "tlsGet",
      "tlsGetItem"
    ]
  },
  "plugin_radsecproxy_write": {
    "toolName": "plugin_radsecproxy_write",
    "module": "plugins",
    "submodule": "radsecproxy",
    "methods": [
      "clientsAddItem",
      "clientsDelItem",
      "clientsSet",
      "clientsSetItem",
      "clientsToggleItem",
      "generalSet",
      "realmsAddItem",
      "realmsDelItem",
      "realmsSet",
      "realmsSetItem",
      "realmsToggleItem",
      "rewritesAddItem",
      "rewritesDelItem",
      "rewritesSet",
      "rewritesSetItem",
      "rewritesToggleItem",
      "serversAddItem",
      "serversDelItem",
      "serversSet",
      "serversSetItem",
      "serversToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "tlsAddItem",
      "tlsDelItem",
      "tlsSet",
      "tlsSetItem",
      "tlsToggleItem"
    ]
  },
  "plugin_redis_read": {
    "toolName": "plugin_redis_read",
    "module": "plugins",
    "submodule": "redis",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_redis_write": {
    "toolName": "plugin_redis_write",
    "module": "plugins",
    "submodule": "redis",
    "methods": [
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_relayd_read": {
    "toolName": "plugin_relayd_read",
    "module": "plugins",
    "submodule": "relayd",
    "methods": [
      "serviceConfigtest",
      "serviceStatus",
      "settingsDirty",
      "settingsGet",
      "settingsSearch",
      "statusSum"
    ]
  },
  "plugin_relayd_write": {
    "toolName": "plugin_relayd_write",
    "module": "plugins",
    "submodule": "relayd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsDel",
      "settingsSet",
      "settingsToggle",
      "statusToggle"
    ]
  },
  "plugin_rspamd_read": {
    "toolName": "plugin_rspamd_read",
    "module": "plugins",
    "submodule": "rspamd",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_rspamd_write": {
    "toolName": "plugin_rspamd_write",
    "module": "plugins",
    "submodule": "rspamd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_shadowsocks_read": {
    "toolName": "plugin_shadowsocks_read",
    "module": "plugins",
    "submodule": "shadowsocks",
    "methods": [
      "generalGet",
      "localGet",
      "localserviceStatus",
      "serviceStatus"
    ]
  },
  "plugin_shadowsocks_write": {
    "toolName": "plugin_shadowsocks_write",
    "module": "plugins",
    "submodule": "shadowsocks",
    "methods": [
      "generalSet",
      "localSet",
      "localserviceReconfigure",
      "localserviceRestart",
      "localserviceStart",
      "localserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_siproxd_read": {
    "toolName": "plugin_siproxd_read",
    "module": "plugins",
    "submodule": "siproxd",
    "methods": [
      "domainGet",
      "domainGetDomain",
      "domainSearchDomain",
      "generalGet",
      "serviceShowregistrations",
      "serviceStatus",
      "userGet",
      "userGetUser",
      "userSearchUser"
    ]
  },
  "plugin_siproxd_write": {
    "toolName": "plugin_siproxd_write",
    "module": "plugins",
    "submodule": "siproxd",
    "methods": [
      "domainAddDomain",
      "domainDelDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ]
  },
  "plugin_smart_read": {
    "toolName": "plugin_smart_read",
    "module": "plugins",
    "submodule": "smart",
    "methods": [
      "serviceAbort",
      "serviceInfo",
      "serviceList",
      "serviceLogs",
      "serviceTest"
    ]
  },
  "plugin_softether_read": {
    "toolName": "plugin_softether_read",
    "module": "plugins",
    "submodule": "softether",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_softether_write": {
    "toolName": "plugin_softether_write",
    "module": "plugins",
    "submodule": "softether",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_sslh_read": {
    "toolName": "plugin_sslh_read",
    "module": "plugins",
    "submodule": "sslh",
    "methods": [
      "serviceStatus",
      "settingsGet",
      "settingsIndex"
    ]
  },
  "plugin_sslh_write": {
    "toolName": "plugin_sslh_write",
    "module": "plugins",
    "submodule": "sslh",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_stunnel_read": {
    "toolName": "plugin_stunnel_read",
    "module": "plugins",
    "submodule": "stunnel",
    "methods": [
      "serviceStatus",
      "servicesGet",
      "servicesGetItem"
    ]
  },
  "plugin_stunnel_write": {
    "toolName": "plugin_stunnel_write",
    "module": "plugins",
    "submodule": "stunnel",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "servicesAddItem",
      "servicesDelItem",
      "servicesSet",
      "servicesSetItem",
      "servicesToggleItem"
    ]
  },
  "plugin_tailscale_read": {
    "toolName": "plugin_tailscale_read",
    "module": "plugins",
    "submodule": "tailscale",
    "methods": [
      "authenticationGet",
      "serviceStatus",
      "settingsGet",
      "settingsGetSubnet",
      "statusGet",
      "statusIp",
      "statusNet",
      "status"
    ]
  },
  "plugin_tailscale_write": {
    "toolName": "plugin_tailscale_write",
    "module": "plugins",
    "submodule": "tailscale",
    "methods": [
      "authenticationSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddSubnet",
      "settingsDelSubnet",
      "settingsReload",
      "settingsSet",
      "settingsSetSubnet",
      "statusSet"
    ]
  },
  "plugin_tayga_read": {
    "toolName": "plugin_tayga_read",
    "module": "plugins",
    "submodule": "tayga",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_tayga_write": {
    "toolName": "plugin_tayga_write",
    "module": "plugins",
    "submodule": "tayga",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_telegraf_read": {
    "toolName": "plugin_telegraf_read",
    "module": "plugins",
    "submodule": "telegraf",
    "methods": [
      "generalGet",
      "inputGet",
      "keyGet",
      "keyGetKey",
      "outputGet",
      "serviceStatus"
    ]
  },
  "plugin_telegraf_write": {
    "toolName": "plugin_telegraf_write",
    "module": "plugins",
    "submodule": "telegraf",
    "methods": [
      "generalSet",
      "inputSet",
      "keyAddKey",
      "keyDelKey",
      "keySet",
      "keySetKey",
      "keyToggleKey",
      "outputSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_tftp_read": {
    "toolName": "plugin_tftp_read",
    "module": "plugins",
    "submodule": "tftp",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_tftp_write": {
    "toolName": "plugin_tftp_write",
    "module": "plugins",
    "submodule": "tftp",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_tinc_read": {
    "toolName": "plugin_tinc_read",
    "module": "plugins",
    "submodule": "tinc",
    "methods": [
      "settingsGet",
      "settingsGetHost",
      "settingsGetNetwork",
      "settingsSearchHost",
      "settingsSearchNetwork"
    ]
  },
  "plugin_tinc_write": {
    "toolName": "plugin_tinc_write",
    "module": "plugins",
    "submodule": "tinc",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsDelHost",
      "settingsDelNetwork",
      "settingsSet",
      "settingsSetHost",
      "settingsSetNetwork",
      "settingsToggleHost",
      "settingsToggleNetwork"
    ]
  },
  "plugin_tor_read": {
    "toolName": "plugin_tor_read",
    "module": "plugins",
    "submodule": "tor",
    "methods": [
      "exitaclGet",
      "exitaclGetacl",
      "generalGet",
      "generalGethidservauth",
      "hiddenserviceGet",
      "hiddenserviceGetservice",
      "hiddenserviceaclGet",
      "hiddenserviceaclGetacl",
      "relayGet",
      "serviceCircuits",
      "serviceGetHiddenServices",
      "serviceStatus",
      "serviceStreams",
      "socksaclGet",
      "socksaclGetacl"
    ]
  },
  "plugin_tor_write": {
    "toolName": "plugin_tor_write",
    "module": "plugins",
    "submodule": "tor",
    "methods": [
      "exitaclAddacl",
      "exitaclDelacl",
      "exitaclSet",
      "exitaclSetacl",
      "exitaclToggleacl",
      "generalAddhidservauth",
      "generalDelhidservauth",
      "generalSet",
      "generalSethidservauth",
      "generalTogglehidservauth",
      "hiddenserviceAddservice",
      "hiddenserviceDelservice",
      "hiddenserviceSet",
      "hiddenserviceSetservice",
      "hiddenserviceToggleservice",
      "hiddenserviceaclAddacl",
      "hiddenserviceaclDelacl",
      "hiddenserviceaclSet",
      "hiddenserviceaclSetacl",
      "hiddenserviceaclToggleacl",
      "relaySet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "socksaclAddacl",
      "socksaclDelacl",
      "socksaclSet",
      "socksaclSetacl",
      "socksaclToggleacl"
    ]
  },
  "plugin_turnserver_read": {
    "toolName": "plugin_turnserver_read",
    "module": "plugins",
    "submodule": "turnserver",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_turnserver_write": {
    "toolName": "plugin_turnserver_write",
    "module": "plugins",
    "submodule": "turnserver",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_udpbroadcastrelay_read": {
    "toolName": "plugin_udpbroadcastrelay_read",
    "module": "plugins",
    "submodule": "udpbroadcastrelay",
    "methods": [
      "serviceConfig",
      "serviceGet",
      "serviceStatus",
      "settingsGet",
      "settingsGetRelay",
      "settingsSearchRelay"
    ]
  },
  "plugin_udpbroadcastrelay_write": {
    "toolName": "plugin_udpbroadcastrelay_write",
    "module": "plugins",
    "submodule": "udpbroadcastrelay",
    "methods": [
      "serviceReload",
      "serviceRestart",
      "serviceSet",
      "serviceStart",
      "serviceStop",
      "settingsAddRelay",
      "settingsDelRelay",
      "settingsSet",
      "settingsSetRelay",
      "settingsToggleRelay"
    ]
  },
  "plugin_vnstat_read": {
    "toolName": "plugin_vnstat_read",
    "module": "plugins",
    "submodule": "vnstat",
    "methods": [
      "generalGet",
      "serviceDaily",
      "serviceHourly",
      "serviceMonthly",
      "serviceStatus",
      "serviceYearly"
    ]
  },
  "plugin_vnstat_write": {
    "toolName": "plugin_vnstat_write",
    "module": "plugins",
    "submodule": "vnstat",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_wazuhagent_read": {
    "toolName": "plugin_wazuhagent_read",
    "module": "plugins",
    "submodule": "wazuhagent",
    "methods": [
      "serviceStatus",
      "settingsGet"
    ]
  },
  "plugin_wazuhagent_write": {
    "toolName": "plugin_wazuhagent_write",
    "module": "plugins",
    "submodule": "wazuhagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsSet"
    ]
  },
  "plugin_wol_read": {
    "toolName": "plugin_wol_read",
    "module": "plugins",
    "submodule": "wol",
    "methods": [
      "wolGet",
      "wolGetHost",
      "wolGetwake",
      "wolWakeall"
    ]
  },
  "plugin_wol_write": {
    "toolName": "plugin_wol_write",
    "module": "plugins",
    "submodule": "wol",
    "methods": [
      "wolAddHost",
      "wolDelHost",
      "wolSet",
      "wolSetHost"
    ]
  },
  "plugin_zabbixagent_read": {
    "toolName": "plugin_zabbixagent_read",
    "module": "plugins",
    "submodule": "zabbixagent",
    "methods": [
      "serviceStatus",
      "settingsGet",
      "settingsGetAlias",
      "settingsGetUserparameter"
    ]
  },
  "plugin_zabbixagent_write": {
    "toolName": "plugin_zabbixagent_write",
    "module": "plugins",
    "submodule": "zabbixagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsAddAlias",
      "settingsAddUserparameter",
      "settingsDelAlias",
      "settingsDelUserparameter",
      "settingsSet",
      "settingsSetAlias",
      "settingsSetUserparameter",
      "settingsToggleAlias",
      "settingsToggleUserparameter"
    ]
  },
  "plugin_zabbixproxy_read": {
    "toolName": "plugin_zabbixproxy_read",
    "module": "plugins",
    "submodule": "zabbixproxy",
    "methods": [
      "generalGet",
      "serviceStatus"
    ]
  },
  "plugin_zabbixproxy_write": {
    "toolName": "plugin_zabbixproxy_write",
    "module": "plugins",
    "submodule": "zabbixproxy",
    "methods": [
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop"
    ]
  },
  "plugin_zerotier_read": {
    "toolName": "plugin_zerotier_read",
    "module": "plugins",
    "submodule": "zerotier",
    "methods": [
      "networkGet",
      "networkInfo",
      "networkSearch",
      "settingsGet",
      "settingsStatus"
    ]
  },
  "plugin_zerotier_write": {
    "toolName": "plugin_zerotier_write",
    "module": "plugins",
    "submodule": "zerotier",
    "methods": [
      "networkAdd",
      "networkDel",
      "networkSet",
      "networkToggle",
      "settingsSet"
    ]
  }
};

// Infer the OPNsense API body key from a method name.
// OPNsense MVC controllers expect the model name as the top-level request body key:
//   filterAddRule      → 'rule'
//   filterSetRule      → 'rule'
//   aliasAddItem       → 'alias'   (prefix before Add/Set when model is generic 'Item')
//   keaAddReservation  → 'reservation'
//   vlanAddItem        → 'vlan'
//   serverAddServer    → 'server'
function inferBodyKey(methodName) {
  const match = methodName.match(/^(.*?)(?:Add|Set)([A-Z][a-zA-Z]*)$/);
  if (!match) return null;
  const [, prefix, model] = match;
  if (model && model.toLowerCase() !== 'item') {
    return model.charAt(0).toLowerCase() + model.slice(1);
  }
  // For addItem/setItem, the key is the prefix (e.g. aliasAddItem → 'alias')
  return prefix || null;
}

class OPNsenseMCPServer {
  constructor(config) {
    this.config = config;
    this.client = null;
    this.server = new Server(
      {
        name: 'opnsense-mcp-server',
        version: '0.6.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
  }

  ensureClient() {
    if (!this.client) {
      this.client = new OPNsenseClient({
        baseUrl: this.config.url,
        apiKey: this.config.apiKey,
        apiSecret: this.config.apiSecret,
        verifySsl: this.config.verifySsl ?? true,
      });
    }
    return this.client;
  }

  setupHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.getAvailableTools(),
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      const tool = TOOLS.find(t => t.name === name);
      if (!tool) {
        throw new McpError(ErrorCode.MethodNotFound, `Tool ${name} not found`);
      }

      // Skip plugin tools if not enabled
      if (tool.module === 'plugins' && !this.config.includePlugins) {
        throw new McpError(ErrorCode.MethodNotFound, `Plugin tools not enabled. Use --plugins flag to enable.`);
      }

      try {
        const result = await this.callModularTool(tool, args);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        console.error('Tool call error:', {
          tool: tool.name,
          module: tool.module,
          args,
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
        });
        
        // Extract more details from axios errors
        let errorMessage = 'Unknown error';
        if (error instanceof Error) {
          errorMessage = error.message;
          if (error.response) {
            const response = error.response;
            errorMessage = `HTTP ${response.status}: ${response.statusText}\n`;
            if (response.data) {
              errorMessage += `Response: ${JSON.stringify(response.data, null, 2)}`;
            }
          }
        }
        
        return {
          content: [{
            type: 'text',
            text: `Error calling ${tool.name}.${args.method || 'unknown'}: ${errorMessage}`
          }],
        };
      }
    });
  }

  getAvailableTools() {
    return TOOLS.filter(tool => {
      // Include all non-plugin tools
      if (tool.module !== 'plugins') return true;
      // Include plugin tools only if enabled
      return this.config.includePlugins;
    }).map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    }));
  }

  async callModularTool(tool, args) {
    const client = this.ensureClient();
    
    // Validate method parameter
    if (!args.method) {
      throw new Error(`Missing required parameter 'method'. Available methods: ${tool.methods.join(', ')}`);
    }
    
    if (!tool.methods.includes(args.method)) {
      throw new Error(`Invalid method '${args.method}'. Available methods: ${tool.methods.join(', ')}`);
    }
    
    // Get the module
    let moduleObj;
    if (tool.module === 'plugins' && tool.submodule) {
      moduleObj = client.plugins[tool.submodule];
    } else {
      moduleObj = client[tool.module];
    }

    if (!moduleObj) {
      throw new Error(`Module ${tool.module} not found`);
    }

    // Get the method
    const method = moduleObj[args.method];
    if (!method || typeof method !== 'function') {
      throw new Error(`Method ${args.method} not found in module ${tool.module}`);
    }

    // Extract params, excluding the method field
    const { method: _, params = {}, ...otherArgs } = args;
    let callParams = { ...params, ...otherArgs };

    // Fix OPNsense body key: add/set methods expect the model name as the top-level key.
    // e.g. filterAddRule expects {rule: {...}}, aliasAddItem expects {alias: {...}}.
    // If callParams has only an 'item' key (the old generic schema placeholder),
    // re-key it to the correct model name inferred from the method name.
    if ('item' in callParams && Object.keys(callParams).length === 1) {
      const inferredKey = inferBodyKey(args.method);
      callParams = { [inferredKey || 'item']: callParams.item };
    }

    console.error(`Calling ${tool.module}.${args.method} with params:`, callParams);

    // Only pass parameters if there are any
    if (Object.keys(callParams).length > 0) {
      return await method.call(moduleObj, callParams);
    } else {
      return await method.call(moduleObj);
    }
  }

  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('OPNsense MCP server v0.6.0 (modular) started');
    console.error(`Core tools: 48 modules`);
    console.error(`Plugin tools: 124 modules (${this.config.includePlugins ? 'enabled' : 'disabled'})`);
    console.error(`Total available: ${this.config.includePlugins ? '172' : '48'} modules`);
  }
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    url: '',
    apiKey: '',
    apiSecret: '',
    verifySsl: true,
    includePlugins: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':
      case '-u':
        config.url = args[++i];
        break;
      case '--api-key':
      case '-k':
        config.apiKey = args[++i];
        break;
      case '--api-secret':
      case '-s':
        config.apiSecret = args[++i];
        break;
      case '--no-verify-ssl':
        config.verifySsl = false;
        break;
      case '--plugins':
        config.includePlugins = true;
        break;
      case '--help':
      case '-h':
        showHelp();
        process.exit(0);
        break;
    }
  }

  return config;
}

function showHelp() {
  console.log(`
OPNsense MCP Server v0.6.0 (Modular Edition)

Usage: opnsense-mcp-server --url <url> --api-key <key> --api-secret <secret> [options]

Required:
  -u, --url <url>           OPNsense API URL (e.g., https://192.168.1.1)
  -k, --api-key <key>       API Key for authentication
  -s, --api-secret <secret> API Secret for authentication

Options:
  --no-verify-ssl           Disable SSL certificate verification
  --plugins                 Include plugin tools (adds 124 plugin modules)
  -h, --help                Show this help message

Environment Variables:
  OPNSENSE_URL              OPNsense API URL
  OPNSENSE_API_KEY          API Key
  OPNSENSE_API_SECRET       API Secret
  OPNSENSE_VERIFY_SSL       Set to 'false' to disable SSL verification
  INCLUDE_PLUGINS           Set to 'true' to include plugin tools

Examples:
  # Basic usage (48 core modules)
  opnsense-mcp-server --url https://192.168.1.1 --api-key mykey --api-secret mysecret

  # With plugins enabled (172 total modules)
  opnsense-mcp-server --url https://192.168.1.1 --api-key mykey --api-secret mysecret --plugins

Tool Usage:
  Each tool represents a module and accepts a 'method' parameter to specify the operation.
  
  Example: firewall_manage
  - method: "aliasSearchItem" - Search firewall aliases
  - method: "aliasAddItem" - Add a new alias
  - method: "aliasSetItem" - Update an existing alias (requires uuid in params)
  
  Parameters are passed in the 'params' object:
  {
    "method": "aliasSearchItem",
    "params": {
      "searchPhrase": "web",
      "current": 1,
      "rowCount": 20
    }
  }

Based on @richard-stovall/opnsense-typescript-client v0.5.3
`);
}

// Main entry point
async function main() {
  const config = parseArgs();
  
  // Use environment variables as fallback
  config.url = config.url || process.env.OPNSENSE_URL || '';
  config.apiKey = config.apiKey || process.env.OPNSENSE_API_KEY || '';
  config.apiSecret = config.apiSecret || process.env.OPNSENSE_API_SECRET || '';
  if (!config.verifySsl || process.env.OPNSENSE_VERIFY_SSL === 'false') {
    config.verifySsl = false;
  }
  if (config.includePlugins || process.env.INCLUDE_PLUGINS === 'true') {
    config.includePlugins = true;
  }

  // Validate required arguments
  if (!config.url || !config.apiKey || !config.apiSecret) {
    console.error('Error: Missing required arguments\n');
    showHelp();
    process.exit(1);
  }

  // Create and start server
  const server = new OPNsenseMCPServer(config);
  await server.start();
}

// Run the server
main().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
