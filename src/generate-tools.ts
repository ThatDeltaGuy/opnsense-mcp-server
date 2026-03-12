import * as fs from 'fs';
import * as path from 'path';
import { OPNsenseClient } from '@richard-stovall/opnsense-typescript-client';

// Create client to introspect
const client = new OPNsenseClient({
  baseUrl: 'https://dummy',
  apiKey: 'dummy',
  apiSecret: 'dummy'
});

interface ModularToolDefinition {
  name: string;
  description: string;
  module: string;
  submodule?: string;
  methods: string[];
  inputSchema: any;
}

// Get all methods from a module
function getModuleMethods(obj: any): string[] {
  if (!obj || typeof obj !== 'object') return [];

  const proto = Object.getPrototypeOf(obj);
  if (!proto) return [];

  return Object.getOwnPropertyNames(proto).filter(
    key => typeof proto[key] === 'function' && key !== 'constructor'
  );
}

// camelCase words that indicate a state-mutating (write) operation.
// Classification: split method name on uppercase letters, check if any word is in this set.
const WRITE_WORDS = new Set([
  'add', 'set', 'del', 'delete', 'toggle',
  'apply', 'reconfigure', 'reload', 'refresh',
  'restart', 'start', 'stop', 'kill', 'halt', 'reboot', 'poweroff',
  'reset', 'revert', 'rollback', 'savepoint', 'cancel',
  'activate', 'enable', 'disable',
  'save', 'store', 'restore', 'dismiss',
  'update', 'upload', 'import', 'install', 'reinstall', 'uninstall', 'remove',
  'generate', 'gen', 'sign', 'revoke', 'renew', 'issue',
  'move', 'flush', 'clear', 'create', 'init',
]);

// Some plugins use all-lowercase nouns after the action verb, so the camelCase
// split doesn't isolate the verb (e.g. 'bansDelban' → ['bans','delban']).
// These short verb prefixes trigger a startsWith check as a fallback.
const WRITE_VERB_PREFIXES = ['add', 'del', 'set', 'toggle', 'create', 'delete', 'remove', 'reset', 'sign'];

// Words that start with a write verb prefix but are NOT write actions themselves.
const NOT_WRITE_DESPITE_PREFIX = new Set(['settings', 'address', 'general', 'generate', 'generated']);

// Classify a method as read (non-mutating) or write (state-mutating).
function classifyMethod(methodName: string): 'read' | 'write' {
  const words = methodName.split(/(?=[A-Z])/).map(w => w.toLowerCase());
  for (const word of words) {
    if (WRITE_WORDS.has(word)) return 'write';
    // Prefix fallback for compound lowercase words (e.g. 'delban', 'addcachepath')
    if (!NOT_WRITE_DESPITE_PREFIX.has(word)) {
      for (const prefix of WRITE_VERB_PREFIXES) {
        if (word.length > prefix.length && word.startsWith(prefix)) return 'write';
      }
    }
  }
  return 'read';
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function generateReadSchema(methods: string[]): any {
  return {
    type: 'object',
    properties: {
      method: {
        type: 'string',
        description: 'The read method to call (non-mutating)',
        enum: methods
      },
      params: {
        type: 'object',
        description: 'Method parameters. For search: {searchPhrase: "...", current: 1, rowCount: 20}. For get: {uuid: "..."}. Many read methods take no params.',
        properties: {
          uuid: {
            type: 'string',
            description: 'Item UUID (for get operations)'
          },
          searchPhrase: {
            type: 'string',
            description: 'Search phrase (for search operations)'
          },
          current: {
            type: 'integer',
            description: 'Page number (for search operations)',
            default: 1
          },
          rowCount: {
            type: 'integer',
            description: 'Results per page (for search operations)',
            default: 20
          }
        }
      }
    },
    required: ['method']
  };
}

function generateWriteSchema(methods: string[]): any {
  return {
    type: 'object',
    properties: {
      method: {
        type: 'string',
        description: 'The write method to call (modifies state)',
        enum: methods
      },
      params: {
        type: 'object',
        description: 'Method parameters. For add/set pass the OPNsense model-keyed body (e.g. {rule: {...}} for filterAddRule, {alias: {...}} for aliasAddItem, {reservation: {...}} for keaAddReservation). For del/toggle pass {uuid: "..."}. For apply/reconfigure/service methods params is usually empty.',
        properties: {
          uuid: {
            type: 'string',
            description: 'Item UUID (for set/del/toggle operations)'
          }
        }
      }
    },
    required: ['method']
  };
}

// Split a module's methods into read/write tools. Returns 1-2 tools.
function createModuleTools(
  baseName: string,
  module: string,
  methods: string[],
  submodule?: string
): ModularToolDefinition[] {
  const readMethods = methods.filter(m => classifyMethod(m) === 'read');
  const writeMethods = methods.filter(m => classifyMethod(m) === 'write');
  const label = capitalize(submodule || module);
  const tools: ModularToolDefinition[] = [];

  if (readMethods.length > 0) {
    tools.push({
      name: `${baseName}_read`,
      description: `${label} read operations — ${readMethods.length} methods: ${readMethods.slice(0, 6).join(', ')}${readMethods.length > 6 ? '...' : ''}`,
      module,
      ...(submodule ? { submodule } : {}),
      methods: readMethods,
      inputSchema: generateReadSchema(readMethods)
    });
  }

  if (writeMethods.length > 0) {
    tools.push({
      name: `${baseName}_write`,
      description: `${label} write operations — ${writeMethods.length} methods: ${writeMethods.slice(0, 6).join(', ')}${writeMethods.length > 6 ? '...' : ''}`,
      module,
      ...(submodule ? { submodule } : {}),
      methods: writeMethods,
      inputSchema: generateWriteSchema(writeMethods)
    });
  }

  return tools;
}

// Analyze all modules and create tools
const modularTools: ModularToolDefinition[] = [];

// Core module
const coreMethods = getModuleMethods(client.core);
if (coreMethods.length > 0) {
  modularTools.push(...createModuleTools('core', 'core', coreMethods));
}

// Firewall module
const firewallMethods = getModuleMethods(client.firewall);
if (firewallMethods.length > 0) {
  modularTools.push(...createModuleTools('firewall', 'firewall', firewallMethods));
}

// Auth module
const authMethods = getModuleMethods(client.auth);
if (authMethods.length > 0) {
  modularTools.push(...createModuleTools('auth', 'auth', authMethods));
}

// Interfaces module
const interfacesMethods = getModuleMethods(client.interfaces);
if (interfacesMethods.length > 0) {
  modularTools.push(...createModuleTools('interfaces', 'interfaces', interfacesMethods));
}

// Direct modules
const directModules = [
  'captiveportal', 'cron', 'dhcpv4', 'dhcpv6', 'dhcrelay',
  'diagnostics', 'dnsmasq', 'firmware', 'ids', 'ipsec', 'kea',
  'monit', 'openvpn', 'routes', 'routing', 'syslog',
  'trafficshaper', 'trust', 'unbound', 'wireguard'
];

directModules.forEach(moduleName => {
  const mod = (client as any)[moduleName];
  if (mod) {
    const methods = getModuleMethods(mod);
    if (methods.length > 0) {
      modularTools.push(...createModuleTools(moduleName, moduleName, methods));
    }
  }
});

// Plugin modules
const plugins = client.plugins as any;
const pluginNames = Object.keys(plugins).filter(key => key !== 'http');

pluginNames.forEach(pluginName => {
  const plugin = plugins[pluginName];
  if (plugin) {
    const methods = getModuleMethods(plugin);
    if (methods.length > 0) {
      modularTools.push(...createModuleTools(`plugin_${pluginName}`, 'plugins', methods, pluginName));
    }
  }
});

const coreToolCount = modularTools.filter(t => t.module !== 'plugins').length;
const pluginToolCount = modularTools.filter(t => t.module === 'plugins').length;

console.log(`\nTotal tools generated: ${modularTools.length}`);
console.log(`Core tools: ${coreToolCount}`);
console.log(`Plugin tools: ${pluginToolCount}`);

// Count read vs write
const readCount = modularTools.filter(t => t.name.endsWith('_read')).length;
const writeCount = modularTools.filter(t => t.name.endsWith('_write')).length;
console.log(`Read tools: ${readCount}, Write tools: ${writeCount}`);

// Method documentation keyed by tool name
const methodDocs: any = {};
modularTools.forEach(tool => {
  methodDocs[tool.name] = {
    toolName: tool.name,
    module: tool.module,
    ...(tool.submodule ? { submodule: tool.submodule } : {}),
    methods: tool.methods
  };
});

// Save tool definitions
fs.writeFileSync('tools-generated.json', JSON.stringify({
  totalTools: modularTools.length,
  coreTools: coreToolCount,
  pluginTools: pluginToolCount,
  tools: modularTools,
  methodDocs: methodDocs
}, null, 2));

console.log('\nTool definitions generated successfully!');
console.log('Saved to tools-generated.json');
