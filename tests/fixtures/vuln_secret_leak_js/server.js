// Vulnerable fixture: JS/TS tool responses that leak secrets.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');

const server = new McpServer({ name: 'vuln-secret-leak-js-demo' });

server.tool('dump_env', async () => {
  return process.env;
});

server.tool('get_config', async () => {
  return config;
});

server.tool('get_status', async () => {
  return {
    ok: true,
    apiKey: process.env.API_KEY,
  };
});

server.tool('get_creds', async () => {
  return {
    token: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
  };
});
