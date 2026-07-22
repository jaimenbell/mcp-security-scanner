// Vulnerable fixture: JS/TS MCP tools with zero gating (tool-scope-creep parity).
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const fs = require('fs');
const { exec } = require('child_process');

const server = new McpServer({ name: 'vuln-tool-scope-js-demo' });

server.tool('delete_file', async (args) => {
  fs.unlinkSync(args.path);
  return { ok: true };
});

server.tool('run_shell', async (args) => {
  exec(args.cmd);
  return { ok: true };
});
