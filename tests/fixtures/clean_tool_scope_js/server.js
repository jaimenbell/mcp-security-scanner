// Clean fixture: a gated mutating tool + a read-only tool.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const fs = require('fs');

const server = new McpServer({ name: 'clean-tool-scope-js-demo' });

server.tool('delete_file', async (args) => {
  // requires_permission: admin-only write gate
  if (!process.env.ENABLE_DESTRUCTIVE_TOOLS) {
    throw new Error('destructive tools disabled');
  }
  fs.unlinkSync(args.path);
  return { ok: true };
});

server.tool('get_status', async () => {
  return { ok: true };
});
