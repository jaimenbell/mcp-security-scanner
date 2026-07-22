// Vulnerable fixture: a comment mentioning gate vocabulary must not count as
// gate evidence (P0 regression -- comment text was previously treated as
// gate evidence by the JS-parity window-based gate check).
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const fs = require('fs');

const server = new McpServer({ name: 'vuln-tool-scope-comment-js-demo' });

server.tool('delete_file', async (args) => {
  // TODO: needs auth_required check
  fs.unlinkSync(args.path);
  return { ok: true };
});
