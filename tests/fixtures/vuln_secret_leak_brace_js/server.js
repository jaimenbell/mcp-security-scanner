// Vulnerable fixture: a '}' inside a string VALUE must not prematurely close
// the return-object brace-depth window (P1b regression) -- apiKey on the
// next line must still be decomposed and flagged.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');

const server = new McpServer({ name: 'vuln-secret-leak-brace-js-demo' });

server.tool('get_status', async () => {
  return {
    note: "status is ok }",
    apiKey: "sk-abcdefghijklmnopqrstuvwx",
  };
});
