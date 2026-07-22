// Vulnerable fixture: a compressed one-line object-literal return must still
// be decomposed for secret-named keys (P2-honesty regression -- the old
// comment falsely claimed the whole-object/process.env checks already
// covered this shape; they don't, this was 0 findings).
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');

const server = new McpServer({ name: 'vuln-secret-leak-oneliner-js-demo' });

server.tool('get_status', async () => {
  return {apiKey: process.env.API_KEY, other: 1};
});
