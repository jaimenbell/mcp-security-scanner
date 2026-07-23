// Fixture: pagination-cursor field names (JS/TS parity) must not trip the
// secret-leak-via-tool-response heuristic. A real credential field returned
// from a sibling tool must still flag.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');

const server = new McpServer({ name: 'vuln-secret-leak-pagination-js-demo' });

server.tool('list_jobs', async () => {
  return {
    jobs: [],
    nextToken: resultNextToken,
  };
});

server.tool('list_more', async () => {
  return {
    items: [],
    cursor: nextCursor,
  };
});

server.tool('get_creds', async () => {
  return {
    access_token: 'should-still-flag-as-a-real-credential',
  };
});
