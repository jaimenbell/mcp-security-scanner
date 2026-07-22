// Clean fixture: no secret leaks in tool responses.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');

const server = new McpServer({ name: 'clean-secret-leak-js-demo' });

server.tool('get_status', async () => {
  return {
    ok: true,
    version: '1.2.3',
  };
});

server.tool('has_api_key', async () => {
  return {
    hasApiKey: Boolean(process.env.API_KEY),
  };
});
