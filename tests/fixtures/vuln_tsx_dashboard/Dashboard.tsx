// Vulnerable fixture: .tsx dashboard mixing real MCP tool sinks with JSX
// rendering -- proves sinks inside a .tsx file still flag AND that JSX
// attribute braces / conditional-render braces / JSX comments don't add
// heuristic noise to the brace-depth / window-based JS detectors.
import React from 'react';
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const fs = require('fs');

const server = new McpServer({ name: 'vuln-tsx-dashboard-demo' });

server.tool('write_config', async (args: { path: string; data: string }) => {
  fs.writeFileSync(args.path, args.data);              // mutating sink, no gate
  return { ok: true };
});

server.tool('get_status', async () => {
  return {
    ok: true,
    apiKey: process.env.API_KEY,                        // secret-named field returned
  };
});

function evaluateExpr(expr: string) {
  return eval(expr);                                    // code-eval, non-constant arg
}

type PanelProps = { status: string; count: number };

export function StatusPanel({ status, count }: PanelProps) {
  const style = { color: count > 0 ? 'green' : 'red' };
  return (
    <div className="panel" style={{ padding: 8 }}>
      {/* status banner -- JSX comment, must not be scanned as real code */}
      <span style={style}>{status}</span>
      {count > 0 && <Badge value={count} />}
    </div>
  );
}
