// Clean fixture: same tool/eval shapes done safely, plus the same realistic
// JSX rendering -- proves the JSX itself never trips a finding on its own.
import React from 'react';
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const fs = require('fs');
const path = require('path');

const server = new McpServer({ name: 'clean-tsx-dashboard-demo' });
const BASE_DIR = path.resolve('/srv/data');             // containment hint

server.tool('write_config', async (args: { path: string; data: string }) => {
  // requires_permission: admin-only write gate
  if (!process.env.ENABLE_DESTRUCTIVE_TOOLS) {
    throw new Error('destructive tools disabled');
  }
  const target = path.resolve(BASE_DIR, args.path);
  fs.writeFileSync(target, args.data);
  return { ok: true };
});

server.tool('get_status', async () => {
  return {
    ok: true,
    version: '1.2.3',
  };
});

function evaluateExpr() {
  return eval('1 + 1');                                 // constant arg
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
