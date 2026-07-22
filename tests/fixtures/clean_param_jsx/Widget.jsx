// Clean fixture: .jsx equivalent done safely.
import React from 'react';
const { execFile } = require('child_process');

function runCmd() {
  execFile('ls', ['-la']);                             // argv, no shell
}

export function Widget({ label, onClick }) {
  return (
    <button style={{ padding: 4 }} onClick={onClick}>
      {/* label text -- JSX comment */}
      {label}
    </button>
  );
}
