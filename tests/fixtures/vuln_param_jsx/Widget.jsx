// Vulnerable fixture: .jsx param-injection sinks + JSX rendering, proving
// .jsx collection parity and that JSX attribute braces don't add noise.
import React from 'react';
const { exec } = require('child_process');

function runCmd(userArg) {
  exec(`ls ${userArg}`);                               // shell injection
}

export function Widget({ label, onClick }) {
  return (
    <button style={{ padding: 4 }} onClick={onClick}>
      {/* label text -- JSX comment */}
      {label}
    </button>
  );
}
