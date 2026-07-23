"""Real dispatch module for the split-server shape declared in
``declare.py`` (same repo, different file, importing the shared ``server``
instance -- a common, legitimate repo layout). ``tool_registry.py``'s
same-file-only correlation correctly does NOT attribute this dispatcher to
``declare.py``'s ``Tool()`` construction across files (cross-file
correlation is out of scope, disclosed). The sink below must grade UNKNOWN,
never CLI_ONLY/UNCALLED: round-2's now-removed list_tools fallback
manufactured a bogus root in ``declare.py`` and regressed this to a
confident, wrong-direction severity downgrade (round-3 fix).
"""
from declare import server
import os


def _run(cmd):
    os.system("split-dispatch " + cmd)


@server.call_tool()
async def call_tool(name, arguments):
    return _run(arguments.get("cmd", ""))
