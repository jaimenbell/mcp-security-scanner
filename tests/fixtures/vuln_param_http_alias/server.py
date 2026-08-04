"""Fixture: the SAME HTTP sinks, reached under an import ALIAS.

Every sink below is one this detector already matched before alias resolution
existed -- the only thing that changed is the local name the import bound it
to. `import httpx as hx; hx.post(url)` is `httpx.post(url)` with one keyword
added, and a matcher that reads the literal source text saw none of it.

Both resolution paths are exercised, because they are separate mechanisms:

  * SINK-NAME canonicalization  -- `hx.get` / `hx_post` / a bare `get` /
    `ur.urlopen` resolve back to a name in the module-qualified surface.
  * CONSTRUCTOR canonicalization -- `hx.Client()` / `AsyncClient()` /
    `Session()` resolve back to a known client constructor, so the receiver
    they bind is proven and its instance calls become sinks. This one is not
    optional: it is the shape actually found in the wild (the reference
    "fetch" MCP server imports `AsyncClient` by symbol).

Each flagged call is stored into a UNIQUELY named result variable, and the
test module matches on that name rather than on the call text -- `hx_get(` is
a substring of nothing, but `get(` is a substring of `hx_get(`, and a
substring assertion that can match two call sites passes or fails for the
wrong reason.

The unaliased controls at the top exist so severity is asserted as PARITY
against the literal spelling in the same file, not against a hardcoded
constant. Resolving a rename must not change what a finding says.

(Deliberately avoids the words this detector treats as evidence of URL
validation -- naming one in prose is enough to silence the whole file, since
that check is a raw-text substring test.)
"""

import httpx
import httpx as hx
import urllib.request as ur
from httpx import get
from httpx import post as hx_post
from httpx import AsyncClient
from requests import Session


# --- controls: the literal, unaliased spelling ----------------------------

def unaliased_controls(url, body):
    c_read = httpx.get(url)
    c_write = httpx.put(url, json=body)
    return c_read, c_write


# --- form 1: module alias -------------------------------------------------

def module_alias(url, body):
    r_mod_read = hx.get(url)
    r_mod_write = hx.put(url, json=body)
    return r_mod_read, r_mod_write


# --- form 2: symbol alias, renamed ----------------------------------------

def symbol_alias_renamed(url, body):
    r_sym_write = hx_post(url, json=body)
    return r_sym_write


# --- form 3: symbol alias, bare (local name == canonical name) ------------

def symbol_alias_bare(url):
    # Still needs the map: the surface is keyed by DOTTED name, so an
    # unqualified `get` matches nothing without resolving the import.
    r_bare_read = get(url)
    return r_bare_read


# --- form 4: module-chain alias (two-level dotted submodule) --------------

def module_chain_alias(url):
    # `urllib.request` is not a single-token module name. Splitting the
    # import on '.' and keeping the head would resolve this to `urllib`,
    # which is not the sink and not on the module list.
    r_chain_read = ur.urlopen(url)
    return r_chain_read


# --- form 5: client CONSTRUCTOR reached through a module alias ------------

def constructor_module_alias(url, body):
    mclient = hx.Client()
    r_ctor_mod = mclient.post(url, json=body)
    return r_ctor_mod


# --- form 6: client CONSTRUCTOR reached through a symbol alias ------------

def constructor_symbol_alias(url):
    aclient = AsyncClient()
    r_ctor_sym = aclient.get(url)
    return r_ctor_sym


def constructor_symbol_alias_session(url, body):
    rsess = Session()
    r_ctor_sess = rsess.patch(url, data=body)
    return r_ctor_sess


# --- controls that must stay silent ---------------------------------------

def a_constant_url_under_an_alias():
    # The constant-string gate is untouched by alias resolution: resolving a
    # name says nothing about whether its URL is caller-influenced.
    hx.get("http://127.0.0.1:1/static")
    hx_post("http://127.0.0.1:1/static", json={})
    return None


def an_alias_of_something_that_is_not_a_sink(url):
    # `httpx.Headers` is on the module list but is not in the sink surface.
    # Alias resolution recovers renames of names ALREADY in that surface; it
    # never adds one.
    return hx.Headers({"x": url})


def a_module_not_on_the_list(url):
    # `flask` is not an HTTP-client module this rule resolves. Its alias
    # resolves to nothing and flags nothing -- the module list is the gate.
    import flask as fl
    return fl.get(url)
