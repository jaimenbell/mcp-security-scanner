"""Fixture: HTTP sinks reached through a CLIENT INSTANCE, not a module.

`httpx.Client()` / `httpx.AsyncClient()` / `requests.Session()` /
`aiohttp.ClientSession()` are the dominant real-world shape -- on this repo's
own 13-repo scan corpus they outnumber module-level calls 75 to 48 -- and a
module-qualified-name matcher sees none of them.

The bottom half of this file is the precision half. Those receivers carry the
same method names on purpose: they are what a bare short-name matcher would
flag, and they must stay silent.

Receiver names are kept distinct from one another on purpose (`sess`, not
`s`, next to `cs`) so a substring assertion in the test module cannot match
two different call sites and quietly pass or fail for the wrong reason.

(Deliberately avoids the words this detector treats as evidence of URL
validation -- naming one in prose is enough to silence the whole file, since
that check is a raw-text substring test.)
"""

import aiohttp
import httpx
import requests


# --- bound receivers: real sinks -------------------------------------------

def plain_assignment_binding(url, body):
    hclient = httpx.Client()
    r1 = hclient.get(url)
    r2 = hclient.put(url, json=body)
    r3 = hclient.delete(url)
    return r1, r2, r3


def session_binding(url, body):
    sess = requests.Session()
    r4 = sess.post(url, data=body)
    r5 = sess.patch(url, data=body)
    return r4, r5


async def context_manager_binding(url):
    async with httpx.AsyncClient() as ac:
        r6 = await ac.head(url)
        r7 = await ac.options(url)
    return r6, r7


async def aiohttp_binding(url, body):
    async with aiohttp.ClientSession() as cs:
        r8 = await cs.post(url, json=body)
    return r8


class Fetcher:
    def __init__(self):
        self._http = httpx.AsyncClient()

    async def pull(self, url):
        # Attribute-bound receiver -- `self._http` is as resolvable as a
        # bare name and just as much a sink.
        return await self._http.get(url)


def method_first_on_an_instance(url):
    mclient = httpx.Client()
    # (method, url) again -- the URL is the SECOND argument here too.
    r9 = mclient.request("GET", url)
    with mclient.stream("POST", url) as streamed:
        pass
    return r9, streamed


def constant_url_on_a_bound_client():
    # Control: bound receiver, but nothing caller-influenced to redirect.
    kclient = httpx.Client()
    kclient.put("http://127.0.0.1:1/static", json={})
    return None


# --- unbound / non-HTTP receivers: must stay silent ------------------------

def a_queue_is_not_a_client(q, val):
    q.put(val)


def an_orm_session_is_not_an_http_session(db, row):
    db.delete(row)
    db.get(row)


def a_bare_parameter_is_not_evidence(fetcher, url):
    # No binding anywhere in this file says what `fetcher` is. Unknown, and
    # a guess here is exactly the 63x flood.
    fetcher.post(url)
    fetcher.delete(url)


def a_real_binding_under_a_contested_name(url):
    # `client` genuinely IS an httpx client here. It is still not flagged --
    # because of the function below. See the pair of tests on this.
    client = httpx.Client()
    return client.get(url)


def a_parameter_shadowing_a_bound_name(client, url):
    # The case that broke the first implementation. Resolution is file-wide,
    # so without treating a parameter as conflicting evidence the binding
    # above leaks onto THIS parameter and manufactures a finding on a
    # receiver nothing in the file describes. The conflict rule cancels the
    # name in both directions: this call is not flagged, and neither is the
    # real one above. That symmetry is the stated cost of a decidable
    # one-pass resolution, and it errs quiet.
    client.patch(url)


def a_non_http_constructor(key, val):
    store = _make_store()
    store.get(key)
    store.put(key, val)
    store.delete(key)


def _make_store():
    return {}


def a_rebound_name_is_ambiguous(url):
    # `conn` is an httpx client here...
    conn = httpx.Client()
    return conn.get(url)


def a_rebound_name_is_ambiguous_2(url):
    # ...and something else entirely here. Same file, same name, conflicting
    # evidence -- so neither call may be flagged.
    conn = _make_store()
    return conn.get(url)
