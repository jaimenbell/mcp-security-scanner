"""Fixture: the FULL module-qualified HTTP sink surface, one call per method.

Every call below is the same `ssrf` finding class -- a caller-influenced URL
fetched with no host restriction. They exist to pin RECALL: the detector's
sink list was hand-enumerated and named only `httpx.get`/`httpx.post`, so
`httpx.put(...)` and `httpx.delete(...)` were structurally undetectable and
therefore could never be calibrated either.

(Deliberately avoids the words this detector treats as evidence of URL
validation -- naming one in prose is enough to silence the whole file, since
that check is a raw-text substring test.)
"""

import httpx
import requests


def httpx_read(url):
    a = httpx.get(url)
    b = httpx.head(url)
    c = httpx.options(url)
    return a, b, c


def httpx_write(url, body):
    d = httpx.post(url, json=body)
    e = httpx.put(url, json=body)
    f = httpx.patch(url, json=body)
    g = httpx.delete(url)
    return d, e, f, g


def requests_rest(url, body):
    # The two verbs `requests` was also missing.
    h = requests.patch(url, data=body)
    i = requests.options(url)
    return h, i


def method_first_forms(url):
    # `request`/`stream` take the method FIRST and the URL SECOND. A sink
    # matcher that only ever inspects arg[0] sees the literal method string,
    # concludes "constant, not caller-influenced", and reports nothing --
    # even though the URL right beside it is fully caller-controlled.
    j = httpx.request("GET", url)
    k = requests.request("POST", url)
    with httpx.stream("GET", url) as m:
        pass
    return j, k, m


def constant_urls_stay_quiet():
    # Control: a constant URL is not caller-influenced, so no verb -- however
    # newly covered -- may produce a finding here.
    httpx.put("http://127.0.0.1:1/static", json={})
    httpx.delete("http://127.0.0.1:1/static")
    httpx.request("GET", "http://127.0.0.1:1/static")
    return None
