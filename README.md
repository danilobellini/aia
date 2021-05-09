# AIA Chasing in Python

This library was built as a workaround to the CPython
[issue 18617](https://bugs.python.org/issue18617)
(AIA chasing for missing intermediate certificates on TLS connections)
regarding SSL/TLS.

**Why a session?**
That's not really a session in the HTTP sense,
it's just a way to cache the downloaded certificates in memory,
so one doesn't need to validate the same certificate more than once.

**How does it get the certificate chain?**
It gets the whole chain
from the AIA (Authority Information Access) extension
of each certificate,
and gets the root certificate locally, from the system.

**How does it validate the certificate chain?**
Through OpenSSL, which must be installed as an external dependency.

**When should I use it?**
Ideally, never, but that might not be an option.
When the web server configuration
doesn't include the entire chain (apart from the root certificate),
there are only two "options":
ignore the certificate (not secure)
or get the intermediary certificates in the chain through AIA
(that's why this small library was written).


## How to install

Anywhere, assuming OpenSSL is already installed:

```bash
pip install aia
```

For system installation in Arch Linux, there's also the
[python-aia](https://aur.archlinux.org/packages/python-aia/)
package in AUR.


## How to use it?

For simple requests on HTTPS, there's a straightforward way based
on the standard library `urllib.request.urlopen`.

```python
from aia import AIASession
aia_session = AIASession()

# A GET result (only if status was 200), as bytes
content = aia_session.download("https://...")

# Return a `http.client.HTTPResponse` object, like `urllib.request.urlopen`
response = aia_session.urlopen("https://...")

# Indirectly, the same above
from urllib.request import urlopen
url = "https://..."
context = aia_session.ssl_context_from_url(url)
response = urlopen(url, context=context)
```

The context methods also helps when working with HTTP client libraries.
For example, with [`requests`](http://python-requests.org/):

```python
from tempfile import NamedTemporaryFile
from aia import AIASession
import requests

aia_session = AIASession()
url = "https://..."
cadata = aia_session.cadata_from_url(url)  # Validated PEM certificate chain
with NamedTemporaryFile("w") as pem_file:
    pem_file.write(cadata)
    pem_file.flush()
    resp = requests.get(url, verify=pem_file.name)
```

With [`httpx`](https://www.python-httpx.org/) in synchronous code
it's really straightforward, since it accepts the `SSLContext` instance:

```python
from aia import AIASession
import httpx

aia_session = AIASession()
url = "https://..."
context = aia_session.ssl_context_from_url(url)
resp = httpx.get(url, verify=context)
```

The certificate fetching part of this library and the OpenSSL call
are blocking, so this library is still not prepared
for asynchronous code.
But one can easily make some workaround to use it, for example with
[`tornado.httpclient`](https://www.tornadoweb.org/en/stable/httpclient.html)
or with the already seen `httpx`, using `asyncio`:

```python
import asyncio
from functools import partial
from aia import AIASession

async def get_context(aia_session, url, executor=None):
    return await asyncio.get_event_loop().run_in_executor(
        executor,
        partial(aia_session.ssl_context_from_url, url),
    )


# Tornado version
from tornado.httpclient import AsyncHTTPClient

async def download_tornado_async(url):
    aia_session = AIASession()
    context = await get_context(aia_session, url)
    client = AsyncHTTPClient()
    try:
        resp = await client.fetch(url, ssl_options=context)
        return resp.body
    finally:
        client.close()

result = asyncio.run(download_tornado_async("https://..."))


# httpx version
import httpx

async def download_httpx_async(url):
    aia_session = AIASession()
    context = await get_context(aia_session, url)
    async with httpx.AsyncClient(verify=context) as client:
        resp = await client.get(url)
        return resp.content

result = asyncio.run(download_httpx_async("https://..."))
```
