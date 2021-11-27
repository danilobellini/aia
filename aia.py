from contextlib import ExitStack
from functools import lru_cache, partial
import logging
import re
import socket
import ssl
import subprocess
from tempfile import NamedTemporaryFile
from urllib.request import urlopen, Request
from urllib.parse import urlsplit


__version__ = "0.2.0"

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = f"Python-aia/{__version__}"


class DownloadError(Exception):
    pass


class AIAError(Exception):
    pass


class AIASchemeError(AIAError):
    pass


class AIADownloadError(AIAError, DownloadError):
    pass


class InvalidCAError(AIAError):
    pass


class CachedMethod:
    """
    A ``functools.lru_cache`` cache decorator for methods,
    but applied on each bound method (i.e., in the instance)
    in order to avoid memory leak issues relating to
    caching an unbound method directly from the owner class.
    """

    def __init__(self, maxsize=128, typed=False):
        if callable(maxsize):
            self.func = maxsize
            self.maxsize = None
        else:
            self.maxsize = maxsize
        self.typed = typed

    def __call__(self, func):
        self.func = func
        return self

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        bound_method = partial(self.func, instance)
        result = lru_cache(self.maxsize, self.typed)(bound_method)
        setattr(instance, self.name, result)
        return result


def openssl_get_cert_info(cert_der):
    """
    Get issuer, subject and AIA CA issuers (``aia_ca_issuers``)
    from a DER certificate, using OpenSSL.
    """
    command_line = [
        "openssl", "x509", "-inform", "DER", "-noout",
        "-issuer", "-subject", "-ext", "authorityInfoAccess",
        "-nameopt", "utf8,sep_comma_plus",
    ]
    proc = subprocess.run(command_line, input=cert_der, capture_output=True)
    output_pairs = re.findall(
        r"^(issuer=|subject=|\s+CA\s*Issuers.*URI:)(.*)$",
        proc.stdout.decode("utf-8"),
        re.MULTILINE | re.IGNORECASE,
    )
    result = {"aia_ca_issuers": []}
    for k, v in output_pairs:
        if k.startswith(" "):
            result["aia_ca_issuers"].append(v.strip())
        else:
            result[k.lower()[:-1]] = v.strip()
    return result


class AIASession:

    def __init__(self, user_agent=DEFAULT_USER_AGENT):
        self.user_agent = user_agent
        self._context = ssl.SSLContext()  # TLS (don't check broken chain)
        self._context.load_default_certs()

        # Trusted certificates whitelist in dict format like:
        # {"RFC4514 string": b"DER certificate contents"}
        self._trusted = {
            openssl_get_cert_info(ca_der)["subject"]: ca_der
            for ca_der in self._context.get_ca_certs(True)
        }

    @CachedMethod
    def get_host_cert(self, host):
        """
        Get the DER (binary) certificate for the taget host
        without checking it (leaf certificate).
        """
        logger.debug(f"Downloading {host} certificate (TLS)")
        with socket.create_connection((host, 443)) as sock:
            with self._context.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(True)

    @CachedMethod
    def _get_ca_issuer_cert(self, url):
        """
        Get an intermediary DER (binary) certificate in the chain
        from a given URL which should had been found
        as the CA Issuer URI in the AIA extension
        of the previous "node" (certificate) of the chain.
        """
        if urlsplit(url).scheme != "http":
            raise AIASchemeError("Invalid CA issuer certificate URI protocol")
        logger.debug(f"Downloading CA issuer certificate at {url}")
        req = Request(url=url, headers={"User-Agent": self.user_agent})
        with urlopen(req) as resp:
            if resp.status != 200:
                raise AIADownloadError(f"HTTP {resp.status} (CA Issuer Cert.)")
            return resp.read()

    def aia_chase(self, host):
        """
        Generator of the certificate chain from a host,
        up to (and including) the root certificate.

        The result is a list a DER bytestring certificate,
        whose first item is the host certificate and the next entries
        are the intermediary certificates.
        """
        der_cert = self.get_host_cert(host)

        # Traverse the AIA path until it gets a self-signed certificate
        # or a certificate without a "parent" issuer URI reference
        while True:
            cert_dict = openssl_get_cert_info(der_cert)
            cert_issuer = cert_dict["issuer"]
            if cert_dict["subject"] == cert_issuer:  # Self-signed (root) cert
                if cert_issuer not in self._trusted:
                    raise InvalidCAError("Root in AIA but not in trusted list")
                logger.debug(f"Found a self-signed (root) certificate for "
                             f"{host} in AIA, and it's also in trusted list!")
                yield self._trusted[cert_issuer]
                return
            yield der_cert
            if not cert_dict["aia_ca_issuers"]:
                if cert_issuer not in self._trusted:
                    raise InvalidCAError("Root not in trusted database")
                logger.debug(f"Found the {host} certificate root!")
                yield self._trusted[cert_issuer]
                return
            logger.debug(f"Found another {host} certificate chain entry (AIA)")
            der_cert = self._get_ca_issuer_cert(cert_dict["aia_ca_issuers"][0])

    def validate_certificate_chain(self, der_certs):
        """
        Validate a given certificate chain which should be full,
        as a list of DER (binary) certificates from leaf to root
        (in this order and including both),
        raising an ``ssl.SSLError`` when the chain isn't valid.

        This method requires OpenSSL,
        which should be available from the command line.
        """
        with ExitStack() as stack:
            def new_pem_file(data):
                pf = stack.enter_context(
                    NamedTemporaryFile("wb", suffix=".pem"),
                )
                pf.write(data.encode("ascii"))
                pf.flush()
                return pf

            pem_certs = [ssl.DER_cert_to_PEM_cert(dc) for dc in der_certs]
            target_pem = new_pem_file(pem_certs[0])
            intermediary_pem = new_pem_file("".join(pem_certs[1:-1]))
            root_pem = new_pem_file(pem_certs[-1])

            command_line = [
                "openssl", "verify",
                "-CAfile", root_pem.name,
                "-untrusted", intermediary_pem.name,
                target_pem.name,
            ]
            openssl_proc = subprocess.run(command_line, capture_output=True)

            # Logs the OpenSSL results
            logger.debug("OpenSSL certificate chain validation results:")
            for stream_name in ["stdout", "stderr"]:
                msg = getattr(openssl_proc, stream_name)
                if msg.strip():
                    for line in msg.decode("ascii").splitlines():
                        logger.debug(f"[{stream_name}] {line}")
            logger.debug(f"[return code] {openssl_proc.returncode}")

            if openssl_proc.returncode != 0:
                raise ssl.SSLError("Certificate chain verification failed")

    @CachedMethod
    def cadata_from_host(self, host):
        """
        Get the certification chain, apart from the leaf node,
        as joined PEM (ASCII string in base64 with extra delimiters)
        certificates in a single string, to be used in a SSLContext.
        """
        der_certs = list(self.aia_chase(host))
        logger.info(f"Checking the {host} certificate chain...")
        self.validate_certificate_chain(der_certs)
        logger.info(f"The {host} certificate chain is valid!")
        return "".join(ssl.DER_cert_to_PEM_cert(dc) for dc in der_certs[1:])

    def cadata_from_url(self, url):
        """Façade to the ``cadata_from_host`` method."""
        split_result = urlsplit(url)
        return self.cadata_from_host(split_result.netloc)

    def ssl_context_from_host(self, host, purpose=ssl.Purpose.SERVER_AUTH):
        """
        SSLContext instance for a single host name
        that gets (and validates) its certificate chain from AIA.
        """
        return ssl.create_default_context(
            purpose=purpose,
            cadata=self.cadata_from_host(host),
        )

    def ssl_context_from_url(self, url, purpose=ssl.Purpose.SERVER_AUTH):
        """
        Same to the ``ssl_context_from_host`` method,
        but with the host name obtained from the given URL.
        """
        return ssl.create_default_context(
            purpose=purpose,
            cadata=self.cadata_from_url(url),
        )

    def urlopen(self, url, data=None, timeout=None):
        """Same to ``urllib.request.urlopen``, but handles AIA."""
        url_string = url.full_url if isinstance(url, Request) else url
        context = self.ssl_context_from_url(url_string)
        kwargs = {"data": data, "timeout": timeout, "context": context}
        cleaned_kwargs = {k: v for k, v in kwargs.items() if v is not None}
        return urlopen(url, **cleaned_kwargs)

    def download(self, url):
        """A simple façade to get a raw bytes download."""
        resp = self.urlopen(Request(
            url=url,
            headers={"User-Agent": self.user_agent},
        ))
        if resp.status != 200:
            raise DownloadError(f"HTTP {resp.status}")
        return resp.read()
