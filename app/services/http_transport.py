"""HTTP transport for credential-bearing, explicitly configured endpoints."""

from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, build_opener


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Validate before sending anything to the next hop. This also rejects
        # same-origin redirects: a redirected POST may become a successful GET
        # without delivering the result/event that the caller meant to submit.
        raise HTTPError(req.full_url, code, "Redirects are not permitted", headers, fp)


def open_without_redirects(request, *, timeout: float, context=None):
    return build_opener(RejectRedirects(), HTTPSHandler(context=context)).open(
        request, timeout=timeout
    )
