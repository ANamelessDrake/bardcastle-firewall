"""Tiny HTTP-to-HTTPS redirect for the dashboard.

Runs on port 80 and 301-redirects every request to HTTPS, so browsing to
http://<host> lands on the TLS site. The dashboard itself runs on 443.
"""

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

# HTTPSRedirectMiddleware turns any http request into a redirect to https on
# the same host, before routing, so no routes are needed.
app = Starlette(middleware=[Middleware(HTTPSRedirectMiddleware)])
