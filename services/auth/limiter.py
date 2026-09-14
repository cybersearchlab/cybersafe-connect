"""
services/auth/limiter.py
================================================================================
Rate limiting — Authentication Microservice (CyberSafe Connect)
================================================================================

Single Limiter instance (slowapi), shared between app.py (which registers it
on the FastAPI application) and routes.py (which applies it per-route via the
@limiter.limit(...) decorator).

--------------------------------------------------------------------------------
WHY A SEPARATE FILE, DISTINCT FROM app.py AND routes.py
--------------------------------------------------------------------------------
routes.py needs to import `limiter` to decorate its endpoints, and app.py
needs to import `routes` to register them. If `limiter` were defined in
app.py, routes.py would have to import app.py — which already imports
routes.py: a circular import. A separate module, with no dependency on
either, avoids the problem.

--------------------------------------------------------------------------------
CONTEXT — WHY THIS MODULE EXISTS
--------------------------------------------------------------------------------
The project README claimed rate limiting (slowapi) for the auth module, but
no slowapi dependency or middleware of that kind was actually found in its
code (see CyberSafe_Connect_Rapport_Comprehension.docx, §3.6). This module
implements the rate limiting required by the auth service specification,
with values aligned with the scam-checker module.
================================================================================
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# key_func=get_remote_address: the limit is applied per IP address. This is
# the standard approach for unauthenticated endpoints (/register, /login,
# /verify-email). For authenticated endpoints (/refresh), a custom key_func
# could be used to limit per user ID instead.
limiter = Limiter(key_func=get_remote_address)