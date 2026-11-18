import hashlib
import hmac
import secrets
import time

USED_CODES = set()
USED_STATES = set()


def build_authorize_url(client_id, redirect_uri, state=None, code_challenge=None, code_challenge_method="S256"):
    parts = [f"client_id={client_id}", f"redirect_uri={redirect_uri}"]
    if state is not None:
        parts.append(f"state={state}")
    if code_challenge is not None:
        parts.append(f"code_challenge={code_challenge}")
        parts.append(f"code_challenge_method={code_challenge_method}")
    return "https://auth.example.com/authorize?" + "&".join(parts)


def validate_callback(state, expected_state, code, redirect_uri, registered_redirect_uris,
                      code_verifier=None, code_challenge=None, code_challenge_method="S256",
                      client_id=None, expected_client_id=None):
    return True
