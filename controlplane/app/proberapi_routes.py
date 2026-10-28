"""The prober API's routes, served by the ingest under /api/v1/prober/.

`app/proberapi.py` owns what the API decides and why. This is only the HTTP:
who is asking, how big the body is, and which class of refusal to answer.

    POST   /api/v1/prober/batches              queue a batch        API key
    GET    /api/v1/prober/batches/{id}         its state or answer  API key
    GET    /api/v1/prober/vantages             names and addresses  API key
    GET    /api/v1/prober/proofs               this instance's      API key
    POST   /api/v1/prober/proofs/challenges    a DNS or HTTP proof  API key
    POST   /api/v1/prober/proofs/challenges/{id}/verify             API key
    DELETE /api/v1/prober/proofs/{address}     stop probing it      API key
    POST   /api/v1/prober/presence             an agent's presence  proof key

Caddy already sends /api/v1/* to the ingest with an 8 MB body cap
(`ops/caddyfile.reference`), so nothing on the box changes for these to be
reachable. They answer nothing until an instance exists.

## Every answer is JSON with no sentence in it

A refusal is `{"error": "<class>"}` and its status, from the closed set in
`proberapi.ERRORS`, and nothing else. The detail goes to this process's
journal. The one route that answers no JSON at all is presence, which is 204
whatever happened, because the agent reads nothing it is sent (SI-2) and
because whether an address was proved is not something a proof key may ask.

## The observed address is passed in, not imported

Presence needs the address the request arrived from, read under the one
trust rule `ingest.observed_source_address` implements. `build_router`
takes that function as an argument rather than importing the ingest, which
imports this file, so there is no import cycle, and the tests can hand in the
real function or a fixed answer.
"""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import authz, db, instances, proberapi, vantages

log = logging.getLogger(__name__)

PREFIX = proberapi.PATH_PREFIX

# The two published proof methods, spelled the way the dashboard's own routes
# spell them (`ingest.ADDRESS_METHODS`).
PROOF_METHODS = {"dns-txt": authz.METHOD_DNS_TXT,
                 "http-token": authz.METHOD_HTTP_TOKEN}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def refusal(refused: proberapi.Refused) -> JSONResponse:
    response = JSONResponse({"error": refused.error}, status_code=refused.status)
    if refused.retry_after is not None:
        response.headers["Retry-After"] = str(refused.retry_after)
    response.headers["Cache-Control"] = "no-store"
    return response


def answer(body: dict, status: int = 200) -> JSONResponse:
    response = JSONResponse(body, status_code=status)
    response.headers["Cache-Control"] = "no-store"
    return response


def _open():
    """One connection per request, every table these routes read made sure
    of, the same additive init the ingest does per request."""
    con = db.connect()
    db.init(con)
    authz.init(con)
    vantages.init(con)
    instances.init(con)
    proberapi.init(con)
    return con


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ")


def _instance(con, request: Request, kind: str) -> instances.Instance:
    """The live instance behind this request's key of this kind, or the one
    refusal for every way that is not true.

    An accepted API key is stamped with the time, at most once a minute and
    decided from the row this lookup already read, on a connection of its
    own that waits a twentieth of a second and is dropped when the database
    is busy (`instances.stamp_api_key_use`). So the stamp is no part of this
    route's transaction, a read route takes no write lock for it, and a burst
    costs the lock once. Never on a refusal, never for a proof key.
    """
    key = _bearer(request)
    found, used = instances.instance_and_key_use(con, key, kind)
    if found is None:
        raise proberapi.Refused("unknown_key")
    if kind == instances.KIND_API and instances.stamp_due(used):
        instances.stamp_api_key_use(db.db_path(), key)
    return found


async def _json_body(request: Request, limit: int = proberapi.MAX_BODY_BYTES):
    """The body as JSON, refusing one that is too large before reading it
    when it says so, and after reading it when it does not. `limit` is the
    batch's unless a route has a smaller one of its own
    (`app/feedback_routes.py`)."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise proberapi.Refused("too_large")
    body = await request.body()
    if len(body) > limit:
        raise proberapi.Refused("too_large")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise proberapi.Refused("malformed_request") from None


# ------------------------------------------------------------------ batches

def _submit(request: Request, payload) -> JSONResponse:
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_API)
        registry = vantages.list_all(con)
        parsed = proberapi.parse_batch(
            payload, {v.name for v in registry if v.enabled},
            vantages.all_addresses(con))
        batch_id = proberapi.submit(con, instance.id, parsed, _now())
    finally:
        con.close()
    return answer({"id": batch_id, "state": proberapi.STATE_QUEUED}, 202)


def _fetch(request: Request, batch_id: str) -> JSONResponse:
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_API)
        state = proberapi.fetch(con, instance.id, batch_id, _now())
    finally:
        con.close()
    waiting = state["state"] in (proberapi.STATE_QUEUED, proberapi.STATE_RUNNING)
    return answer(state, 202 if waiting else 200)


def _vantages(request: Request) -> JSONResponse:
    """Every vantage's name and addresses, switched off or not, because an
    instance must keep all of them out of its targets. Never the ssh
    destination: that is ours and says where our key goes."""
    con = _open()
    try:
        _instance(con, request, instances.KIND_API)
        listed = [{"name": v.name, "enabled": v.enabled,
                   "addresses": list(v.addresses)}
                  for v in vantages.list_all(con)]
    finally:
        con.close()
    return answer({"vantages": listed})


# ------------------------------------------------------------------- proofs

def _proof_view(row) -> dict:
    """The end the gate reads, not the column: a proof by presence written
    under the week ends an hour after its last renewal (`authz.live_until`).
    Only live rows reach here, so it is never None."""
    return {"address": row["target"], "family": row["family"],
            "method": row["method"], "verified_at": row["verified_at"],
            "expires_at": authz.live_until(row).isoformat()}


def _proofs(request: Request) -> JSONResponse:
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_API)
        rows = authz.live_for_account(con, instance.account, _now())
    finally:
        con.close()
    return answer({"proofs": [_proof_view(row) for row in rows]})


def _start_challenge(request: Request, payload) -> JSONResponse:
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_API)
        if not isinstance(payload, dict):
            raise proberapi.Refused("malformed_request")
        address = payload.get("address")
        method = PROOF_METHODS.get(payload.get("method"))
        if not isinstance(address, str) or method is None:
            raise proberapi.Refused("malformed_request")
        # The token a token file already holds, named for another address of
        # the same server. Given again only when it is one of this instance's
        # own live token file proofs, and a new one is made otherwise
        # (`authz._account_token`, docs/PRODUCT.md 5, the clause of 2026-10-03).
        named = payload.get("token")
        if named is not None and (
                method != authz.METHOD_HTTP_TOKEN or not isinstance(named, str)
                or not authz.TOKEN_SHAPE.fullmatch(named)):
            raise proberapi.Refused("malformed_request")
        try:
            challenge = authz.start_proof(con, address, method,
                                          account=instance.account, now=_now(),
                                          same_token_as=named)
        except authz.TargetError:
            raise proberapi.Refused("target_refused") from None
    finally:
        con.close()
    return answer({"id": challenge.id, "address": challenge.target,
                   "method": payload["method"], "token": challenge.token,
                   "publish_at": challenge.publish_at,
                   "expires_at": challenge.expires_at}, 201)


def _verify_challenge(request: Request, challenge_id: int) -> JSONResponse:
    """Reads the evidence, so it can take a DNS or HTTP timeout. A plain
    function for that reason: FastAPI runs it in a thread, and the event loop
    keeps answering everyone else meanwhile."""
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_API)
        if authz.challenge_for_account(con, challenge_id, instance.account) is None:
            raise proberapi.Refused("unknown_challenge")
        result = authz.verify_proof(con, challenge_id, now=_now())
    finally:
        con.close()
    # SI-8: the class and nothing else. The registry's sentence names the
    # address and where its token was read, and every instance's Verify
    # passes this route since 2026-10-24 (the challenge of that day).
    if not result.recorded:
        log.info("instance %s, challenge %s not proved: %s", instance.name,
                 challenge_id, result.code)
    return answer({"proved": result.recorded, "result": result.code})


def _revoke(request: Request, address: str) -> JSONResponse:
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_API)
        try:
            closed = authz.revoke(con, address, now=_now(),
                                  account=instance.account)
        except authz.TargetError:
            raise proberapi.Refused("target_refused") from None
    finally:
        con.close()
    return answer({"revoked": closed})


# ----------------------------------------------------------------- presence

def _presence(request: Request, payload, observed: str | None) -> Response:
    con = _open()
    try:
        instance = _instance(con, request, instances.KIND_PROOF)
        if not isinstance(payload, dict):
            raise proberapi.Refused("malformed_request")
        claimed = payload.get("interface_addresses")
        if observed is None:
            # observed_source_address has already said why in the journal.
            return Response(status_code=204)
        if not instance.proves_by_presence:
            # An instance that signed up proves by DNS TXT or a token file
            # only (docs/PRODUCT.md 5, 2026-10-20). The same empty answer as
            # every other presence, and its class in the journal.
            log.info("presence proved nothing: %s", "not_invited")
            return Response(status_code=204)
        result = authz.record_presence_claim(con, instance.account, observed,
                                             claimed, now=_now(),
                                             origin=instance.origin)
    finally:
        con.close()
    # SI-8: an instance's server would otherwise put its address in this
    # journal every quarter hour. A presence that proved writes nothing, and
    # one that proved nothing writes its class and nothing else, decided
    # 2026-10-20.
    if not result.recorded:
        log.info("presence proved nothing: %s", result.code)
    return Response(status_code=204)


# ------------------------------------------------------------------- router

def build_router(observed_source_address) -> APIRouter:
    """The routes, with the function that reads a request's observed address
    handed in. The ingest passes its own."""
    router = APIRouter()

    @router.post(f"{PREFIX}/batches")
    async def submit_batch(request: Request) -> Response:
        try:
            payload = await _json_body(request)
            return await run_in_threadpool(_submit, request, payload)
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.get(PREFIX + "/batches/{batch_id}")
    def fetch_batch(batch_id: str, request: Request) -> Response:
        try:
            return _fetch(request, batch_id)
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.get(f"{PREFIX}/vantages")
    def list_vantages(request: Request) -> Response:
        try:
            return _vantages(request)
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.get(f"{PREFIX}/proofs")
    def list_proofs(request: Request) -> Response:
        try:
            return _proofs(request)
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.post(f"{PREFIX}/proofs/challenges")
    async def start_challenge(request: Request) -> Response:
        try:
            payload = await _json_body(request)
            return await run_in_threadpool(_start_challenge, request, payload)
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.post(PREFIX + "/proofs/challenges/{challenge_id}/verify")
    def verify_challenge(challenge_id: str, request: Request) -> Response:
        try:
            if not challenge_id.isascii() or not challenge_id.isdigit() \
                    or len(challenge_id) > 18:
                raise proberapi.Refused("unknown_challenge")
            return _verify_challenge(request, int(challenge_id))
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.delete(PREFIX + "/proofs/{address}")
    def revoke_proof(address: str, request: Request) -> Response:
        try:
            return _revoke(request, address)
        except proberapi.Refused as refused:
            return refusal(refused)

    @router.post(f"{PREFIX}/presence")
    async def presence(request: Request) -> Response:
        try:
            # Read before anything else, because it is a property of the
            # connection, the same order the ingest's own presence takes.
            observed = observed_source_address(request)
            payload = await _json_body(request)
            return await run_in_threadpool(_presence, request, payload, observed)
        except proberapi.Refused as refused:
            return refusal(refused)

    return router
