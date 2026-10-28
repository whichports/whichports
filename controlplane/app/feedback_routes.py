"""The Feedback window's two routes (app/feedback.py says what a message is
and what is kept, docs/record 4.425 why free text may travel here at all).

    POST /api/v1/feedback        ours. An instance asks, with its API key.
    POST /api/admin/feedback     a signed-in person's browser asks the
                                 instance it is signed in to.

**The browser never talks to our box.** It talks to its own instance, and
the instance talks to us, the way every batch to the prober API already
goes. So nothing of the person's browser, no address and no cookie, is ever
in front of us.

## Where a message goes

The setting that already says who an instance's probers are decides, and
there is no second one:

- `WHICHPORTS_PROBER_API` and its key both set: one request to our box,
  through the prober API's own client (`dispatch.send_feedback`), while the
  person waits. Nothing is stored on the instance.
- Neither set, our own box and any instance without our key: the row is
  written into this control plane's own table, under the session's
  workspace, and no request leaves.
- One without the other: nothing is sent and nothing is stored. Storing here
  would tell the person they had reached us.

## What is never done

Nothing is kept for later when our box does not answer, and nothing is sent
a second time: a thing leaves an instance on a click and at no other time.
Nothing our box says beyond a status and one of five classes reaches the
page, so nothing in an answer is acted on (SI-2). **The words are never
handed to a logger**, here or in anything these routes call.

## The refusals

Five classes of the prober API's closed set, `feedback.REFUSALS`, on both
routes, as `{"error": "<class>"}` with that class's status. The instance's
route has one answer more, for the page alone and never on our wire: 502
`{"error": "no_answer"}` when our box could not be asked or did not answer
with one of the five.

## The console's two writes

    POST /api/admin/feedback/<id>/done
    POST /api/admin/feedback/<id>/delete

His Done and his Delete (docs/record 4.425, 4.436), on the table this
control plane holds: ours on our box, the instance's own on an instance
without our key. Only an account with the admin flag, which is the one
check the console's other write, the address lookup, makes. Without the
flag the answer is the lookup's, 404, and without a session 403.
"""
import logging
import os
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from . import dispatch, feedback, instances, proberapi, proberapi_routes

log = logging.getLogger(__name__)

OUR_PATH = dispatch.FEEDBACK_PATH
WINDOW_PATH = "/api/admin/feedback"
STORED = {"stored": True}


def destination(environ) -> str:
    """The host the window's To line names: the host of the prober API when
    both settings are set, since that is where the message goes, and empty
    otherwise, when the message stays on this instance and the page names
    its own host. The one setting that says who an instance's probers are
    decides, as `_from_the_window` decides from it."""
    base_url = environ.get(dispatch.PROBER_API_ENV, "").strip()
    key = environ.get(dispatch.PROBER_API_KEY_ENV, "").strip()
    if not base_url or not key:
        return ""
    return urllib.parse.urlsplit(base_url).netloc


def _console_write(action, row_id: int) -> JSONResponse:
    """One of the console's two writes on the table here. 404 when there is
    no such open message to mark or no such message to delete, so a second
    click on the same row changes nothing."""
    con = proberapi_routes._open()
    try:
        feedback.init(con)
        did = action(con, row_id)
    finally:
        con.close()
    if not did:
        return proberapi_routes.answer({"detail": "no such message"}, 404)
    word = "deleted" if action is feedback.delete else "done"
    return proberapi_routes.answer({word: True})


def opener():
    """The opener the request to our box goes through. None is the client's
    own, which refuses a redirect. A test stands its own in here."""
    return None


def _message(payload, *, closed_list: bool) -> feedback.Message:
    try:
        return feedback.parse(payload, closed_list=closed_list)
    except feedback.NotAMessage as exc:
        raise proberapi.Refused(exc.error) from None


def no_answer() -> JSONResponse:
    response = JSONResponse({"error": dispatch.NO_ANSWER}, status_code=502)
    response.headers["Cache-Control"] = "no-store"
    return response


# ------------------------------------------------------------------ our box

def _from_an_instance(request: Request, payload) -> JSONResponse:
    con = proberapi_routes._open()
    try:
        feedback.init(con)
        # The API key and no other. The proof key is in every agent's
        # install command, and nothing an agent holds may write here.
        instance = proberapi_routes._instance(con, request, instances.KIND_API)
        message = _message(payload, closed_list=False)
        if feedback.sent_in_the_last_day(con, instance_id=instance.id) >= feedback.PER_DAY:
            raise proberapi.Refused("over_instance_pace")
        feedback.store(con, message, instance_id=instance.id)
    finally:
        con.close()
    return proberapi_routes.answer(STORED)


# --------------------------------------------------------------- an instance

def _stored_here(workspace_id: int, message: feedback.Message) -> JSONResponse:
    con = proberapi_routes._open()
    try:
        feedback.init(con)
        if feedback.sent_in_the_last_day(con, workspace_id=workspace_id) >= feedback.PER_DAY:
            raise proberapi.Refused("over_instance_pace")
        feedback.store(con, message, workspace_id=workspace_id)
    finally:
        con.close()
    return proberapi_routes.answer(STORED)


def _from_the_window(workspace_id: int, payload, environ=None) -> JSONResponse:
    environ = os.environ if environ is None else environ
    # On an instance the page and this code are one commit, so the screen is
    # one of the closed list, and what is wrong is refused before anything
    # leaves.
    message = _message(payload, closed_list=True)
    base_url = environ.get(dispatch.PROBER_API_ENV, "").strip()
    key = environ.get(dispatch.PROBER_API_KEY_ENV, "").strip()
    if not base_url and not key:
        return _stored_here(workspace_id, message)
    if not base_url or not key:
        log.warning("feedback: %s and %s go together and one is not set, so"
                    " nothing was sent", dispatch.PROBER_API_ENV,
                    dispatch.PROBER_API_KEY_ENV)
        return no_answer()
    try:
        stored, why_not = dispatch.send_feedback(
            base_url, key, message.as_body(), opener=opener())
    except dispatch.TransportConfigError:
        log.warning("feedback: %s is not an https address with nothing after"
                    " the host, so nothing was sent", dispatch.PROBER_API_ENV)
        return no_answer()
    if stored:
        return proberapi_routes.answer(STORED)
    if why_not in feedback.REFUSALS:
        raise proberapi.Refused(why_not)
    # No answer, or an answer that is none of the five. The class is all
    # that is written down, and it is ours or a word of the closed set.
    log.info("feedback: no answer from the prober API")
    return no_answer()


def build_router(require_operator, operator_workspace, require_admin) -> APIRouter:
    """The window's two routes and the console's two. The ingest hands in
    its own check for a signed-in session, its own reading of which
    workspace that session works in, and its own check for the admin flag,
    so the session decides and the request never does."""
    router = APIRouter()

    @router.post(WINDOW_PATH + "/{row_id}/done")
    async def mark_done(row_id: int, request: Request) -> Response:
        require_admin(request)
        return await run_in_threadpool(_console_write, feedback.mark_done, row_id)

    @router.post(WINDOW_PATH + "/{row_id}/delete")
    async def delete(row_id: int, request: Request) -> Response:
        require_admin(request)
        return await run_in_threadpool(_console_write, feedback.delete, row_id)

    @router.post(OUR_PATH)
    async def from_an_instance(request: Request) -> Response:
        try:
            payload = await proberapi_routes._json_body(request, feedback.MAX_BODY_BYTES)
            return await run_in_threadpool(_from_an_instance, request, payload)
        except proberapi.Refused as refused:
            return proberapi_routes.refusal(refused)

    @router.post(WINDOW_PATH)
    async def from_the_window(request: Request) -> Response:
        # Any signed-in account of the workspace: a message harms nothing,
        # and a viewer sees the screens too.
        require_operator(request)
        workspace_id = operator_workspace(request)
        try:
            payload = await proberapi_routes._json_body(request, feedback.MAX_BODY_BYTES)
            return await run_in_threadpool(_from_the_window, workspace_id, payload)
        except proberapi.Refused as refused:
            return proberapi_routes.refusal(refused)

    return router
