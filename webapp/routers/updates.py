import asyncio
import json
from fastapi import APIRouter, Request, Depends
from sse_starlette.sse import EventSourceResponse
from chimera_intel.core.broadcast import broadcast
from .auth import get_current_user
from .. import models

router = APIRouter()


@router.get("/")
async def sse_updates(
    request: Request, current_user: models.User = Depends(get_current_user)
):
    """
    Server-Sent Events endpoint to stream updates to the client.
    """
    queue = broadcast.subscribe()

    async def event_generator():
        try:
            while True:
                # Wait for a message from the broadcaster
                payload = await queue.get()
                channel = payload["channel"]
                message = payload["message"]

                # Only send updates intended for the current user
                if channel == f"user:{current_user.id}":
                    yield {"event": "update", "data": json.dumps(message)}
        except asyncio.CancelledError:
            # Handle client disconnection
            broadcast.unsubscribe(queue)
            raise

    return EventSourceResponse(event_generator())
