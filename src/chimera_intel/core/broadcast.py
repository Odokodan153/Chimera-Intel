import asyncio
from typing import Dict, Any

class Broadcaster:
    """
    A simple in-memory broadcaster for sending messages to clients.
    """
    def __init__(self):
        self._subscribers = set()

    async def __call__(self, channel: str, message: Dict[str, Any]):
        """
        Broadcasts a message to all subscribers.
        """
        for queue in self._subscribers:
            await queue.put({"channel": channel, "message": message})

    def subscribe(self):
        """
        Subscribes a client to receive messages.
        """
        queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        """
        Unsubscribes a client.
        """
        self._subscribers.remove(queue)

# Create a global instance of the broadcaster
broadcast = Broadcaster()