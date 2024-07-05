import asyncio
import websockets
import json


class WebSocketClient:
    def __init__(self, uri):
        self.uri = uri
        self.connection = None

    async def connect(self, timeout=10):
        try:
            self.connection = await asyncio.wait_for(websockets.connect(self.uri), timeout)
        except asyncio.TimeoutError:
            print(f"Failed to connect to {self.uri} within {timeout} seconds.")
            return False
        return True

    async def send(self, message):
        await self.connection.send(json.dumps(message))

    async def receive(self):
        return await self.connection.recv()

    async def close(self):
        await self.connection.close()

    async def listen(self, on_message):
        try:
            async for message in self.connection:
                data = json.loads(message)
                await on_message(data)
        except websockets.ConnectionClosed:
            print("Connection closed")
