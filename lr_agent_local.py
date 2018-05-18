import websockets
import asyncio
import logging
import json

from loggingtools.logger import build_logger


class LRAgentLocalClient:

    def __init__(self, websocket, agent):
        self.agent = agent
        self.websocket = websocket
        self.worker = websockets.serve(self.receive, 'localhost', 8765)
        self.logger = build_logger("local-api", "/etc/whalebone/logs/")

    async def receive(self, websocket, path):
        while True:
            try:
                msg = await websocket.recv()
            except websockets.ConnectionClosed:
                pass
            else:
                try:
                    msg["cli"] = "true"
                    response = await self.agent.process(msg)
                except Exception as e:
                    request = json.loads(msg)
                    response = {"action": request["action"], "data": {"status": "failure", "body": str(e)}}
                    self.logger.warning(e)
                else:
                    await self.websocket.send(json.dumps(self.agent.encode_base64_json(response)))
                await websocket.send(json.dumps(response))
