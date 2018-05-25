import websockets
import os
import json
import base64

from loggingtools.logger import build_logger


class LRAgentLocalClient:

    def __init__(self, websocket, agent):
        self.agent = agent
        self.websocket = websocket
        try:
            port = int(os.environ["LOCAL_API_PORT"])
        except KeyError:
            port = 8765
        self.worker = websockets.serve(self.receive, 'localhost', port)
        self.logger = build_logger("local-api", "/etc/whalebone/logs/")

    async def receive(self, websocket, path):
        while True:
            try:
                msg = await websocket.recv()
            except websockets.ConnectionClosed:
                pass
            else:
                try:
                    msg = json.loads(msg)
                    self.logger.info("Received: {}".format(msg))
                    msg["cli"] = "true"
                    response = await self.agent.process(json.dumps(msg))
                except Exception as e:
                    request = json.loads(msg)
                    response = {"action": request["action"], "data": {"status": "failure", "body": str(e)}}
                    self.logger.warning(e)
                else:
                    try:
                        await self.websocket.send(json.dumps(self.agent.encode_base64_json(response)))
                    except Exception as e:
                        self.logger.warning(e)
                try:
                    response["data"] = json.loads(base64.b64decode(response["data"].encode("utf-8")).decode("utf-8"))
                    self.logger.info("Sending: {}".format(msg))
                    await websocket.send(json.dumps(response))
                except Exception as e:
                    self.logger.info(e)
