import websockets
import os
import json
import base64
import asyncio
import socket

from loggingtools.logger import build_logger


class LRAgentLocalClient:

    def __init__(self, agent):
        self.agent = agent
        # self.websocket = websocket
        self.port = int(os.environ.get("LOCAL_API_PORT", 8765))
        self.logger = build_logger("local-api", "/etc/whalebone/logs/")

    async def start_api(self):
        while True:
            if self.test_port():
                try:
                    worker = websockets.serve(self.receive, '0.0.0.0', self.port)
                except Exception as e:
                    self.logger.info("Unable to init worker, {}".format(e))
                else:
                    # await worker
                    self.logger.info("Local api created")
                    return worker
                    # break
            else:
                self.logger.warning("Bind unsuccessful, port is used")
                await asyncio.sleep(10)

    def test_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("localhost", self.port))
        except OSError:
            return False
        else:
            sock.close()
            return True

    async def receive(self, websocket, path):  # path is used parameter in coroutine but it is necessary to work
        while True:
            try:
                msg = await websocket.recv()
            except websockets.ConnectionClosed:
                pass
            else:
                try:
                    request = json.loads(msg)
                    self.logger.info("Received: {}".format(request))
                    request["cli"] = "true"
                    response = await self.agent.process(json.dumps(request))
                except json.JSONDecodeError:
                    response = {"error": "failed to json parse request"}
                except Exception as e:
                    response = {"action": request["action"], "data": {"status": "failure", "body": str(e)}}
                    self.logger.warning("Failed to execute request {}, {}.".format(request, e))
                finally:
                    try:
                        # response["data"] = json.loads(base64.b64decode(response["data"].encode("utf-8")).decode("utf-8"))
                        self.logger.info("Sending: {}".format(response))
                        await websocket.send(json.dumps(response))
                    except Exception as e:
                        self.logger.info(e)
                # else:
                #     try:
                #         await self.websocket.send(json.dumps(self.agent.encode_base64_json(response)))
                #     except Exception as e:
                #         self.logger.warning(e)
