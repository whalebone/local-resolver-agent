import json

from dockertools.docker_connector import DockerConnector
from sysinfo.sys_info import get_system_info


class LRAgentClient:

    def __init__(self, websocket):
        self.websocket = websocket
        self.dockerConnector = DockerConnector()

    async def listen(self):
        while True:
            request = await self.websocket.recv()
            print("< {}".format(request))
            response = self.process(request)
            await self.send(response)

    async def send(self, message):
        await self.websocket.send(json.dumps(message))

    async def sendSysInfo(self):
        sysInfoMessage = dict()
        sysInfoMessage["action"] = "sysinfo"
        sysInfoMessage["data"] = get_system_info()
        await self.send(sysInfoMessage)

    def process(self, request_json):
        request = json.loads(request_json)
        response = dict()
        if "action" not in request or request["action"] is None:
            return LRAgentClient.getError('Missing action in request', request)
        if "requestId" in request and request["requestId"] is not None:
            response["requestId"] = request["requestId"]
        response["action"] = request["action"]

        # get system info
        if request["action"] == "sysinfo":
            response["data"] = get_system_info()
            print("> {}".format(response))
            response["status"] = "success"
            return response

        # get dockertools containers
        if request["action"] == "containers":
            data = list()
            for container in self.dockerConnector.getContainers():
                data.append({
                    "id" : container.short_id,
                    "image" : {
                        "id": container.image.id[7:19],
                        "tags": container.image.tags
                    },
                    "name" : container.name,
                    "status" : container.status
                })
            response["data"] = data
            response["status"] = "success"
            return response
        else:
            return LRAgentClient.getError('Unknown action', request)

    @staticmethod
    def getError(message, request):
        errorResponse = {
            "status": "failure",
            "message": message,
        }
        if "requestId" in request and request["requestId"] is not None:
            errorResponse["requestId"] = request["requestId"]
        if "action" in request and request["action"] is not None:
            errorResponse["action"] = request["action"]
        if "data" in request and request["data"] is not None:
            errorResponse["data"] = request["data"]
        return errorResponse
