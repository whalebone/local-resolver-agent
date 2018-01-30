import json
import time

from local_resolver_agent.dockertools.docker_connector import DockerConnector
from local_resolver_agent.sysinfo.sys_info import get_system_info
from local_resolver_agent.exception.exc import ContainerException

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
        sysInfoMessage["data"] = get_system_info(self.dockerConnector)
        await self.send(sysInfoMessage)

    # {'data': {'test': 'test'}, 'action': 'sysinfo'}

    def process(self, request_json):
        request = json.loads(request_json)
        print(request)
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

        if request["action"] == "create":
            response["status"] = self.dockerConnector.start_service(request["data"])
            return response

        if request["action"] == "upgrade":
            status = {}
            if request["data"]["service"] != "lr-agent": # vice kontejneru, smaze neexistujici nebo jednu
                try:
                    self.dockerConnector.remove_container(request["data"]["service"])
                except ContainerException as e:
                    status["status"] = "failed"
                    status["body"] = e
                else:
                    try:
                        status = self.dockerConnector.start_service(request["data"]["config"])
                    except ContainerException as e:
                        status["status"] = "failed"
                        status["body"] = e
            else:
                try:
                    self.dockerConnector.rename_container("lr-agent", "lr-agent-old")
                except ContainerException as e:
                    status["status"] = "failed"
                    status["body"] = e
                else:
                    try:
                        self.dockerConnector.start_service(request["data"]["config"])
                    except ContainerException as e:
                        self.dockerConnector.rename_container("lr-agent-old", "lr-agent")
                        status["status"] = "failed"
                        status["body"] = e
                    else:
                        while True:
                            if self.dockerConnector.inspect_config("lr-agent")["State"]["Running"] is True:
                                try:
                                    self.remove_container("lr-agent-old")
                                except ContainerException as e:
                                    self.dockerConnector.remove_container("lr-agent")
                                    self.dockerConnector.rename_container("lr-agent-old", "lr-agent")
                                    status["status"] = "failed"
                                    status["body"] = e
                                    break
                            else:
                                time.sleep(2)
            response["status"] = status
            return response

        if request["action"] == "rename":
            status = {}
            for old_name, new_name in request["data"].items():
                status[old_name]={}
                try:
                    self.dockerConnector.rename_container(old_name, new_name)
                except ContainerException as e:
                    status[old_name]["status"] = "failed"
                    status[old_name]["body"] = e
                else:
                    status[old_name]["status"] = "sucess"
            response["status"] = status
            return response

        if request["action"] == "restart":
            status = {}
            for container in request["data"]:
                status[container] = {}
                try:
                    self.dockerConnector.restart_container(container)
                except ContainerException as e:
                    status[container]["status"] = "failed"
                    status[container]["body"]= e
                else:
                    status[container]["status"] = "sucess"
            response["status"] = status
            return response

        if request["action"] == "stop":
            status = {}
            for container in request["data"]:
                status[container] = {}
                try:
                    self.dockerConnector.stop_container(container)
                except ContainerException as e:
                    status[container]["status"] = "failed"
                    status[container]["body"] = e
                else:
                    status[container]["status"] = "sucess"
            response["status"] = status
            return response

        if request["action"] == "remove":
            status = {}
            for container in request["data"]:
                status[container] = {}
                try:
                    self.dockerConnector.remove_container(container)
                except ContainerException as e:
                    status[container]["status"] = "failed"
                    status[container]["body"] = e
                else:
                    status[container]["status"] = "sucess"
            response["status"] = status
            return response

    # if request["action"] == "containers":
    #     data = list()
    #     for container in self.dockerConnector.getContainers():
    #         data.append({
    #             "id" : container.short_id,
    #             "image" : {
    #                 "id": container.image.id[7:19],
    #                 "tags": container.image.tags
    #             },
    #             "name" : container.name,
    #             "status" : container.status
    #         })
    #     response["data"] = data
    #     response["status"] = "success"
    #     return response
    # else:
    #     return LRAgentClient.getError('Unknown action', request)

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
