import json
import asyncio
import base64
import yaml

from local_resolver_agent.dockertools.docker_connector import DockerConnector
from local_resolver_agent.sysinfo.sys_info import get_system_info
from local_resolver_agent.exception.exc import ContainerException
from local_resolver_agent.dockertools.compose_parser import ComposeParser
from local_resolver_agent.secret_directory.logger import build_logger


class LRAgentClient:

    def __init__(self, websocket):
        self.websocket = websocket
        self.dockerConnector = DockerConnector()
        self.compose_parser = ComposeParser()
        self.logger = build_logger("lr-agent", "/home/narzhan/Downloads/agent_logs/")

    async def listen(self):
        while True:
            request = await self.websocket.recv()
            try:
                response = await self.process(request)
            except Exception as e:
                request = json.loads(request)
                response = {"status": "failure", "requestId": request["requestId"], "action": request["action"],
                            "body": str(e)}
                self.logger.warning(e)
            await self.send(response)

    async def send(self, message: dict):
        try:
            await self.websocket.send(json.dumps(message))
        except Exception as e:
            self.logger.warning(e)

    async def sendSysInfo(self):
        try:
            sys_info = {"action": "sysinfo", "data": get_system_info(self.dockerConnector)}
        except Exception as e:
            self.logger.info(e)
            sys_info = {"action": "sysinfo", "status": "failure", "data": str(e)}
        await self.send(sys_info)

    async def send_acknowledgement(self, message: dict):
        message["data"] = "Command received"
        await self.send(message)

    async def process(self, request_json):
        request = json.loads(request_json)
        print(request)
        response = {}
        if "action" not in request or request["action"] is None:
            return self.getError('Missing action in request', request)
        if "requestId" in request and request["requestId"] is not None:
            response["requestId"] = request["requestId"]
        response["action"] = request["action"]
        response["status"] = "success"

        if request["action"] == "sysinfo":
            try:
                response["data"] = get_system_info(self.dockerConnector)
                response["status"] = "success"
            except Exception as e:
                self.logger.info(e)
                self.getError(e, request)
            return response

        if request["action"] == "create":
            await self.send_acknowledgement(response)
            status = {}
            decoded_data = base64.b64decode(request["data"])
            parsed_compose = self.compose_parser.create_service(decoded_data)
            self.save_file("compose/docker-compose.yml", "yml", parsed_compose)
            for service, config in parsed_compose["services"].items():
                status[service] = {}
                try:
                    await self.dockerConnector.start_service(config)
                except ContainerException as e:
                    status[service] = {"status": "failure", "body": str(e)}
                    response["status"] = "failure"
                    self.logger.info(e)
                else:
                    status[service]["status"] = "success"
            del response["requestId"]
            response["data"] = status
            return response

        if request["action"] == "upgrade":
            await self.send_acknowledgement(response)
            status = {}
            decoded_data = base64.b64decode(request["data"])
            parsed_compose = self.compose_parser.create_service(decoded_data)
            self.save_file("compose/docker-compose.yml", "yml", parsed_compose)
            if "lr-agent" not in parsed_compose:
                for service, config in parsed_compose["services"].items():
                    status[service] = {}
                    try:
                        await self.dockerConnector.remove_container(service)  # tries to remove old container
                    except ContainerException as e:
                        status[service] = {"status": "failure", "message": "remove old container", "body": str(e)}
                        response["status"] = "failure"
                        self.logger.info(e)
                    else:
                        try:
                            await self.dockerConnector.start_service(config)  # tries to start new container
                        except ContainerException as e:
                            status[service] = {"status": "failure", "message": "start of new container", "body": str(e)}
                            response["status"] = "failure"
                            self.logger.info(e)
                        else:
                            status[service]["status"] = "success"
            else:
                try:
                    await self.dockerConnector.rename_container("lr-agent", "lr-agent-old")  # tries to rename old agent
                except ContainerException as e:
                    status["lr-agent"] = {"status": "failure", "message": "rename old agent", "body": str(e)}
                    response["status"] = "failure"
                    self.logger.info(e)
                else:
                    for service, config in parsed_compose["services"].items():
                        status[service] = {}
                        try:
                            await self.dockerConnector.start_service(config)  # tries to start new agent
                        except ContainerException as e:
                            status[service] = {"status": "failure", "message": "start of new agent", "body": str(e)}
                            response["status"] = "failure"
                            self.logger.info(e)
                            try:
                                await self.dockerConnector.rename_container("lr-agent-old",
                                                                            "lr-agent")  # tries to rename old agent
                            except ContainerException as e:
                                status[service] = {"status": "failure", "message": "rename rollback", "body": str(e)}
                                response["status"] = "failure"
                                self.logger.info(e)
                        else:
                            while True:
                                inspect = await self.dockerConnector.inspect_config("lr-agent")
                                if inspect["State"]["Running"] is True:
                                    try:
                                        await self.dockerConnector.remove_container(
                                            "lr-agent-old")  # tries to renomve old agent
                                    except ContainerException as e:
                                        status[service] = {"status": "failure", "message": "removal of old agent",
                                                           "body": str(e)}
                                        response["status"] = "failure"
                                        self.logger.info(e)
                                        try:
                                            await self.dockerConnector.remove_container(
                                                "lr-agent")  # tries to rename new agent
                                        except ContainerException as e:
                                            status[service] = {"status": "failure",
                                                               "message": "removal of old agent and new agent",
                                                               "body": str(e)}
                                            self.logger.info(e)
                                        else:
                                            try:
                                                await self.dockerConnector.rename_container("lr-agent-old",
                                                                                            "lr-agent")  # tries to rename old agent
                                            except ContainerException as e:
                                                status[service] = {"status": "failure",
                                                                   "message": "removal and rename of old agent",
                                                                   "body": str(e)}
                                                self.logger.info(e)
                                        # break
                                    else:  # for testing purpose
                                        break
                                else:
                                    await asyncio.sleep(2)
            del response["requestId"]
            response["data"] = status
            return response

        if request["action"] == "rename":
            status = {}
            for old_name, new_name in request["data"].items():
                status[old_name] = {}
                try:
                    await self.dockerConnector.rename_container(old_name, new_name)
                except ContainerException as e:
                    status[old_name] = {"status": "failure", "body": str(e)}
                    response["status"] = "failure"
                    self.logger.info(e)
                else:
                    status[old_name]["status"] = "success"
            response["data"] = status
            return response

        if request["action"] == "restart":
            await self.send_acknowledgement(response)
            status = {}
            for container in request["data"]:
                status[container] = {}
                try:
                    await self.dockerConnector.restart_container(container)
                except ContainerException as e:
                    status[container] = {"status": "failure", "body": str(e)}
                    response["status"] = "failure"
                    self.logger.info(e)
                else:
                    status[container]["status"] = "success"
            del response["requestId"]
            response["data"] = status
            return response

        if request["action"] == "stop":
            await self.send_acknowledgement(response)
            status = {}
            for container in request["data"]:
                status[container] = {}
                try:
                    await self.dockerConnector.stop_container(container)
                except ContainerException as e:
                    status[container] = {"status": "failure", "body": str(e)}
                    response["status"] = "failure"
                    self.logger.info(e)
                else:
                    status[container]["status"] = "success"
            del response["requestId"]
            response["data"] = status
            return response

        if request["action"] == "remove":
            await self.send_acknowledgement(response)
            status = {}
            for container in request["data"]:
                status[container] = {}
                try:
                    await self.dockerConnector.remove_container(container)
                except ContainerException as e:
                    status[container] = {"status": "failure", "body": str(e)}
                    response["status"] = "failure"
                    self.logger.info(e)
                else:
                    status[container]["status"] = "success"
            del response["requestId"]
            response["data"] = status
            return response

        if request["action"] == "containers":
            data = []
            for container in self.dockerConnector.get_containers():
                data.append({
                    "id": container.short_id,
                    "image": {
                        "id": container.image.id[7:19],
                        "tags": container.image.tags
                    },
                    "name": container.name,
                    "status": container.status
                })
            return {**response, "status": "success", "data": data}
        else:
            return self.getError('Unknown action', request)

    def save_file(self, location, file_type, content):
        with open("/etc/whalebone/{}".format(location), "w") as file:
            if file_type == "yml":
                yaml.dump(content, file, default_flow_style=False)
            elif file_type == "json":
                json.dump(content, file)
            else:
                file.write(content)

    def getError(self, message, request):
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
