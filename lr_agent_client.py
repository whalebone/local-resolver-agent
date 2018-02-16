import json
import asyncio
import base64
import yaml
import os

from dockertools.docker_connector import DockerConnector
from sysinfo.sys_info import get_system_info
from exception.exc import ContainerException, ComposeException
from dockertools.compose_parser import ComposeParser
from loggingtools.logger import build_logger
from loggingtools.log_reader import LogReader
from resolvertools.resolver_connector import FirewallConnector


class LRAgentClient:

    def __init__(self, websocket):
        self.websocket = websocket
        self.dockerConnector = DockerConnector()
        self.compose_parser = ComposeParser()
        self.firewall_connector = FirewallConnector()
        self.log_reader = LogReader()
        self.folder = "/etc/whalebone/"
        self.logger = build_logger("lr-agent", "/etc/whalebone/logs/")

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

    async def send_sys_info(self):
        try:
            sys_info = {"action": "sysinfo", "data": get_system_info(self.dockerConnector)}
        except Exception as e:
            self.logger.info(e)
            sys_info = {"action": "sysinfo", "status": "failure", "data": str(e)}
        await self.send(sys_info)

    async def send_acknowledgement(self, message: dict):
        message["data"] = "Command received"
        await self.send(message)

    async def validate_host(self):
        if not os.path.exists("{}docker-compose.yml".format(self.folder)):
            request = {"action": "request", "data": "compose missing, send resolver compose"}
            await self.send(request)
        else:
            try:
                with open("{}docker-compose.yml".format(self.folder), "r") as compose:
                    parsed_compose = self.compose_parser.create_service(compose)
                    active_services = [container.name for container in self.dockerConnector.get_containers()]
                    for service, config in parsed_compose["services"].items():
                        if service not in active_services:
                            try:
                                await self.dockerConnector.start_service(config)
                            except Exception as e:
                                print(service)
                                self.logger.warning(
                                    "Service: {} is offline, automatic start failed due to: {}".format(service, e))
            except Exception as e:
                self.logger.warning(e)

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

        method_calls = {"sysinfo": self.system_info, "create": self.create_container, "upgrade": self.upgrade_container,
                        "rename": self.rename_container, "containers": self.list_containers,
                        "stop": self.stop_container, "remove": self.remove_container,
                        "containerlogs": self.container_logs,
                        "fwrules": self.firewall_rules, "fwcreate": self.create_rule, "fwfetch": self.fetch_rule,
                        "fwmodify": self.modify_rule, "fwdelete": self.delete_rule,
                        "logs": self.agent_log_files, "log": self.agent_all_logs,
                        "flog": self.agent_filtered_logs, "dellogs": self.agent_delete_logs}
        method_arguments = {"sysinfo": [response, request], "create": [response, request],
                            "upgrade": [response, request],
                            "rename": [response, request], "containers": [response],
                            "containerlogs": [response, request],
                            "stop": [response, request], "remove": [response, request],
                            "fwrules": [response], "fwcreate": [response, request], "fwfetch": [response, request],
                            "fwmodify": [response, request], "fwdelete": [response, request],
                            "logs": [response], "log": [response, request],
                            "flog": [response, request], "dellogs": [response, request]}

        try:
            return await method_calls[request["action"]](*method_arguments[request["action"]])
        except KeyError as e:
            self.logger.info(e)
            return self.getError('Unknown action', request)

    async def system_info(self, response: dict, request: dict) -> dict:
        try:
            response["data"] = get_system_info(self.dockerConnector)
            response["status"] = "success"
        except Exception as e:
            self.logger.info(e)
            self.getError(str(e), request)
        return response

    async def create_container(self, response: dict, request: dict) -> dict:
        await self.send_acknowledgement(response)
        status = {}
        decoded_data = base64.b64decode(request["data"]["compose"])
        try:
            parsed_compose = self.compose_parser.create_service(decoded_data)
        except ComposeException as e:
            self.logger.warning(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            if "resolver" in parsed_compose["services"]:
                try:
                    if "compose" in request["data"]:
                        self.save_file("compose/docker-compose.yml", "yml", request["data"]["compose"])
                    if "config" in request["data"]:
                        self.save_file("kresd/kres.conf", "text", request["data"]["config"])
                    if "rules" in request["data"]:
                        self.save_file("kresd/firewall.conf", "json", request["data"]["rules"])
                except IOError as e:
                    status["dump"] = {"compose": {"status": "failure", "body": str(e)}}
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
                if service == "resolver":
                    try:
                        self.firewall_connector.inject_all_rules()
                    except ConnectionError as e:
                        self.logger.info(e)
                        status[service]["inject"] = "failure"
            del response["requestId"]
            response["data"] = status
        return response

    async def upgrade_container(self, response: dict, request: dict) -> dict:
        await self.send_acknowledgement(response)
        status = {}
        decoded_data = base64.b64decode(request["data"]["compose"])
        if "services" in request["data"]:
            services = request["data"]["services"]
        else:
            services = []
        try:
            parsed_compose = self.compose_parser.create_service(decoded_data)
        except ComposeException as e:
            self.logger.warning(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            for service, config in parsed_compose["services"].items():
                if service in services or len(services) == 0:
                    if service not in ["lr-agent", "resolver"]:
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
                                status[service] = {"status": "failure", "message": "start of new container",
                                                   "body": str(e)}
                                response["status"] = "failure"
                                self.logger.info(e)
                            else:
                                status[service]["status"] = "success"
                    else:
                        if "resolver" in parsed_compose["services"]:
                            try:
                                if "config" in request["data"]:
                                    self.save_file("kresd/kres.conf", "text", request["data"]["config"])
                                if "rules" in request["data"]:
                                    self.save_file("kresd/firewall.conf", "json", request["data"]["rules"])
                            except IOError as e:
                                status["dump"] = {"compose": {"status": "failure", "body": str(e)}}
                        try:
                            await self.dockerConnector.rename_container(service, "{}-old".format(
                                service))  # tries to rename old agent
                        except ContainerException as e:
                            status["lr-agent"] = {"status": "failure", "message": "rename old service", "body": str(e)}
                            response["status"] = "failure"
                            self.logger.info(e)
                        else:
                            status[service] = {}
                            try:
                                await self.dockerConnector.start_service(config)  # tries to start new agent
                            except ContainerException as e:
                                status[service] = {"status": "failure", "message": "start of new service",
                                                   "body": str(e)}
                                response["status"] = "failure"
                                self.logger.info(e)
                                try:
                                    await self.dockerConnector.rename_container("{}-old".format(service),
                                                                                service)  # tries to rename old agent
                                except ContainerException as e:
                                    status[service] = {"status": "failure", "message": "rename rollback",
                                                       "body": str(e)}
                                    response["status"] = "failure"
                                    self.logger.info(e)
                            else:
                                while True:
                                    inspect = await self.dockerConnector.inspect_config(service)
                                    if inspect["State"]["Running"] is True:
                                        try:
                                            await self.dockerConnector.remove_container(
                                                "{}-old".format(service))  # tries to renomve old agent
                                        except ContainerException as e:
                                            status[service] = {"status": "failure", "message": "removal of old service",
                                                               "body": str(e)}
                                            response["status"] = "failure"
                                            self.logger.info(e)
                                            try:
                                                await self.dockerConnector.remove_container(
                                                    service)  # tries to rename new agent
                                            except ContainerException as e:
                                                status[service] = {"status": "failure",
                                                                   "message": "removal of old and new service",
                                                                   "body": str(e)}
                                                self.logger.info(e)
                                            else:
                                                try:
                                                    await self.dockerConnector.rename_container(
                                                        "{}-old".format(service), service)  # tries to rename old agent
                                                except ContainerException as e:
                                                    status[service] = {"status": "failure",
                                                                       "message": "removal and rename of old agent",
                                                                       "body": str(e)}
                                                    self.logger.info(e)
                                            break
                                        else:
                                            if service == "resolver":  # for testing purpose
                                                try:
                                                    self.firewall_connector.inject_all_rules()
                                                except ConnectionError as e:
                                                    self.logger.info(e)
                                                    status[service]["inject"] = "failure"
                                            status[service]["status"] = "success"
                                            break
                                    else:
                                        await asyncio.sleep(2)
            del response["requestId"]
            response["data"] = status
        return response

    async def rename_container(self, response: dict, request: dict) -> dict:
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

    # async def restart_container(self, response: dict, request: dict) -> dict:
    #     await self.send_acknowledgement(response)
    #     status = {}
    #     for container in request["data"]:
    #         status[container] = {}
    #         try:
    #             await self.dockerConnector.restart_container(container)
    #         except ContainerException as e:
    #             status[container] = {"status": "failure", "body": str(e)}
    #             response["status"] = "failure"
    #             self.logger.info(e)
    #         else:
    #             status[container]["status"] = "success"
    #     del response["requestId"]
    #     response["data"] = status
    #     return response

    async def stop_container(self, response: dict, request: dict) -> dict:
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

    async def remove_container(self, response: dict, request: dict) -> dict:
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

    async def list_containers(self, response: dict) -> dict:
        data = []
        for container in self.dockerConnector.get_containers():
            data.append({
                "id": container.short_id,
                "image": {
                    "id": container.image.id[7:19],
                    "tags": container.image.tags
                },
                "labels": {
                    label: value for label, value in container.labels.items() if container.name == label
                },
                "name": container.name,
                "status": container.status
            })
        return {**response, "data": data}

    async def container_logs(self, response: dict, request: dict) -> dict:
        try:
            logs = self.dockerConnector.container_logs(**request["data"])
        except ConnectionError as e:
            response["data"] = str(e)
            response["status"] = "failure"
            self.logger.info(e)
        else:
            response["data"] = base64.b64encode(logs).decode("utf-8")
        return response

    async def firewall_rules(self, response: dict) -> dict:
        try:
            data = self.firewall_connector.active_rules()
        except (ConnectionError, Exception) as e:
            self.logger.info(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            response["data"] = data
        return response

    async def create_rule(self, response: dict, request: dict) -> dict:
        status = {}
        for rule in request["data"]:
            status[rule] = {}
            try:
                self.firewall_connector.create_rule(rule)
            except (ConnectionError, Exception) as e:
                self.logger.info(e)
                response["status"] = "failure"
                status[rule] = {"status": "failure", "body": str(e)}
            else:
                status[rule] = {"status": "success"}
        successful_rules = [rule for rule in status.keys() if status[rule]["status"] == "success"]
        if len(successful_rules) > 0:
            try:
                self.save_file("kresd/firewall.conf", "json", successful_rules)
            except IOError as e:
                self.logger.info(e)
                response["status"] = "failure"
                response["data"] = str(e)
        response["data"] = status
        return response

    async def fetch_rule(self, response: dict, request: dict) -> dict:
        try:
            data = self.firewall_connector.fetch_rule_information(request["data"])
        except (ConnectionError, Exception) as e:
            self.logger.info(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            response["data"] = data
        return response

    async def delete_rule(self, response: dict, request: dict) -> dict:
        status = {}
        for rule in request["data"]:
            status[rule] = {}
            try:
                self.firewall_connector.delete_rule(rule)
            except (ConnectionError, Exception) as e:
                self.logger.info(e)
                response["status"] = "failure"
                status[rule] = {"status": "failure", "body": str(e)}
            else:
                status[rule] = {"status": "success"}
        response["data"] = status
        return response

    async def modify_rule(self, response: dict, request: dict) -> dict:
        try:
            self.firewall_connector.modify_rule(*request["data"])
        except (ConnectionError, Exception) as e:
            self.logger.info(e)
            response["status"] = "failure"
            response["data"] = str(e)
        return response

    async def agent_log_files(self, response: dict) -> dict:
        try:
            files = self.log_reader.list_files()
        except FileNotFoundError as e:
            self.logger.info(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            response["data"] = files
        return response

    async def agent_all_logs(self, response: dict, request: dict) -> dict:
        try:
            lines = self.log_reader.view_log(request["data"])
        except IOError as e:
            self.logger.info(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            response["data"] = lines
        return response

    async def agent_filtered_logs(self, response: dict, request: dict) -> dict:
        try:
            lines = self.log_reader.filter_logs(**request["data"])
        except Exception as e:
            self.logger.info(e)
            response["status"] = "failure"
            response["data"] = str(e)
        else:
            response["data"] = lines
        return response

    async def agent_delete_logs(self, response: dict, request: dict) -> dict:
        status = {}
        for file in request["data"]:
            status[file] = {}
            try:
                self.log_reader.delete_log(file)
            except IOError as e:
                status[file] = {"status": "failure", "data": str(e)}
                response["status"] = "failure"
            else:
                status["status"] = "success"
                status[file] = {"status": "status"}
        return response

    def save_file(self, location, file_type, content):
        try:
            with open("{}{}".format(self.folder, location), "w") as file:
                if file_type == "yml":
                    yaml.dump(content, file, default_flow_style=False)
                elif file_type == "json":
                    json.dump(content, file)
                else:
                    for rule in content:
                        file.write(rule + "\n")
        except Exception as e:
            self.logger.info(e)
            raise IOError(e)

    def getError(self, message: str, request: dict)-> dict:
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
