import json
import asyncio
import base64

import yaml
import os
import requests
import websockets

from dockertools.docker_connector import DockerConnector
from sysinfo.sys_info import get_system_info, check_port, check_resolving
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
        self.logger = build_logger("lr-agent", "{}logs/".format(self.folder))
        self.async_actions = ["stop", "remove", "create", "upgrade"]
        self.error_stash = {}
        try:
            self.alive = int(os.environ['KEEP_ALIVE'])
        except KeyError:
            self.alive = 10

    async def listen(self):
        # async for request in self.websocket:
        while True:
            try:
                request = await asyncio.wait_for(self.websocket.recv(), timeout=self.alive)
            except asyncio.TimeoutError:
                try:
                    pong_waiter = await self.websocket.ping()
                    await asyncio.wait_for(pong_waiter, timeout=self.alive)
                except asyncio.TimeoutError:
                    # pass
                    # self.logger.info("Failed to receive pong")
                    raise Exception("Failed to receive pong")
            else:
                try:
                    response = await self.process(request)
                except Exception as e:
                    request = json.loads(request)
                    response = {"data": {"status": "failure", "body": str(e)}}
                    for field in ["requestId", "action"]:
                        if field in request:
                            response[field] = request[field]
                    self.logger.warning(e)
                else:
                    try:
                        if response["action"] in self.async_actions:
                            self.process_response(response)
                    except Exception as e:
                        self.logger.info("General error at error dumping, {}".format(e))
                await self.send(response)

    async def send(self, message: dict):
        try:
            message = self.encode_base64_json(message)
        except Exception as e:
            self.logger.warning(e)
        else:
            if message["action"] != "sysinfo":
                self.logger.info("Sending: {}".format(message))
            await self.websocket.send(json.dumps(message))

    async def send_sys_info(self):
        try:
            sys_info = {"action": "sysinfo", "data": get_system_info(self.dockerConnector, self.error_stash)}
        except Exception as e:
            self.logger.info(e)
            sys_info = {"action": "sysinfo", "data": {"status": "failure", "body": str(e)}}
        await self.send(sys_info)

    async def send_acknowledgement(self, message: dict):
        message["data"] = {"status": "success", "message": "Command received"}
        await self.send(message)

    async def validate_host(self):
        if not os.path.exists("{}compose/docker-compose.yml".format(self.folder)):
            request = {"action": "request", "data": {"message": "compose missing"}}
            await self.send(request)
        else:
            try:
                with open("{}compose/docker-compose.yml".format(self.folder), "r") as compose:
                    parsed_compose = self.compose_parser.create_service(yaml.load(compose))
                    active_services = [container.name for container in self.dockerConnector.get_containers()]
                    for service, config in parsed_compose["services"].items():
                        if service not in active_services:
                            try:
                                await self.upgrade_start_service(service, config)
                                # await self.dockerConnector.start_service(config)
                            except Exception as e:
                                self.logger.warning(
                                    "Service: {} is offline, automatic start failed due to: {}".format(service, e))
            except Exception as e:
                self.logger.warning(e)

    def process_response(self, response: dict):
        for key, value in response["data"].items():
            if value["status"] == "failure":
                try:
                    if key not in self.error_stash:
                        self.error_stash[key] = {response["action"]: value["body"]}
                    else:
                        self.error_stash[key].update({response["action"]: value["body"]})
                except KeyError as e:
                    self.logger.info("Error at process_response during key ingest, key not found {}".format(e))
            else:
                try:
                    if key in self.error_stash and response["action"] in self.error_stash[key]:
                        del self.error_stash[key][response["action"]]
                        if len(self.error_stash[key]) == 0:
                            del self.error_stash[key]
                except KeyError as e:
                    self.logger.info("Error at process_response during key clearance, {}".format(e))

    async def process(self, request_json):
        # request = json.loads(request_json) # rewrite
        try:
            request = self.decode_base64_json(json.loads(request_json))
        except Exception as e:
            self.logger.info(e, request)
            return {"requestId": request["requestId"], "action": request["action"],
                    "data": {"status": "failure", "message": "failed to parse/decode request", "body": str(e)}}

        self.logger.info("Received: {}".format(request))
        response = {}
        if "action" not in request:
            return self.getError('Missing action in request', request)
        if "requestId" in request:
            response["requestId"] = request["requestId"]
        response["action"] = request["action"]

        method_calls = {"sysinfo": self.system_info, "create": self.create_container, "upgrade": self.upgrade_container,
                        "rename": self.rename_container, "containers": self.list_containers,
                        "stop": self.stop_container, "remove": self.remove_container,
                        "containerlogs": self.container_logs,
                        "fwrules": self.firewall_rules, "fwcreate": self.create_rule, "fwfetch": self.fetch_rule,
                        "fwmodify": self.modify_rule, "fwdelete": self.delete_rule,
                        "logs": self.agent_log_files, "log": self.agent_all_logs,
                        "flog": self.agent_filtered_logs, "dellogs": self.agent_delete_logs,
                        "test": self.agent_test_message, "updatecache": self.update_cache,
                        "saveconfig": self.write_config, "whitelistadd": self.whitelist_add,
                        "localtest": self.local_api_check}
        method_arguments = {"sysinfo": [response, request], "create": [response, request],
                            "upgrade": [response, request],
                            "rename": [response, request], "containers": [response],
                            "containerlogs": [response, request],
                            "stop": [response, request], "remove": [response, request],
                            "fwrules": [response], "fwcreate": [response, request], "fwfetch": [response, request],
                            "fwmodify": [response, request], "fwdelete": [response, request],
                            "logs": [response], "log": [response, request],
                            "flog": [response, request], "dellogs": [response, request], "test": [response],
                            "updatecache": [response], "saveconfig": [response, request],
                            "whitelistadd": [response, request], "localtest": [response]}

        try:
            return await method_calls[request["action"]](*method_arguments[request["action"]])
        except KeyError as e:
            self.logger.info(e)
            return self.getError('Unknown action', request)

    async def system_info(self, response: dict, request: dict) -> dict:
        try:
            response["data"] = get_system_info(self.dockerConnector, self.error_stash)
        except Exception as e:
            self.logger.info(e)
            self.getError(str(e), request)
        return response

    async def create_container(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        # decoded_data = self.decode_base64_string(request["data"]["compose"])
        decoded_data = self.upgrade_load_compose(request, response)
        if "status" in decoded_data:
            return decoded_data
        try:
            parsed_compose = self.compose_parser.create_service(decoded_data)
        except ComposeException as e:
            self.logger.warning(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            # if "config" in request["data"]:
            #     try:
            #         await self.write_config(response, request)
            #     except Exception as e:
            #         self.logger.info(e)
            self.logger.warning(parsed_compose)
            if "resolver" in parsed_compose["services"]:
                result = self.upgrade_save_files(request, decoded_data)
                if result != {}:
                    status["dump"] = result
            for service, config in parsed_compose["services"].items():
                status[service] = {}
                try:
                    await self.dockerConnector.start_service(config)
                except ContainerException as e:
                    status[service] = {"status": "failure", "body": str(e)}
                    self.logger.info(e)
                else:
                    status[service]["status"] = "success"
                    if service == "resolver":
                        await self.update_cache({})

                # if service == "resolver":
                #     try:
                #         request = {"action": "request", "data": {"message": "rules missing"}}
                #         await self.send(request)
                #     except Exception as e:
                #         status[service]["inject_request"] = {"status": "failure", "body": str(e)}
                #     else:
                #         status[service]["inject_request"] = "success"

                # try:
                #     self.firewall_connector.inject_all_rules()
                # except ConnectionError as e:
                #     self.logger.info(e)
                #     status[service]["inject"] = "failure"
                # else:
                #     status[service]["inject"] = "success"
            if "requestId" in response:
                del response["requestId"]
            response["data"] = status
        return response

    async def upgrade_container(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        decoded_data = self.upgrade_load_compose(request, response)
        if "status" in decoded_data:
            return decoded_data
        if "services" in request["data"]:
            services = request["data"]["services"]
        else:
            services = []
        try:
            parsed_compose = self.compose_parser.create_service(decoded_data)
        except ComposeException as e:
            self.logger.warning(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            ordered_services = list(parsed_compose["services"].keys())  # creates list of services from compose
            if "lr-agent" in ordered_services:
                ordered_services.append(ordered_services.pop(
                    ordered_services.index("lr-agent")))  # puts agent at the end of the list if present
            if "resolver" in services or not services:
                try:
                    old_config = self.load_file("resolver/kres.conf")
                except IOError as e:
                    status["load"] = {"status": "failure", "body": str(e)}
                # result = self.upgrade_save_files(request, decoded_data)
                # if result != {}:
                #     status["dump"] = result
            for service in ordered_services:
                if service in services or not services:
                    status[service] = {}
                    if service not in ["lr-agent", "resolver"]:
                        await self.upgrade_pull_image(parsed_compose["services"][service]['image'])
                        remove = await self.upgrade_worker_method(service,
                                                                  service,
                                                                  self.dockerConnector.remove_container,
                                                                  "remove old container")
                        if remove == {}:
                            start = await self.upgrade_start_service(service, parsed_compose["services"][service])
                            if isinstance(start, str):
                                status[service]["status"] = start
                            else:
                                status[service] = start
                            # try:
                            #     await self.dockerConnector.start_service(parsed_compose["services"][service])  # tries to start new container
                            # except ContainerException as e:
                            #     status[service] = {"status": "failure", "message": "start of new container",
                            #                        "body": str(e)}
                            #     self.logger.info(e)
                            # else:
                            #     status[service]["status"] = "success"
                        else:
                            status[service] = remove
                        # try:
                        #     if service in [container.name for container in
                        #                    self.dockerConnector.get_containers(stopped=True)]:
                        #         await self.dockerConnector.remove_container(service)  # tries to remove old container
                        # except ContainerException as e:
                        #     status[service] = {"status": "failure", "message": "remove old container", "body": str(e)}
                        #     self.logger.info(e)
                        # else:
                        #     try:
                        #         await self.dockerConnector.start_service(parsed_compose["services"][service])  # tries to start new container
                        #     except ContainerException as e:
                        #         status[service] = {"status": "failure", "message": "start of new container",
                        #                            "body": str(e)}
                        #         self.logger.info(e)
                        #     else:
                        #         status[service]["status"] = "success"
                    else:
                        if service == "resolver" and check_port(self.dockerConnector) == "fail":
                            remove = await self.upgrade_worker_method(service,
                                                                      service,
                                                                      self.dockerConnector.remove_container,
                                                                        "Failed to remove unhealthy container")
                            if remove == {}:
                                start = await self.dockerConnector.start_service(parsed_compose["services"][service],
                                                                                 "Failed to create new container from unhealthy")
                                if start != "success":
                                    status[service] = start
                                # try:
                                #     await self.dockerConnector.start_service(parsed_compose["services"][service])
                                # except Exception as e:
                                #     self.logger.warning("Failed to create new container from unhealthy, {}".format(e))
                                #     status[service] = {"status": "failure",
                                #                        "message": "Failed to create new container from unhealthy",
                                #                        "body": str(e)}
                                else:
                                    status[service]["status"] = "success"
                            else:
                                status[service] = remove

                            # try:
                            #     if service in [container.name for container in
                            #                                     self.dockerConnector.get_containers(
                            #                                         stopped=True)]:
                            #         await self.dockerConnector.remove_container(service)
                            # except Exception as e:
                            #     self.logger.warning("Failed to remove unhealthy container, {}".format(e))
                            #     status[service] = {"status": "failure",
                            #                        "message": "Failed to remove unhealthy container", "body": str(e)}
                            # else:
                            #     try:
                            #         await self.dockerConnector.start_service(parsed_compose["services"][service])
                            #     except Exception as e:
                            #         self.logger.warning("Failed to create new container from unhealthy, {}".format(e))
                            #         status[service] = {"status": "failure",
                            #                            "message": "Failed to create new container from unhealthy",
                            #                            "body": str(e)}
                            #     else:
                            #         status[service]["status"] = "success"
                        else:
                            rename = await self.upgrade_rename_service(service)
                            if rename != "success":
                                status[service] = rename
                            # try:
                            #     await self.upgrade_rename_service(service)
                            #     # if "{}-old".format(
                            #     #         service) in [container.name for container in
                            #     #                      self.dockerConnector.get_containers(stopped=True)]:
                            #     #     await self.dockerConnector.remove_container("{}-old".format(
                            #     #         service))
                            #     #     await self.dockerConnector.rename_container(service, "{}-old".format(
                            #     #         service))  # tries to rename old agent
                            #     # else:
                            #     #     await self.dockerConnector.rename_container(service, "{}-old".format(
                            #     #         service))  # tries to rename old agent
                            # except ContainerException as e:
                            #     status[service] = {"status": "failure", "message": "rename old service", "body": str(e)}
                            #     self.logger.info(e)
                            else:
                                start = await self.upgrade_start_service(service, parsed_compose["services"][service])
                                if start != "success":
                                # try:
                                #     await self.upgrade_start_service(service, parsed_compose["services"][service])
                                #     # if service not in [container.name for container in
                                #     #                    self.dockerConnector.get_containers(stopped=True)]:
                                #     #     await self.dockerConnector.start_service(
                                #     #         parsed_compose["services"][service])  # tries to start new service
                                #     # else:
                                #     #     await self.dockerConnector.remove_container(service)  # deletes orphaned service
                                #     #     await self.dockerConnector.start_service(
                                #     #         parsed_compose["services"][service])  # tries to start new service
                                # except ContainerException as e:
                                #     status[service] = {"status": "failure", "message": "start of new service",
                                #                        "body": str(e)}
                                #     self.logger.info(e)
                                    rename = await self.upgrade_worker_method(service,
                                                                                "{}-old".format(service),
                                                                              self.dockerConnector.rename_container,
                                                                                "rename rollback")
                                    if rename != {}:
                                        status[service] = rename
                                    # try:
                                    #     if "{}-old".format(service) in [container.name for container in
                                    #                                     self.dockerConnector.get_containers(
                                    #                                         stopped=True)]:
                                    #         await self.dockerConnector.rename_container("{}-old".format(service),
                                    #                                                     service)  # tries to rename old agent
                                    # except ContainerException as e:
                                    #     status[service] = {"status": "failure", "message": "rename rollback",
                                    #                        "body": str(e)}
                                    #     self.logger.info(e)
                                else:
                                    try:
                                        while True:
                                            if service == "resolver":
                                                if check_port(self.dockerConnector) == "fail" and check_port(
                                                        self.dockerConnector, "resolver-old") == "fail":
                                                    raise ContainerException("New resolver is not healthy rollback")
                                                stop = await self.upgrade_worker_method("resolver-old", "resolver-old",
                                                                                        self.dockerConnector.stop_container,
                                                                                        "Failed to stop old resolver")
                                                if stop != {}:
                                                    raise ContainerException("Failed to stop old resolver")
                                                # try:
                                                #     if "{}-old".format(service) in [container.name for container in
                                                #                                     self.dockerConnector.get_containers(
                                                #                                         stopped=True)]:
                                                #         await self.dockerConnector.stop_container(
                                                #             "{}-old".format(service))  # tries to stop old resolver
                                                # except Exception as e:
                                                #     raise ContainerException(
                                                #         "Failed to stop old {}, with error {}".format(service, e))
                                                else:
                                                    if check_resolving() == "fail":
                                                        self.save_file("resolver/kres.conf", "text", old_config)
                                                        restart = await self.upgrade_worker_method("resolver-old",
                                                                                                   "resolver-old",
                                                                                                   self.dockerConnector.restart_container,
                                                                                                   "failed to restart old resolver")
                                                        if restart == {}:
                                                            try:
                                                                await self.upgrade_worker_method(service, service,
                                                                                                 self.dockerConnector.remove_container,
                                                                                                 "Filed to remove new resolver.")
                                                                await self.upgrade_worker_method(service,
                                                                                                 "resolver-old",
                                                                                                 self.dockerConnector.rename_container,
                                                                                                 "Filed to remove new resolver.")
                                                            except Exception as e:
                                                                self.logger.warning(
                                                                    "Failure during healtcheck rollback, {}".format(e))
                                                            self.logger.warning(
                                                                        "New resolver is unhealthy, resolving failed")
                                                            status[service] = {"status": "failure",
                                                                               "message": "New resolver is unhealthy, resolving failed",
                                                                               "body": "Resolving healthcheck failed"}
                                                            break
                                                        else:
                                                            status[service]=restart
                                                        # try:
                                                        #     await self.dockerConnector.restart_container(
                                                        #         "{}-old".format(service))  # tries to restart old service
                                                        # except Exception as e:
                                                        #     self.logger.warning("Failed to restart old resolver")
                                                        #     status[service] = {"status": "failure",
                                                        #                        "message": "failed to restart old resolver",
                                                        #                        "body": str(e)}
                                                        # else:
                                                        #     try:
                                                        #         await self.dockerConnector.remove_container(service)
                                                        #     except Exception as e:
                                                        #         self.logger.warning(
                                                        #             "Filed to remove new resolver. {}".format(e))
                                                        #     else:
                                                        #         try:
                                                        #             await self.dockerConnector.rename_container(
                                                        #                 "resolver-old", "resolver")
                                                        #         except Exception as e:
                                                        #             self.logger.warning(
                                                        #                 "Filed to rename old resolver back. {}".format(e))
                                                        #     self.logger.warning(
                                                        #         "New resolver is unhealthy, resolving failed")
                                                        #     status[service] = {"status": "failure",
                                                        #                        "message": "New resolver is unhealthy, resolving failed"}
                                                        #     break
                                            inspect = await self.dockerConnector.inspect_config(service)
                                            if inspect["State"]["Running"] is True:
                                                remove = await self.upgrade_worker_method("{}-old".format(service),
                                                                                          "{}-old".format(service),
                                                                                          self.dockerConnector.remove_container,
                                                                                          "Failed to remove old {}".format(
                                                                                              service))
                                                if remove != {}:
                                                    raise ContainerException(
                                                        "Failed to remove old {}, with error {}".format(service, e))
                                                else:
                                                    break
                                                # try:
                                                #     if "{}-old".format(service) in [container.name for container in
                                                #                                     self.dockerConnector.get_containers(
                                                #                                         stopped=True)]:
                                                #         await self.dockerConnector.remove_container(
                                                #             "{}-old".format(service))  # tries to remove old service
                                                # except Exception as e:
                                                #     raise ContainerException(
                                                #         "Failed to remove old {}, with error {}".format(service, e))
                                                # else:
                                                #     break
                                            else:
                                                await asyncio.sleep(2)
                                    except ContainerException as e:
                                        status[service] = {"status": "failure", "message": "removal of old service",
                                                           "body": str(e)}
                                        self.logger.info(e)
                                        remove = await self.upgrade_worker_method(service, service,
                                                                                  self.dockerConnector.remove_container,
                                                                                    "removal of old and new service")
                                        if remove == {}:
                                            rename = await self.upgrade_worker_method(service,
                                                                                        "{}-old".format(service),
                                                                                      self.dockerConnector.rename_container,
                                                                                        "removal and rename of old agent")
                                            if rename != {}:
                                                status[service] = rename
                                        else:
                                            status[service] = remove

                                        # try:
                                        #     if service in [container.name for container in
                                        #                    self.dockerConnector.get_containers(
                                        #                        stopped=True)]:
                                        #         await self.dockerConnector.remove_container(
                                        #             service)  # tries to remove new service
                                        # except ContainerException as e:
                                        #     status[service] = {"status": "failure",
                                        #                        "message": "removal of old and new service",
                                        #                        "body": str(e)}
                                        #     self.logger.info(e)
                                        # else:
                                        #     try:
                                        #         if "{}-old".format(service) in [container.name for container in
                                        #                                         self.dockerConnector.get_containers(
                                        #                                             stopped=True)]:
                                        #             await self.dockerConnector.rename_container(
                                        #                 "{}-old".format(service), service)  # tries to rename old agent
                                        #     except ContainerException as e:
                                        #         status[service] = {"status": "failure",
                                        #                            "message": "removal and rename of old agent",
                                        #                            "body": str(e)}
                                        #         self.logger.info(e)
                                    else:
                                        if "status" not in status[service]:
                                            status[service]["status"] = "success"
                                            if service == "resolver":
                                                await self.update_cache({})
            try:
                if all(state["status"] == "success" for state in status.values()):
                    result = self.upgrade_save_files(request, decoded_data)
                    if result != {}:
                        status["dump"] = result
            except Exception as e:
                self.logger.warning("Failed to chceck status {}".format(e))
            if "requestId" in response:
                del response["requestId"]
            response["data"] = status
        return response

    def upgrade_save_files(self, request: dict, decoded_data) -> dict:
        try:
            if "compose" in request["data"]:
                self.save_file("compose/docker-compose.yml", "yml", decoded_data)
            if "config" in request["data"]:
                self.save_file("resolver/kres.conf", "text", request["data"]["config"])
        except IOError as e:
            return {"status": "failure", "body": str(e)}
        else:
            return {}

    def upgrade_load_compose(self, request: dict, response: dict):
        if "compose" in request["data"]:
            return request["data"]["compose"]
        else:
            try:
                with open("{}compose/docker-compose.yml".format(self.folder), "r") as compose:
                    return yaml.load(compose)
            except FileNotFoundError:
                del response["requestId"]
                response["data"] = {"status": "failure",
                                    "message": "compose not supplied and local compose not present"}
                return response

    async def upgrade_pull_image(self, name: str):
        try:
            await self.dockerConnector.pull_image(name)  # pulls image before removal, upgrade is instant
        except Exception as e:
            self.logger.info("Failed to pull image before upgrade, {}".format(e))

    async def upgrade_worker_method(self, service: str, name: str, action, error_message: str):
        try:
            if name in [container.name for container in self.dockerConnector.get_containers(stopped=True)]:
                if service != name:
                    await action(name, service)
                else:
                    await action(service)
        except ContainerException as e:
            self.logger.info(e)
            return {"status": "failure", "message": error_message, "body": str(e)}
        else:
            return {}

    async def upgrade_rename_service(self, service: str):
        try:
            if "{}-old".format(service) in [container.name for container in
                                            self.dockerConnector.get_containers(stopped=True)]:
                await self.dockerConnector.remove_container("{}-old".format(service))
                await self.dockerConnector.rename_container(service, "{}-old".format(service))
            else:
                await self.dockerConnector.rename_container(service, "{}-old".format(service))
        except ContainerException as e:
            self.logger.warning("Failed to rename {} service, error {}".format(service, e))
            return {"status": "failure", "message": "rename of new container", "body": str(e)}
        else:
            return "success"

    async def upgrade_start_service(self, service: str, compose: dict, error_message: str= "start of new container"):
        try:
            if service not in [container.name for container in self.dockerConnector.get_containers(stopped=True)]:
                await self.dockerConnector.start_service(compose)  # tries to start new service
            else:
                await self.dockerConnector.remove_container(service)  # deletes orphaned service
                await self.dockerConnector.start_service(compose)  # tries to start new service
        except ContainerException as e:
            self.logger.warning("Failed to create {} service, error {}".format(service, e))
            return {"status": "failure", "message": error_message, "body": str(e)}
        else:
            return "success"

    # async def upgrade_start_container(self, compose: dict): # find usage
    #     try:
    #         await self.dockerConnector.start_service(compose)  # tries to start new container
    #     except ContainerException as e:
    #         self.logger.info(e)
    #         return {"status": "failure", "message": "start of new container", "body": str(e)}
    #     else:
    #         return "success"

    async def rename_container(self, response: dict, request: dict) -> dict:
        status = {}
        for old_name, new_name in request["data"].items():
            status[old_name] = {}
            try:
                await self.dockerConnector.rename_container(old_name, new_name)
            except ContainerException as e:
                status[old_name] = {"status": "failure", "body": str(e)}
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
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        try:
            for container in request["data"]["containers"]:
                status[container] = {}
                try:
                    await self.dockerConnector.stop_container(container)
                except ContainerException as e:
                    status[container] = {"status": "failure", "body": str(e)}
                    self.logger.info(e)
                else:
                    status[container]["status"] = "success"
        except KeyError:
            response["data"] = {"status": "failure", "message": "No containers specified in 'containers' key"}
            return response
        if "requestId" in response:
            del response["requestId"]
        response["data"] = status
        return response

    async def remove_container(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        try:
            for container in request["data"]["containers"]:
                status[container] = {}
                try:
                    await self.dockerConnector.remove_container(container)
                except ContainerException as e:
                    status[container] = {"status": "failure", "body": str(e)}
                    self.logger.info(e)
                else:
                    status[container]["status"] = "success"
        except KeyError:
            response["data"] = {"status": "failure", "message": "No containers specified in 'containers' key"}
            return response
        if "requestId" in response:
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
            response["data"] = {"status": "failure", "body": str(e)}
            self.logger.info(e)
        else:
            response["data"] = {"body": base64.b64encode(logs).decode("utf-8"), "status": "success"}
        return response

    async def firewall_rules(self, response: dict) -> dict:
        try:
            data = self.firewall_connector.active_rules()
        except (ConnectionError, Exception) as e:
            self.logger.info(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            response["data"] = data
        return response

    async def create_rule(self, response: dict, request: dict) -> dict:
        status = {}
        try:
            for rule in request["data"]["rules"]:
                status[rule] = {}
                try:
                    data = self.firewall_connector.create_rule(rule)
                except (ConnectionError, Exception) as e:
                    self.logger.info(e)
                    status[rule] = {"status": "failure", "body": str(e)}
                else:
                    status[rule] = {"status": "success", "rule": data}
        except KeyError:
            response["data"] = {"status": "failure", "message": "No rules specified in 'rules' key."}
            return response
        successful_rules = [rule for rule in status.keys() if status[rule]["status"] == "success"]
        if len(successful_rules) > 0:
            try:
                self.save_file("kres/firewall.conf", "json", successful_rules)
            except IOError as e:
                self.logger.info(e)
                response["data"] = {"status": "failure", "body": str(e)}
        response["data"] = status
        return response

    async def fetch_rule(self, response: dict, request: dict) -> dict:
        try:
            data = self.firewall_connector.fetch_rule_information(request["data"])
        except (ConnectionError, Exception) as e:
            self.logger.info(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            response["data"] = data
        return response

    async def delete_rule(self, response: dict, request: dict) -> dict:
        status = {}
        try:
            for rule in request["data"]["rules_ids"]:
                status[rule] = {}
                try:
                    self.firewall_connector.delete_rule(rule)
                except (ConnectionError, Exception) as e:
                    self.logger.info(e)
                    status[rule] = {"status": "failure", "body": str(e)}
                else:
                    status[rule] = {"status": "success"}
        except KeyError:
            response["data"] = {"status": "failure", "message": "No rules_ids specified in 'rules' key."}
            return response
        response["data"] = status
        return response

    async def modify_rule(self, response: dict, request: dict) -> dict:
        try:
            self.firewall_connector.modify_rule(*request["data"]["rule"])
        except (ConnectionError, Exception) as e:
            self.logger.info(e)
            response["data"] = {"status": "failure", "body": str(e)}
        except KeyError:
            response["data"] = {"status": "failure", "message": "No rule specified in 'rule' key."}
            return response
        else:
            response["data"] = {"status": "success"}
        return response

    async def agent_log_files(self, response: dict) -> dict:
        try:
            files = self.log_reader.list_files()
        except FileNotFoundError as e:
            self.logger.info(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            response["data"] = files
        return response

    async def agent_all_logs(self, response: dict, request: dict) -> dict:
        try:
            lines = self.log_reader.view_log(request["data"])
        except IOError as e:
            self.logger.info(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            response["data"] = lines
        return response

    async def agent_filtered_logs(self, response: dict, request: dict) -> dict:
        try:
            lines = self.log_reader.filter_logs(**request["data"])
        except Exception as e:
            self.logger.info(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            response["data"] = lines
        return response

    async def agent_delete_logs(self, response: dict, request: dict) -> dict:
        status = {}
        try:
            for file in request["data"]["files"]:
                status[file] = {}
                try:
                    self.log_reader.delete_log(file)
                except IOError as e:
                    status[file] = {"status": "failure", "body": str(e)}
                else:
                    status[file] = {"status": "success"}
        except KeyError:
            response["data"] = {"status": "failure", "message": "No files specified in 'files' key."}
            return response
        response["data"] = status
        return response

    async def agent_test_message(self, response: dict) -> dict:
        response["data"] = {"status": "success", "message": "Agent seems ok"}
        return response

    async def update_cache(self, response: dict) -> dict:
        try:
            address = os.environ["KRESMAN_LISTENER"]
        except KeyError:
            address = "http://localhost:8080"
        try:
            msg = requests.get("{}/updatenow".format(address))
        except Exception as e:
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            if msg.ok:
                response["data"] = {"status": "success", "message": "Cache update successful"}
            else:
                response["data"] = {"status": "failure", "message": "Cache update failed"}
        return response

    async def write_config(self, response: dict, request: dict) -> dict:
        write_type = {"base64": "wb", "json": "w", "text": "w"}
        status = {}
        for key, value in request["data"]["config"].items():
            if not os.path.exists("{}/{}".format(self.folder, key)):
                os.mkdir("{}/{}".format(self.folder, key))
            for data in value:
                try:
                    with open("{}/{}/{}".format(self.folder, key, data["path"]), write_type[data["type"]]) as file:
                        if data["type"] == "json":
                            json.dump(data["data"], file)
                        elif data["type"] == "base64":
                            file.write(base64.b64decode(data["data"].encode("utf-8")))
                        else:
                            for line in data["data"]:
                                file.write("{}\n".format(line))
                except Exception as e:
                    status[key] = {"status": "failure", "message": "Failed to dump config", "body": str(e)}
                else:
                    status[key] = {"status": "success", "message": "Config dump successful"}
        response["data"] = status
        return response

    async def whitelist_add(self, response: dict, request: dict) -> dict:
        try:
            response["data"] = request["data"]
        except KeyError as e:
            response["data"] = {"status": "failure", "body": str(e)}
        return response

    async def local_api_check(self, response: dict):
        try:
            port = os.environ["LOCAL_API_PORT"]
        except KeyError:
            port = "8765"
        async with websockets.connect('ws://localhost:{}'.format(port)) as websocket:
            try:
                await websocket.send(json.dumps({"action": "test"}))
                resp = await websocket.recv()
            except Exception as e:
                self.logger.info("Local api healthcheck failed, {}".format(e))
                response["data"] = {"status": "failure", "body": str(e)}
            else:
                if json.loads(resp)["data"]["status"] == "success":
                    response["data"] = {"status": "success", "message": "Local api is up"}
            return response

    def save_file(self, location: str, file_type: str, content):
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
            self.logger.info("Failed to save compose: {}".format(e))
            raise IOError(e)

    def load_file(self, location: str) -> list:
        try:
            with open("{}{}".format(self.folder, location), "r") as file:
                return file.read().splitlines()
        except Exception as e:
            self.logger.info("Failed to load content: {}".format(e))
            raise IOError(e)

    def decode_base64_json(self, message: dict) -> dict:
        if "data" in message:
            if not isinstance(message["data"], dict):
                '''
                 If data field is dict, it arrived from local services and is not encoded in base64
                 Was therefore correctly decoded in process().
                '''
                try:
                    message["data"] = json.loads(base64.b64decode(message["data"].encode("utf-8")).decode("utf-8"))
                except json.JSONDecodeError:
                    message["data"] = self.decode_base64_string(message["data"])
        return message

    def encode_base64_json(self, message: dict) -> dict:
        if "data" in message:
            message["data"] = base64.b64encode(json.dumps(message["data"]).encode("utf-8")).decode("utf-8")
        return message

    def decode_base64_string(self, b64_string: str) -> str:
        return base64.b64decode(b64_string.encode("utf-8")).decode("utf-8")

    def getError(self, message: str, request: dict) -> dict:
        error_response = {}
        if "requestId" in request:
            error_response["requestId"] = request["requestId"]
        if "action" in request:
            error_response["action"] = request["action"]
        if "data" in request:
            error_response["data"] = {"message": message, "body": request["data"]}
        else:
            error_response["data"] = message
        return error_response
