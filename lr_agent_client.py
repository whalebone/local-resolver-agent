import json
import asyncio
import base64
import logging
import socket
import zipfile
import yaml
import os
import uuid
import re
import requests
import websockets

from collections import deque
from shutil import copyfile, copytree, rmtree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from subprocess import call
from datetime import datetime
from logging.handlers import RotatingFileHandler

from dockertools.docker_connector import DockerConnector
from sysinfo.sys_info import SystemInfo
from exception.exc import ContainerException, ComposeException, PongFailedException
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
        self.sysinfo_logger = build_logger("sys_info", "{}logs/".format(self.folder))
        self.async_actions = ["stop", "remove", "create", "upgrade", "datacollect", "updatecache", "suicide"]
        self.error_stash = {}
        if "RPZ_WHITELIST" in os.environ:
            self.microsoft_id = uuid.uuid4()
            self.rpz_period = int(os.environ.get("RPZ_PERIOD", 86400))
            self.last_update = None
        # if "WEBSOCKET_LOGGING" in os.environ:
        self.enable_websocket_log()
        self.alive = int(os.environ.get('KEEP_ALIVE', 10))

    async def listen(self):
        # async for request in self.websocket:
        while True:
            try:
                request = await asyncio.wait_for(self.websocket.recv(), timeout=self.alive)
            except asyncio.TimeoutError:
                try:
                    pong_waiter = await self.websocket.ping()
                    await asyncio.wait_for(pong_waiter, timeout=self.alive)
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                    raise PongFailedException("Failed to receive pong")
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
                        if response["action"] in self.async_actions and response["action"] != "updatecache":
                            self.process_response(response)
                    except Exception as e:
                        self.logger.info("Error during exception persistence, {}".format(e))
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
            sys_info = {"action": "sysinfo",
                        "data": SystemInfo(self.dockerConnector, self.sysinfo_logger, self.error_stash).get_system_info()}
        except Exception as e:
            self.logger.info(e)
            sys_info = {"action": "sysinfo", "data": {"status": "failure", "body": str(e)}}
        self.save_file("sysinfo/metrics.log", "sysinfo", sys_info["data"], "a")
        await self.send(sys_info)

    async def send_acknowledgement(self, message: dict):
        message["data"] = {"status": "success", "message": "Command received"}
        await self.send(message)

    async def validate_host(self):
        if os.path.exists("{}etc/agent/upgrade.json".format(self.folder)):
            with open("{}etc/agent/upgrade.json".format(self.folder), "r") as upgrade:
                request = json.loads(upgrade.read())
            try:
                response = await self.upgrade_container({"action": "upgrade"}, request)
            except Exception as e:
                self.logger.warning("Failed to resume upgrade, {}".format(e))
            else:
                self.logger.info("Done persisted upgrade with response: {}".format(response))
                self.process_response(response)
            self.delete_file("{}etc/agent/upgrade.json".format(self.folder))
        elif not os.path.exists("{}etc/agent/docker-compose.yml".format(self.folder)):
            request = {"action": "request", "data": {"message": "compose missing"}}
            await self.send(request)
        else:
            try:
                with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose:
                    parsed_compose = self.compose_parser.create_service(compose)
                    active_services = [container.name for container in self.dockerConnector.get_containers()]
                    for service, config in parsed_compose["services"].items():
                        if service not in active_services:
                            try:
                                await self.upgrade_start_service(service, config)
                            except Exception as e:
                                self.logger.warning(
                                    "Service: {} is offline, automatic start failed due to: {}".format(service, e))
                                continue
                        if service in self.error_stash:
                            del self.error_stash[service]
            except Exception as e:
                self.logger.warning(e)

    def enable_websocket_log(self):
        logger = logging.getLogger('websockets')
        logger.setLevel(int(os.environ.get("WEBSOCKET_LOGGING", 10)))
        formatter = logging.Formatter('%(asctime)s | %(lineno)d | %(message)s')
        handler = RotatingFileHandler("{}/logs/agent-ws.log".format(self.folder), maxBytes=200000000, backupCount=5)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    def process_response(self, response: dict):
        for service, error_message in response["data"].items():
            if isinstance(error_message, dict):
                if error_message["status"] == "failure":
                    try:
                        self.error_stash[service] = {response["action"]: error_message["body"]}
                    except KeyError:
                        self.error_stash[service].update({response["action"]: error_message["body"]})
                else:
                    if service in self.error_stash and response["action"] in self.error_stash[service]:
                        del self.error_stash[service][response["action"]]
                        if len(self.error_stash[service]) == 0:
                            del self.error_stash[service]

    async def process(self, request_json, cli=False):
        try:
            request = self.decode_base64_json(json.loads(request_json))
        except Exception as e:
            self.logger.info("Failed to parse request: {}, {}".format(e, request_json))
            return {"action": "request",
                    "data": {"status": "failure", "message": "failed to parse/decode request", "body": str(e)}}
        if not cli:
            self.logger.info("Received: {}".format(request))
        response = {}
        if "action" not in request:
            return self.getError('Missing action in request', request)
        if "requestId" in request:
            response["requestId"] = request["requestId"]
        response["action"] = request["action"]

        method_calls = {"sysinfo": self.system_info, "create": self.create_container, "upgrade": self.upgrade_container,
                        "suicide": self.resolver_suicide, "clearcache": self.resolver_cache_clear,
                        # "restart": self.restart_container, "rename": self.rename_container,
                        # "stop": self.stop_container, "remove": self.remove_container,
                        # "fwrules": self.firewall_rules, "fwcreate": self.create_rule, "fwfetch": self.fetch_rule,
                        # "fwmodify": self.modify_rule, "fwdelete": self.delete_rule, "localtest": self.local_api_check,
                        # "logs": self.agent_log_files, "log": self.agent_all_logs, "whitelistadd": self.whitelist_add,
                        # "flog": self.agent_filtered_logs, "dellogs": self.agent_delete_logs,  "saveconfig": self.write_config,
                        # "containerlogs": self.container_logs,
                        "updatecache": self.update_cache, "containers": self.list_containers, "test": self.agent_test_message,
                         "datacollect": self.pack_files, "trace": self.trace_domain}
        method_arguments = {"sysinfo": [response, request], "create": [response, request], "test": [response],
                            "upgrade": [response, request], "suicide": [response], "containers": [response],
                            # "restart": [response, request], "rename": [response, request],
                            # "containerlogs": [response, request], "saveconfig": [response, request],
                            "clearcache": [response, request], "updatecache": [response, request],
                            # "stop": [response, request], "remove": [response, request], "localtest": [response],
                            # "fwrules": [response], "fwcreate": [response, request], "fwfetch": [response, request],
                            # "fwmodify": [response, request], "fwdelete": [response, request],
                            # "logs": [response], "log": [response, request],
                            # "flog": [response, request], "dellogs": [response, request],
                            # "whitelistadd": [response, request],
                            "datacollect": [response, request], "trace": [response, request]}

        if "CONFIRMATION_REQUIRED" in os.environ and request["action"] not in ["updatecache"] and not cli:
            self.persist_request(request)
            response["data"] = {"message": "Request successfully persisted.", "status": "success"}
            return response
        else:
            try:
                return await method_calls[request["action"]](*method_arguments[request["action"]])
            except KeyError as e:
                self.logger.info(e)
                return self.getError('Unknown action', request)

    async def system_info(self, response: dict, request: dict) -> dict:
        try:
            response["data"] = SystemInfo(self.dockerConnector, self.sysinfo_logger, self.error_stash,
                                          request).get_system_info()
        except Exception as e:
            self.logger.info(e)
            self.getError(str(e), request)
        return response

    async def create_container(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        decoded_data = self.upgrade_load_compose(request, response)
        if "status" in decoded_data:
            return decoded_data
        try:
            parsed_compose = self.compose_parser.create_service(decoded_data)
        except ComposeException as e:
            self.logger.warning(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            if "resolver" in parsed_compose["services"]:
                result = self.upgrade_save_files(request, decoded_data, ["compose", "config"])
                if result:
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
                        await self.update_cache()
                        self.prefetch_tld()
            if "requestId" in response:
                del response["requestId"]
            response["data"] = status
        return response

    # async def upgrade_container(self, response: dict, request: dict) -> dict:
    #     sysinfo_connector = SystemInfo(self.dockerConnector, self.sysinfo_logger)
    #     if "cli" not in request:
    #         await self.send_acknowledgement(response)
    #     status = {}
    #     compose = self.upgrade_load_compose(request, response)
    #     if "status" in compose:
    #         return compose
    #     try:
    #         parsed_compose = self.compose_parser.create_service(compose)
    #     except ComposeException as e:
    #         self.logger.warning(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     else:
    #         # if request["data"]["services"]:
    #         services = request["data"]["services"] if request["data"]["services"] else list(parsed_compose["services"])
    #         # else:
    #         #     services = list(parsed_compose["services"].keys())
    #         if "lr-agent" in services and len(services) != 1:
    #             request["data"]["services"] = [service for service in services if service != "lr-agent"]
    #             request["data"]["compose"] = json.dumps({'version': '3', 'services':
    #                 {key: value for key, value in parsed_compose["services"].items() if key != "lr-agent"}})
    #             self.save_file("etc/agent/upgrade.json", "json", request)
    #             services = ["lr-agent"]
    #         if "resolver" in services:
    #             try:
    #                 old_config = self.load_file("etc/kres/kres.conf")
    #             except IOError as e:
    #                 status["load"] = {"status": "failure", "body": str(e)}
    #             result = self.upgrade_save_files(request, compose, ["config"])
    #             if result:
    #                 status["dump"] = result
    #         running_containers = [container.name for container in self.dockerConnector.get_containers()]
    #         if "lr-agent-old" in running_containers and "lr-agent" not in running_containers:
    #             try:
    #                 await self.dockerConnector.rename_container("lr-agent-old", "lr-agent")
    #             except ContainerException as ce:
    #                 return {"status": "failure",
    #                         "message": "agent old running without agent, rename failed, {}".format(ce)}
    #         for service in services:
    #             status[service] = {}
    #             if service not in parsed_compose["services"]:
    #                 status[service] = {"status": "failure", "message": "{} not present in compose".format(service)}
    #                 continue
    #             if service not in ["lr-agent", "resolver"]:
    #                 await self.upgrade_pull_image(parsed_compose["services"][service]['image'])
    #                 remove = await self.upgrade_worker_method(service, self.dockerConnector.remove_container,
    #                                                           "remove old container")
    #                 if not remove:
    #                     start = await self.upgrade_start_service(service, parsed_compose["services"][service])
    #                     if isinstance(start, str):
    #                         status[service]["status"] = start
    #                     else:
    #                         status[service] = start
    #                 else:
    #                     status[service] = remove
    #             else:
    #                 if service == "resolver" and sysinfo_connector.check_port() == "fail":
    #                     remove = await self.upgrade_worker_method(service,  self.dockerConnector.remove_container,
    #                                                               "Failed to remove unhealthy container")
    #                     if not remove:
    #                         start = await self.upgrade_start_service(service, parsed_compose["services"][service],
    #                                                                  "Failed to create new container from unhealthy")
    #                         if start != "success":
    #                             status[service] = start
    #                         else:
    #                             status[service]["status"] = "success"
    #                     else:
    #                         status[service] = remove
    #
    #                 else:
    #                     rename = await self.upgrade_rename_service(service)
    #                     if rename != "success":
    #                         status[service] = rename
    #                     else:
    #                         start = await self.upgrade_start_service(service, parsed_compose["services"][service])
    #                         if start != "success":
    #                             status[service] = start
    #                             rename = await self.upgrade_worker_method("{}-old".format(service), self.dockerConnector.rename_container,
    #                                                                       "rename rollback", service)
    #                             if rename:
    #                                 status[service] = rename
    #                         else:
    #                             try:
    #                                 if service == "resolver":
    #                                     for _ in range(10):
    #                                         if sysinfo_connector.check_port() == "ok" and \
    #                                                 sysinfo_connector.check_port("resolver-old") == "ok":
    #                                             break
    #                                         await asyncio.sleep(1)
    #                                     else:
    #                                         try:
    #                                             self.save_file("etc/kres/kres.conf", "text", old_config)
    #                                         except Exception as e:
    #                                             self.logger.warning("Failed to back up to old config".format(e))
    #                                         raise ContainerException("New resolver is not healthy rollback")
    #                                     stop = await self.upgrade_worker_method("resolver-old",
    #                                                                             self.dockerConnector.stop_container,
    #                                                                             "Failed to stop old resolver")
    #                                     if stop:
    #                                         raise ContainerException("Failed to stop old resolver")
    #                                     else:
    #                                         if sysinfo_connector.check_resolving() == "fail":
    #                                             try:
    #                                                 self.save_file("etc/kres/kres.conf", "text", old_config)
    #                                             except Exception as e:
    #                                                 self.logger.warning("Failed to back up to old config".format(e))
    #                                             restart = await self.upgrade_worker_method("resolver-old",
    #                                                                                        self.dockerConnector.restart_container,
    #                                                                                        "failed to restart old resolver")
    #                                             if not restart:
    #                                                 try:
    #                                                     await self.upgrade_worker_method(service,
    #                                                                                      self.dockerConnector.remove_container,
    #                                                                                      "Filed to remove new resolver.")
    #                                                     await self.upgrade_worker_method("resolver-old",
    #                                                                                      self.dockerConnector.rename_container,
    #                                                                                      "Filed to remove new resolver.",
    #                                                                                      service)
    #                                                 except Exception as e:
    #                                                     self.logger.warning(
    #                                                         "Failure during healthcheck rollback, {}".format(e))
    #                                                 self.logger.warning(
    #                                                     "New resolver is unhealthy, resolving failed")
    #                                                 status[service] = {"status": "failure",
    #                                                                    "message": "New resolver is unhealthy, resolving failed",
    #                                                                    "body": "Resolving healthcheck failed"}
    #                                             else:
    #                                                 status[service] = restart
    #                                 inspect = self.dockerConnector.inspect_config(service)
    #                                 if inspect["State"]["Running"] is True:
    #                                     remove = await self.upgrade_worker_method("{}-old".format(service),
    #                                                                               self.dockerConnector.remove_container,
    #                                                                               "Failed to remove old {}".format(
    #                                                                                   service))
    #                                     if remove:
    #                                         raise ContainerException(
    #                                             "Failed to remove old {}, with error {}".format(service, e))
    #
    #                                 else:
    #                                     raise ContainerException("New {} is not running".format(service))
    #                             except ContainerException as e:
    #                                 status[service] = {"status": "failure", "message": "removal of old service",
    #                                                    "body": str(e)}
    #                                 self.logger.info(e)
    #                                 remove = await self.upgrade_worker_method(service, self.dockerConnector.remove_container,
    #                                                                           "removal of old and new service")
    #                                 if not remove:
    #                                     rename = await self.upgrade_worker_method("{}-old".format(service), self.dockerConnector.rename_container,
    #                                                                               "removal and rename of old agent",
    #                                                                               service)
    #                                     if rename:
    #                                         status[service] = rename
    #                                 else:
    #                                     status[service] = remove
    #
    #                             else:
    #                                 if "status" not in status[service]:
    #                                     status[service]["status"] = "success"
    #                                     if service == "resolver":
    #                                         await self.update_cache()
    #         try:
    #             if all(state["status"] == "success" for state in status.values()):
    #                 result = self.upgrade_save_files(request, compose, ["compose"])
    #                 if result:
    #                     status["dump"] = result
    #         except Exception as e:
    #             self.logger.warning("Failed to check status {}".format(e))
    #         if "requestId" in response:
    #             del response["requestId"]
    #         response["data"] = status
    #     return response

    async def upgrade_container(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        compose = self.upgrade_load_compose(request, response)
        if "status" in compose:
            return compose
        try:
            parsed_compose = self.compose_parser.create_service(compose)
        except ComposeException as e:
            self.logger.warning("Failed to create services from parsed compose, {}".format(e))
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            services = request["data"]["services"] if request["data"]["services"] else list(parsed_compose["services"])
            if self.upgrade_check_multi_upgrade(services, request, parsed_compose):
                services = ["lr-agent"]
            if "resolver" in services:
                try:
                    old_config = self.upgrade_load_config(request, compose)
                except Exception as e:
                    status.update({"config dump": str(e)})
            else:
                old_config = None
            try:
                await self.upgrade_check_incorrect_name()
            except ContainerException as ce:
                return {"status": "failure",
                        "message": "agent old running without agent, rename failed, {}".format(ce)}
            for service in services:
                if service not in parsed_compose["services"]:
                    status[service] = {"status": "failure", "message": "{} not present in compose".format(service)}
                    continue
                if service not in ["lr-agent", "resolver"]:
                    status[service] = await self.upgrade_with_downtime(parsed_compose, service)
                else:
                    status[service] = await self.upgrade_without_downtime(service, parsed_compose, old_config)
            try:
                self.upgrade_persist_compose(status, request, compose)
            except Exception as de:
                status["dump"] = de
            if "requestId" in response:
                del response["requestId"]
            response["data"] = status
        return response

    async def upgrade_with_downtime(self, parsed_compose: dict, service: str) -> dict:
        await self.upgrade_pull_image(parsed_compose["services"][service]['image'])
        try:
            await self.upgrade_worker_method(service, self.dockerConnector.remove_container)
        except Exception as e:
            return {"status": "failure", "message": "failed to remove old {}".format(service), "body": str(e)}
        else:
            try:
                await self.upgrade_start_service(service, parsed_compose["services"][service])
            except Exception as se:
                return {"status": "failure", "message": "failed to start new {}".format(service), "body": str(se)}
            else:
                return {"status": "success"}

    def upgrade_load_config(self, request: dict, compose: dict):
        try:
            old_config = self.load_file("etc/kres/kres.conf")
        except IOError as e:
            raise Exception(e)
        else:
            self.upgrade_save_files(request, compose, ["config"])
            return old_config

    def upgrade_check_multi_upgrade(self, services: list, request: dict, parsed_compose: dict) -> bool:
        if "lr-agent" in services and len(services) != 1:
            request["data"]["services"] = [service for service in services if service != "lr-agent"]
            request["data"]["compose"] = json.dumps({'version': '3', 'services':
                {key: value for key, value in parsed_compose["services"].items() if key != "lr-agent"}})
            self.save_file("etc/agent/upgrade.json", "json", request)
            return True
        return False

    def upgrade_persist_compose(self, status: dict, request: dict, compose: dict):
        try:
            if all(state["status"] == "success" for state in status.values()):
                self.upgrade_save_files(request, compose, ["compose"])
        except Exception as e:
            self.logger.warning("There was an error in compose persistence {}".format(e))
            raise Exception(e)

    async def upgrade_check_incorrect_name(self):
        running_containers = [container.name for container in self.dockerConnector.get_containers()]
        if "lr-agent-old" in running_containers and "lr-agent" not in running_containers:
            # try:
            await self.dockerConnector.rename_container("lr-agent-old", "lr-agent")
            # except ContainerException as ce:
            #     return {"status": "failure",
            #             "message": "agent old running without agent, rename failed, {}".format(ce)}

    def upgrade_return_config(self, old_config: list):
        try:
            self.save_file("etc/kres/kres.conf", "text", old_config)
        except Exception as e:
            self.logger.warning("Failed to back up to old config".format(e))

    async def dump_resolver_logs(self):
        try:
            logs = self.dockerConnector.container_logs("resolver", tail=1000)
            self.save_file("logs/resolver_dump.logs", "text", logs)
        except ConnectionError as ce:
            self.logger.warning("Failed to get logs of new unhealthy resolver, {}.".format(ce))
        except IOError as ie:
            self.logger.warning("Failed to persist logs of new unhealthy resolver, {}.".format(ie))

    async def upgrade_check_binding(self, sysinfo_connector, old_config: list):
        for _ in range(10):
            if sysinfo_connector.check_port() == "ok" and sysinfo_connector.check_port("resolver-old") == "ok":
                return True
            await asyncio.sleep(1)
        await self.dump_resolver_logs()
        self.upgrade_return_config(old_config)
        return False

    async def upgrade_translation_fallback(self, service: str, old_config: list):
        await self.dump_resolver_logs()
        self.upgrade_return_config(old_config)
        restart = await self.upgrade_worker_method("resolver-old", self.dockerConnector.restart_container,
                                                   "failed to restart old resolver")
        if not restart:
            try:
                await self.upgrade_worker_method(service, self.dockerConnector.remove_container,
                                                 "Filed to remove new resolver.")
                await self.upgrade_worker_method("resolver-old", self.dockerConnector.rename_container,
                                                 "Filed to remove new resolver.", service)
            except Exception as e:
                self.logger.warning("Failure during healthcheck rollback, {}".format(e))
            self.logger.warning("New resolver is unhealthy, resolving failed")
            return {"status": "failure", "message": "New resolver is unhealthy, resolving failed",
                    "body": "Resolving healthcheck failed"}
        else:
            return restart

    async def upgrade_container_fallback(self, service: str) -> dict:
        try:
            await self.upgrade_worker_method(service, self.dockerConnector.remove_container)
        except Exception as re:
            return {"status": "failure", "message": "failed to remove new {}".format(service), "body": str(re)}
        else:
            try:
                await self.upgrade_worker_method("{}-old".format(service), self.dockerConnector.rename_container,
                                                 name=service)
            except Exception as rn:
                return {"status": "failure", "message": "failed to rename old {}".format(service), "body": str(rn)}

    async def upgrade_replace_unhealthy_resolver(self, service: str, parsed_compose: dict):
        try:
            await self.upgrade_worker_method(service, self.dockerConnector.remove_container)
        except Exception as re:
            return self.upgrade_get_error_message("failed to remove unhealthy {}".format(service), re)
        else:
            try:
                await self.upgrade_start_service(service, parsed_compose["services"][service])
            except Exception as se:
                return self.upgrade_get_error_message("failed to create new {} from unhealthy".format(service), se)
            else:
                return {"status": "success"}

    async def upgrade_check_resolver_resolving(self, sysinfo_connector, old_config: list, service: str) -> dict:
        if not await self.upgrade_check_binding(sysinfo_connector, old_config):
            raise ContainerException("New resolver is not healthy due to port not bound, rollback")
        try:
            await self.upgrade_worker_method("resolver-old", self.dockerConnector.stop_container)
        except Exception as se:
            raise ContainerException("Failed to stop old resolver, {}".format(se))
        else:
            if sysinfo_connector.check_resolving() == "fail":
                return await self.upgrade_translation_fallback(service, old_config)

    def upgrade_check_service_state(self, service: str) -> bool:
        try:
            return True if self.dockerConnector.inspect_config(service)["State"]["Running"] else False
        except Exception:
            return False

    def upgrade_get_error_message(self, message: str, exception):
        return {"status": "failure", "message": message, "body": str(exception)}

    async def upgrade_without_downtime(self, service: str, parsed_compose: dict, old_config: list=None) -> dict:
        sysinfo_connector = SystemInfo(self.dockerConnector, self.sysinfo_logger)
        if service == "resolver" and sysinfo_connector.check_port() == "fail":
            return await self.upgrade_replace_unhealthy_resolver(service, parsed_compose)
        else:
            try:
                await self.upgrade_rename_service(service)
            except Exception as or_re:
                return self.upgrade_get_error_message("failed to rename old {}".format(service), or_re)
            else:
                try:
                    await self.upgrade_start_service(service, parsed_compose["services"][service])
                except Exception as se:
                    try:
                        await self.upgrade_worker_method("{}-old".format(service), self.dockerConnector.rename_container,
                                                              name=service)
                    except Exception as ren:
                        return self.upgrade_get_error_message("failed to rollback name for {}".format(service), ren)
                    else:
                        return self.upgrade_get_error_message("failed to start new service {}".format(service), se)
                else:
                    try:
                        if service == "resolver":
                            status = await self.upgrade_check_resolver_resolving(sysinfo_connector, old_config, service)
                            if status:
                                return status
                        if self.upgrade_check_service_state(service):
                            try:
                                await self.upgrade_worker_method("{}-old".format(service),
                                                                 self.dockerConnector.remove_container)
                            except Exception as ree:
                                raise ContainerException("Failed to remove old {}, with error {}".format(service, ree))
                        else:
                            raise ContainerException("New {} is not running".format(service))
                    except ContainerException as e:
                        self.logger.info(e)
                        error = await self.upgrade_container_fallback(service)
                        if error:
                            return error
                        else:
                            return self.upgrade_get_error_message("failed the removal of old {}".format(service), e)
                    else:
                        if service == "resolver":
                            await self.update_cache()
                            self.prefetch_tld()
                        return {"status": "success"}

    def upgrade_save_files(self, request: dict, decoded_data, keys: list) -> dict:
        try:
            if "compose" in keys and "compose" in request["data"]:
                self.save_file("etc/agent/docker-compose.yml", "yml", decoded_data)
            if "config" in keys and "config" in request["data"]:
                self.save_file("etc/kres/kres.conf", "text", request["data"]["config"])
        except IOError as e:
            raise Exception(e)
            # return {"status": "failure", "body": str(e)}
        # else:
        #     return {}

    def upgrade_load_compose(self, request: dict, response: dict):
        if "compose" in request["data"]:
            return request["data"]["compose"]
        else:
            try:
                with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose:
                    return compose.read()
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

    async def upgrade_worker_method(self, service: str, action, error_message: str="", name: str = None):
        try:
            if service in [container.name for container in self.dockerConnector.get_containers(stopped=True)]:
                if name:
                    await action(service, name)
                else:
                    await action(service)
        except ContainerException as e:
            self.logger.info("Failed to execute action {} for service {} due to {}".format(action, service, e))
            # return {"status": "failure", "message": error_message, "body": str(e)}
            raise Exception(e)

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
            # return {"status": "failure", "message": "rename of new container", "body": str(e)}
            raise Exception(e)
        else:
            return "success"

    async def upgrade_start_service(self, service: str, compose: dict, error_message: str = "start of new container"):
        try:
            if service not in [container.name for container in self.dockerConnector.get_containers(stopped=True)]:
                await self.dockerConnector.start_service(compose)  # tries to start new service
            else:
                await self.dockerConnector.remove_container(service)  # deletes orphaned service
                await self.dockerConnector.start_service(compose)  # tries to start new service
        except ContainerException as e:
            self.logger.warning("Failed to create {} service, error {}".format(service, e))
            # return {"status": "failure", "message": error_message, "body": str(e)}
            raise Exception(e)
        else:
            return "success"

    # def upgrade_agent_persistence(self, compose: dict, request: dict, services: list):
    #     try:
    #         backed_compose, backed_services = {}.update(compose), [].extend(services)
    #         del backed_compose["services"]["lr-agent"]
    #         backed_services.remove("lr-agent")
    #         request["data"]["services"] = backed_services
    #         request["data"]["compose"] = json.dumps(backed_compose)
    #     except IOError as ie:
    #         self.logger.warning("Failed to persist upgrade request, {}".format(ie))
    #     except KeyError as ke:
    #         self.logger.warning("Unexpected exception during upgrade persistence: {}".format(ke))
    #     else:
    #         self.save_file("etc/agent/upgrade.json".format(self.folder), "json", request)

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

    # async def container_action(self, response: dict, request: dict, action) -> dict:
    #     if "cli" not in request:
    #         await self.send_acknowledgement(response)
    #     status = {}
    #     try:
    #         for container in request["data"]["containers"]:
    #             status[container] = {}
    #             try:
    #                 await self.dockerConnector.restart_container(container)
    #             except ContainerException as e:
    #                 status[container] = {"status": "failure", "body": str(e)}
    #                 self.logger.info(e)
    #             else:
    #                 status[container]["status"] = "success"
    #     except KeyError:
    #         response["data"] = {"status": "failure", "message": "No containers specified in 'containers' key"}
    #         return response
    #     if "requestId" in response:
    #         del response["requestId"]
    #     response["data"] = status
    #     return response

    async def restart_container(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        status = {}
        try:
            for container in request["data"]["containers"]:
                status[container] = {}
                try:
                    await self.dockerConnector.restart_container(container)
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

    def check_rpz_file(self, path: str) -> bool:
        pattern = re.compile(
            "^(\*[\.-]?)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\s+CNAME\s+\.$")
        with open(path, "r") as file:
            try:
                for line in file:
                    if not pattern.match(line.strip()):
                        return False
            except Exception as e:
                self.logger.warning("Failed to validate file {}, {}.".format(path, e))
        return True

    def get_office365_domains(self):
        try:
            req = requests.get(
                "https://endpoints.office.com/endpoints/worldwide?clientrequestid={}".format(self.microsoft_id))
        except requests.RequestException as re:
            self.logger.warning("Request to microsoft service failed, {}.".format(re))
        else:
            domains = set()
            for block in req.json():
                if "urls" in block:
                    domains.update(block["urls"])
            return domains

    async def create_office365_rpz(self):
        if "RPZ_WHITELIST" in os.environ:
            if not self.last_update or (datetime.now() - self.last_update).seconds >= self.rpz_period:
                try:
                    data = self.get_office365_domains()
                except Exception as e:
                    self.logger.warning("Failed to get data from Microsoft list, {}.".format(e))
                else:
                    if data:
                        try:
                            with open("{}etc/kres/temporary.rpz".format(self.folder), "w") as file:
                                # for text in ["$ORIGIN whalebone.org.", "$TTL 1H",
                                #              "@ SOA LOCALHOST. rpz.whalebone.org. (1 1h 15m 30d 2h)", "\tNS LOCALHOST."]:
                                #     file.write("{}\n".format(text))
                                for domain in data:
                                    file.write("{}\tCNAME\t.\n".format(domain))
                            if self.check_rpz_file("{}etc/kres/temporary.rpz".format(self.folder)):
                                self.delete_file("{}etc/kres/office365.rpz".format(self.folder))
                                os.rename("{}etc/kres/temporary.rpz".format(self.folder),
                                          "{}etc/kres/office365.rpz".format(self.folder))
                        except Exception as e:
                            self.logger.warning("Failed to finish office365 rpz operation, {}.".format(e))
                        else:
                            self.logger.info(
                                "Rpz file updated with total {} records, next upgrade in {} seconds.".format(len(data),
                                                                                                     self.rpz_period))
                            self.last_update = datetime.now()
                    else:
                        self.logger.warning("No data present in Microsoft domains list.")

    def prefetch_tld(self):
        message = b"prefill.config({['.'] = { url = 'https://www.internic.net/domain/root.zone', interval = 86400 }})"
        for tty in os.listdir("/etc/whalebone/tty/"):
            try:
                self.send_to_socket(message, tty)
            except Exception:
                self.logger.warning("Failed to send prefetch data to socket")
            else:
                self.logger.info("Tlds successfully pre fetched.")
                break

    async def update_cache(self, response: dict = None, request: dict = None) -> dict:
        if request and "cli" not in request:
            await self.send_acknowledgement(response)
        address = os.environ.get("KRESMAN_LISTENER", "http://127.0.0.1:8080")
        try:
            # msg = requests.get("{}/updatenow".format(address), json={}, timeout=int(os.environ.get("HTTP_TIMEOUT", 10)))
            msg = requests.get("{}/updatenow".format(address), json={})
        except requests.exceptions.RequestException as e:
            if response:
                response["data"] = {"status": "failure", "body": str(e)}
        else:
            if response:
                if msg.ok:
                    response["data"] = {"status": "success", "message": "Cache update successful"}
                else:
                    response["data"] = {"status": "failure", "message": "Cache update failed"}
        return response

    async def trace_domain(self, response: dict, request: dict):
        try:
            address = os.environ["TRACE_LISTENER"]
        except KeyError:
            address = "http://127.0.0.1:8453"
        query_type = request["data"]["type"] if "type" in request["data"] else ""
        try:
            msg = requests.get("{}/trace/{}/{}".format(address, request["data"]["domain"], query_type),
                               timeout=int(os.environ.get("HTTP_TIMEOUT", 10)))
        except requests.exceptions.RequestException as e:
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            if msg.ok:
                response["data"] = {"status": "success", "trace": msg.content.decode("utf-8")}
            else:
                response["data"] = {"status": "failure", "message": "Trace failed",
                                    "error": msg.content.decode("utf-8")}
        return response

    async def resolver_cache_clear(self, response: dict, request: dict):
        for tty in os.listdir("/etc/whalebone/tty/"):
            message = "cache.clear()" if request["data"]["clear"] == "all" else "cache.clear('{}', true)".format(
                request["data"]["clear"])
            try:
                self.send_to_socket(message.encode("utf-8"), tty)
            except Exception:
                response["data"] = {"status": "failure"}
            else:
                response["data"] = {"status": "success"}
            return response

    def send_to_socket(self, message: bytes, tty):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect("/etc/whalebone/tty/{}".format(tty))
        except socket.timeout as te:
            self.logger.warning("Timeout of socket {} reading, {}".format(tty, te))
        except socket.error as msg:
            self.logger.warning("Connection error {} to socket {}".format(msg, tty))
        else:
            try:
                sock.sendall(message)
                return
            except socket.timeout as re:
                self.logger.warning("Failed to get data from socket {}, {}".format(tty, re))
            except Exception as e:
                self.logger.warning("Failed to get data from {}, {}".format(tty, e))
            finally:
                sock.close()
        raise Exception

    async def resolver_suicide(self, response: dict):
        await self.send_acknowledgement(response)
        status = {}
        for action in [self.suicide_delete_certs, self.suicide_modify_compose, self.suicide_delete_containers]:
            try:
                if action.__name__ != "suicide_delete_containers":
                    await action()
                else:
                    await action(status)
            except Exception as e:
                self.logger.warning("Failed to execute suicide action {}, {}.".format(action.__name__, e))
                status[action.__name__] = {"status": "failure", "error": str(e)}
            else:
                status[action.__name__] = "success"
        self.logger.warning("Failed tp finish suicide: {}".format(status))

    async def suicide_delete_certs(self):
        for file_name in ["wb_client.crt", "wb_client.key"]:
            self.delete_file("{}etc/{}".format(self.folder, file_name))

    async def suicide_modify_compose(self):
        env_config = {"kresman": ["CLIENT_CRT_BASE64", "CLIENT_KEY_BASE64", "CA_CRT_BASE64", "CORE_URL"],
                      "lr-agent": ["CLIENT_CRT_BASE64", "CLIENT_KEY_BASE64", "PROXY_ADDRESS"]}
        with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose:
            parsed_compose = self.compose_parser.create_service(compose)
            try:
                del parsed_compose["services"]["logstream"]
            except KeyError:
                self.logger.warning("Logstream not found in compose")
            for name, envs in env_config.items():
                for env in envs:
                    try:
                        parsed_compose["services"][name]["environment"][env] = "some string"
                    except KeyError as ke:
                        self.logger.warning("Failed to alter variable {} for {}, key {} is missing".format(env, name, ke))
            await self.upgrade_container({},
                                         {"data": {"services": ["kresman"], "compose": yaml.dump(parsed_compose)},
                                          "cli": "true"})

    async def suicide_delete_containers(self, status: dict):
        for name in ["logstream", "lr-agent"]:
            if name == "lr-agent":
                try:
                    await self.send({"action": "suicide", "status": status,
                                     "message": "All those moments will be lost in time, like tears in rain. Time to die."})
                except Exception as e:
                    self.logger.info("Failed to acknowledge suicide, {}.".format(e))
            await self.remove_container({}, {"data": {"containers": [name]}, "cli": "true"})

    async def pack_files(self, response: dict, request: dict) -> dict:
        if "cli" not in request:
            await self.send_acknowledgement(response)
        folder = "{}{}".format(self.folder, "temp")
        try:
            os.mkdir(folder)
        except FileExistsError:
            rmtree(folder)
            os.mkdir(folder)
        self.gather_static_files(folder)
        customer_id, resolver_id = self.create_client_ids()

        logs_zip = "/opt/whalebone/{}-{}-{}-wblogs.zip".format(customer_id,
                                                               datetime.now().strftime("%Y-%m-%d_%H:%M:%S"),
                                                               resolver_id)
        self.pack_logs(logs_zip, folder)
        try:
            files = {'upload_file': open(logs_zip, 'rb')}
            req = requests.post("https://transfer.whalebone.io", files=files)
        except Exception as e:
            self.logger.info("Failed to send files to transfer.whalebone.io, {}".format(e))
            response["data"] = {"status": "failure", "message": "Data upload failed", "body": str(e)}
        else:
            if req.ok:
                try:
                    requests.post(request["data"],
                                  json={"text": "New customer log archive was uploaded:\n{}".format(
                                      req.content.decode("utf-8"))}, timeout=int(os.environ.get("HTTP_TIMEOUT", 10)))
                except Exception as e:
                    self.logger.info("Failed to send notification to Slack, {}".format(e))
                else:
                    response["data"] = {"status": "success", "message": "Data uploaded"}
        try:
            rmtree(folder)
        except Exception:
            pass
        if "requestId" in response:
            del response["requestId"]
        return response

    def gather_static_files(self, folder: str):
        actions = {"release": {"action": "copy_file", "command": ("/etc/os-release", "{}/release".format(folder))},
                   "etc": {"action": "copy_dir", "command": ("/opt/host/etc/whalebone/", "{}/etc".format(folder))},
                   "log": {"action": "copy_dir", "command": ("/opt/host/var/log/whalebone/", "{}/logs".format(folder))},
                   "agent_log": {"action": "copy_dir",
                                 "command": ("/etc/whalebone/logs/", "{}/agent-logs".format(folder))},
                   "syslog": {"action": "copy_file",
                              "command": ("/opt/host/var/log/syslog", "{}/syslog".format(folder))},
                   "list": {"action": "list", "command": ["ls", "-lh", "/opt/host/opt/whalebone/"],
                            "path": "{}/ls_opt".format(folder)},
                   "df": {"action": "list", "command": ["df", "-h"], "path": "{}/df".format(folder)},
                   "netstat": {"action": "list", "command": ["netstat", "-tupan"], "path": "{}/netstat".format(folder)},
                   "ip": {"action": "list", "command": ["ifconfig"], "path": "{}/ifconfig".format(folder)},
                   "docker_logs": {"action": "list", "command": ["journalctl", "-u", "docker.service"],
                                   "path": "{}/docker.service".format(folder)},
                   "ps": {"action": "list", "command": ["ps", "-aux"], "path": "{}/ps".format(folder)},
                   "list_containers": {"action": "docker", "command": self.docker_ps(),
                                       "path": "{}/docker_ps".format(folder)},
                   }
        with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose:
            parsed_compose = self.compose_parser.create_service(yaml.load(compose, Loader=yaml.SafeLoader))
            for service in parsed_compose["services"]:
                try:
                    actions["{}_service".format(service)] = {"action": "docker",
                                                             "command": self.dockerConnector.container_logs(service,
                                                                                                            tail=1000).decode(
                                                                 "utf-8"),
                                                             "path": "{}/docker.{}.logs".format(folder, service)}
                    actions["{}_inspect".format(service)] = {"action": "docker",
                                                             "command": json.dumps(
                                                                 self.dockerConnector.inspect_config(service)),
                                                             "path": "{}/docker.{}.inspect".format(folder, service)}
                except Exception as e:
                    self.logger.info("Service {} not found, {}".format(service, e))

        for action, specification in actions.items():
            try:
                if specification["action"] == "copy_file":
                    copyfile(*specification["command"])
                elif specification["action"] == "copy_dir":
                    copytree(*specification["command"])
                elif specification["action"] == "docker":
                    with open(specification["path"], "w") as file:
                        file.write(specification["command"])
                else:
                    with open(specification["path"], "w") as file:
                        call(specification["command"], stdout=file)
            except Exception as e:
                self.logger.info("Failed to perform pack of {} action, {}".format(action, e))

    def create_client_ids(self):
        customer_id, resolver_id = "unknown", "unknown"
        try:
            with open("/opt/whalebone/certs/client.crt", "r") as file:
                cert = x509.load_pem_x509_certificate(file.read().encode("utf-8"), default_backend())
        except FileNotFoundError as e:
            self.logger.info("Failed to load cert {}".format(e))
        else:
            try:
                customer_id = cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
                resolver_id = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception as err:
                self.logger.info("Failed to get cert parameterers, error: {}".format(err))
        return customer_id, resolver_id

    def pack_logs(self, logs_zip: str, folder: str):
        try:
            zip_file = zipfile.ZipFile(logs_zip, "w", zipfile.ZIP_DEFLATED)
        except zipfile.BadZipFile as ze:
            self.logger.info("Error when creating zip file")
        else:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    if os.path.getsize(os.path.join(root, file)) >= 20000000:
                        try:
                            self.tail_file(os.path.join(root, file), 2000)
                        except Exception:
                            pass
                    if os.path.exists(os.path.join(root, file)):
                        zip_file.write(os.path.join(root, file))
            zip_file.close()

    def persist_request(self, request: dict):
        if not os.path.exists("{}/requests".format(self.folder)):
            os.mkdir("{}/requests".format(self.folder))
        with open("{}/requests/requests.json".format(self.folder), "w") as file:
            json.dump(request, file)

    def tail_file(self, path: str, tail_size: int, repeated=None):
        try:
            with open(path + "_new", "w") as resized_output:
                for line in deque(open(path, encoding="utf-8"), tail_size):
                    resized_output.write(line)
        except UnicodeDecodeError:
            repeated = "fail"
        except Exception as e:
            self.logger.info("Failed to resize file {} due to error {}".format(path, e))
            if repeated is not None:
                self.tail_file(path, 10, True)
            else:
                repeated = "fail"
        finally:
            try:
                self.delete_file(path)
                if not isinstance(repeated, str):
                    os.rename(path + "_new", path)
                else:
                    self.delete_file(path + "_new")
            except Exception:
                pass

    def delete_file(self, path: str):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            raise

    def docker_ps(self) -> str:
        result = []
        try:
            for container in [container for container in self.dockerConnector.get_containers(stopped=True)]:
                result.append("{} {} {}\n".format(container.image.tags[0], container.status, container.name))
        except Exception as e:
            self.logger.info("Failed to acquire docker ps info, {}".format(e))
        return "".join(result)

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

    def save_file(self, location: str, file_type: str, content, mode: str = "w"):
        try:
            self.create_required_directory(location)
            with open("{}{}".format(self.folder, location), mode) as file:
                if file_type == "yml":
                    if isinstance(content, str):
                        content = yaml.load(content, Loader=yaml.SafeLoader)
                    yaml.dump(content, file, default_flow_style=False)
                elif file_type == "json":
                    json.dump(content, file)
                elif file_type == "sysinfo":
                    file.write("{}\n".format(json.dumps(content)))
                elif file_type == "text":
                    file.write(content)
                else:
                    for rule in content:
                        file.write(rule + "\n")
        except Exception as e:
            self.logger.info("Failed to save file: {}".format(e))
            raise IOError(e)

    def create_required_directory(self, name: str):
        if "/" in name:
            path = "/".join(name.split("/")[:-1])
            os.makedirs("{}{}".format(self.folder, path), exist_ok=True)

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
