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
import aiohttp
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from aiodocker import Docker
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
# from loggingtools.log_reader import LogReader
# from resolvertools.resolver_connector import FirewallConnector


class LRAgentClient:

    def __init__(self, websocket, cli: bool = False):
        self.websocket = websocket
        self.dockerConnector = DockerConnector()
        self.compose_parser = ComposeParser()
        # self.firewall_connector = FirewallConnector()
        # self.log_reader = LogReader()
        self.folder = "/etc/whalebone/"
        self.logger = build_logger("lr-agent", "{}logs/".format(self.folder))
        self.status_log = build_logger("status", "{}logs/".format(self.folder), file_size=10000000, backup_count=2,
                                       console_output=False)
        self.sysinfo_logger = build_logger("sys_info", "{}logs/".format(self.folder))
        self.async_actions = ("stop", "remove", "create", "upgrade", "datacollect", "updatecache", "suicide")
        self.error_stash = {}
        if "RPZ_WHITELIST" in os.environ:
            self.microsoft_id = uuid.uuid4()
            self.rpz_period = int(os.environ.get("RPZ_PERIOD", 86400))
            self.last_update = None
        # if "WEBSOCKET_LOGGING" in os.environ:
        self.enable_websocket_log()
        self.cli = cli
        self.alive = int(os.environ.get('KEEP_ALIVE', 10))
        # self.kresman_token = self.get_kresman_credentials()
        # self.sysinfo_connector = SystemInfo(self.dockerConnector, self.sysinfo_logger, self.kresman_token)
        self.sysinfo_connector = SystemInfo(self.dockerConnector, self.sysinfo_logger)

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
                    status, parsed_request = await self.process(request)
                except Exception as e:
                    status, parsed_request = {"status": "failure", "body": str(e)}, json.loads(request)
                    self.logger.warning("Failed to get action response {}.".format(e))
                else:
                    try:
                        if parsed_request["action"] in self.async_actions and parsed_request["action"] != "updatecache":
                            self.process_response(status, parsed_request["action"])
                    except Exception as e:
                        self.logger.info("Error during exception persistence, {}".format(e))
                await self.send(self.prepare_response(status, parsed_request))

    async def send(self, message: dict):
        try:
            message = self.encode_request(message)
        except Exception as e:
            self.logger.warning(e)
        else:
            if message["action"] != "sysinfo":
                self.logger.info("Sending: {}".format(message))
            await self.websocket.send(json.dumps(message))

    async def send_sys_info(self):
        try:
            sys_info = {"action": "sysinfo", "data": self.sysinfo_connector.get_system_info(self.error_stash)}
        except Exception as e:
            self.logger.info("Failed to get periodic system info {}.".format(e))
            sys_info = {"action": "sysinfo", "data": {"status": "failure", "body": str(e)}}
        self.save_file("sysinfo/metrics.log", "sysinfo", sys_info["data"], "a")
        await self.send(sys_info)

    def prepare_response(self, status: dict, request: dict) -> dict:
        status = status if status else {"Action finished with unknown issue, no status returned"}
        response = {"action": request.get("action", "unknown"),
                    "data": {"action_status": status, "uid": request["data"].get("uid", "")}}
        if "requestId" in request and request["action"] not in self.async_actions:
            response["requestId"] = request["requestId"]
        return response

    async def send_acknowledgement(self, message: dict):
        message["data"] = {"status": "success", "message": "Command received"}
        await self.send(message)

    async def validate_host(self):
        if os.path.exists("{}etc/agent/upgrade.json".format(self.folder)):
            await self.perform_persisted_upgrade()
        elif not os.path.exists("{}etc/agent/docker-compose.yml".format(self.folder)):
            await self.send({"action": "request", "data": {"message": "compose missing"}})
        else:
            await self.check_running_services()

    async def perform_persisted_upgrade(self):
        with open("{}etc/agent/upgrade.json".format(self.folder), "r") as upgrade:
            request = json.load(upgrade)
        try:
            status = await self.upgrade_container(**request["data"])
        except Exception as e:
            self.logger.warning("Failed to resume upgrade, {}".format(e))
        else:
            self.logger.info("Done persisted upgrade with response: {}".format(status))
            self.process_response(status, "upgrade")
            await self.send(self.prepare_response(status, request))
        self.delete_file("{}etc/agent/upgrade.json".format(self.folder))

    async def check_running_services(self):
        try:
            with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose:
                active_services = [container.name for container in self.dockerConnector.get_containers()]
                for service, config in self.compose_parser.create_service(compose)["services"].items():
                    if service not in active_services:
                        try:
                            await self.upgrade_start_service(service, config)
                        except Exception as e:
                            self.logger.warning(
                                "Service: {} is offline, automatic start failed due to: {}".format(service, e))
                            continue
                    if service in self.error_stash:
                        del self.error_stash[service]
        except Exception as se:
            self.logger.warning("Failed to check running services {}.".format(se))

    def enable_websocket_log(self):
        logger = logging.getLogger('websockets')
        if not any(isinstance(handler, RotatingFileHandler) for handler in logger.handlers):
            logger.setLevel(int(os.environ.get("WEBSOCKET_LOGGING", 10)))
            formatter = logging.Formatter('%(asctime)s | %(lineno)d | %(message)s')
            handler = RotatingFileHandler("{}/logs/agent-ws.log".format(self.folder), maxBytes=200000000, backupCount=5)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    async def set_agent_status(self):
        try:
            running_tasks = [task._coro.__name__ for task in asyncio.all_tasks()]
            pong_waiter = await self.websocket.ping()
            await asyncio.wait_for(pong_waiter, timeout=self.alive)
        except Exception as e:
            if "running_tasks" in locals():
                self.status_log.warning("Running tasks {} error encountered with connection {}.".format(running_tasks, e))
            else:
                self.status_log.warning("Failed to get status {}.".format(e))
        else:
            self.status_log.info("Running tasks: {}, ping sent pong received".format(running_tasks))

    def process_response(self, status: dict, action: str):
        if isinstance(status, dict) and status:
            for service, error_message in status.items():
                if isinstance(error_message, dict):
                    if error_message["status"] == "failure":
                        try:
                            self.error_stash[service].update({action: error_message["body"]})
                        except KeyError:
                            self.error_stash[service] = {action: error_message["body"]}
                    else:
                        if service in self.error_stash and action in self.error_stash[service]:
                            del self.error_stash[service][action]
                            if not self.error_stash[service]:
                                del self.error_stash[service]

    async def process(self, request_json: str):
        try:
            request = self.decode_request(json.loads(request_json))
        except Exception as e:
            self.logger.info("Failed to parse request: {}, {}".format(e, request_json))
            return {"action": "request",
                    "data": {"status": "failure", "message": "failed to parse/decode request", "body": str(e)}}
        if not self.cli:
            self.logger.info("Received: {}".format(request))
            if request["action"] in self.async_actions:
                await self.send_acknowledgement({"action": request["action"], "requestId": request["requestId"]})

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
        # method_arguments = {"sysinfo": [response, request], "create": [response, request], "test": [response],
        #                     "upgrade": [response, request], "suicide": [response], "containers": [response],
        #                     # "restart": [response, request], "rename": [response, request],
        #                     # "containerlogs": [response, request], "saveconfig": [response, request],
        #                     "clearcache": [response, request], "updatecache": [response, request],
        #                     # "stop": [response, request], "remove": [response, request], "localtest": [response],
        #                     # "fwrules": [response], "fwcreate": [response, request], "fwfetch": [response, request],
        #                     # "fwmodify": [response, request], "fwdelete": [response, request],
        #                     # "logs": [response], "log": [response, request],
        #                     # "flog": [response, request], "dellogs": [response, request],
        #                     # "whitelistadd": [response, request],
        #                     "datacollect": [response, request], "trace": [response, request]}

        if "CONFIRMATION_REQUIRED" in os.environ and request["action"] not in ["updatecache"] and not self.cli:
            self.persist_request(request)
            # response["data"] = {"message": "Request successfully persisted.", "status": "success"}
            return {"message": "Request successfully persisted.", "status": "success"}, request
        else:
            try:
                # return await method_calls[request["action"]](*method_arguments[request["action"]])
                return await method_calls[request["action"]](**request["data"]), request
            except KeyError as ke:
                self.logger.warning("Unknown action '{}'".format(ke))
                return {"status": "failure", "message": "Action {} is not supported.".format(ke)}, request
            except TypeError as te:
                self.logger.info("Method {}".format(te))
                return {"status": "failure", "message": "Method {}".format(te)}, request

    async def system_info(self, **_) -> dict:
        try:
            return self.sysinfo_connector.get_system_info(self.error_stash, self.cli)
        except Exception as e:
            self.logger.info("Failed to get sys info data {}.".format(e))
            return {}

    async def create_container(self, compose: str = "", config: list = None, **_) -> dict:
        status = {}
        try:
            decoded_data = self.upgrade_load_compose(compose)
        except Exception as e:
            self.logger.warning(e)
        else:
            try:
                parsed_compose = self.compose_parser.create_service(decoded_data)
            except ComposeException as e:
                self.logger.warning(e)
                return {"status": "failure", "body": str(e)}
            else:
                if "volumes" in parsed_compose:
                    await self.check_named_volumes(parsed_compose["volumes"])
                if "resolver" in parsed_compose["services"]:
                    result = self.upgrade_save_files(decoded_data, config)
                    if result:
                        status["dump"] = result
                for service, service_config in parsed_compose["services"].items():
                    status[service] = {}
                    try:
                        await self.dockerConnector.start_service(service_config)
                    except ContainerException as e:
                        status[service] = {"status": "failure", "body": str(e)}
                        self.logger.info("Failed to start service {} due to {}.".format(service, e))
                    else:
                        status[service]["status"] = "success"
                        if service == "resolver":
                            await self.update_cache()
                            self.prefetch_tld()
        return status

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

    async def upgrade_container(self, compose: str = "", config: list = None, services: list = None, uid: str = "",
                                **_) -> dict:
        status, old_config = {}, None
        try:
            compose = self.upgrade_load_compose(compose)
        except Exception as e:
            self.logger.warning(e)
        try:
            parsed_compose = self.compose_parser.create_service(compose)
        except ComposeException as e:
            self.logger.warning("Failed to create services from parsed compose, {}".format(e))
            return {"status": "failure", "body": str(e)}
        else:
            if "volumes" in parsed_compose:
                await self.check_named_volumes(parsed_compose["volumes"])
            services = services if services else list(parsed_compose["services"])
            if self.upgrade_check_multi_upgrade(services, parsed_compose, uid):
                services = ["lr-agent"]
            if "resolver" in services:
                try:
                    old_config = self.upgrade_load_config(config)
                except Exception as e:
                    status.update({"config dump": str(e)})
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
                self.upgrade_persist_compose(status, compose)
            except Exception as de:
                status["dump"] = de
        return status

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

    def upgrade_load_config(self, config: list):
        try:
            old_config = self.load_file("etc/kres/kres.conf")
        except IOError as e:
            raise Exception(e)
        else:
            self.upgrade_save_files(config=config)
            return old_config

    def upgrade_check_multi_upgrade(self, services: list, parsed_compose: dict, uid: str) -> bool:
        if "lr-agent" in services and len(services) != 1:
            request = {"action": "upgrade",
                       "data": {"services": [service for service in services if service != "lr-agent"], "uid": uid}}
            request["data"]["compose"] = json.dumps({'version': '3', 'services': {key: value for key, value in
                                                                                  parsed_compose["services"].items() if
                                                                                  key != "lr-agent"}})
            self.save_file("etc/agent/upgrade.json", "json", request)
            return True
        return False

    def upgrade_persist_compose(self, status: dict, compose: str):
        try:
            if all(state["status"] == "success" for state in status.values()):
                self.upgrade_save_files(compose, None)
        except Exception as e:
            self.logger.warning("There was an error in compose persistence {}".format(e))
            raise Exception(e)

    async def upgrade_check_incorrect_name(self):
        running_containers = [container.name for container in self.dockerConnector.get_containers()]
        if "lr-agent-old" in running_containers and "lr-agent" not in running_containers:
            await self.dockerConnector.rename_container("lr-agent-old", "lr-agent")

    def upgrade_return_config(self, old_config: list):
        try:
            self.save_file("etc/kres/kres.conf", "config", old_config)
        except Exception as e:
            self.logger.warning("Failed to back up to old config".format(e))

    async def dump_resolver_logs(self):
        try:
            self.save_file("logs/resolver_dump.logs", "text", self.dockerConnector.container_logs("resolver", tail=1000))
        except ConnectionError as ce:
            self.logger.warning("Failed to get logs of new unhealthy resolver, {}.".format(ce))
        except IOError as ie:
            self.logger.warning("Failed to persist logs of new unhealthy resolver, {}.".format(ie))

    async def upgrade_check_binding(self, old_config: list):
        for _ in range(10):
            if self.sysinfo_connector.check_port() == "ok" and self.sysinfo_connector.check_port("resolver-old") == "ok":
                return True
            await asyncio.sleep(1)
        await self.dump_resolver_logs()
        self.upgrade_return_config(old_config)
        return False

    async def upgrade_translation_fallback(self, service: str, old_config: list):
        await self.dump_resolver_logs()
        self.upgrade_return_config(old_config)
        try:
            await self.upgrade_worker_method("resolver-old", self.dockerConnector.restart_container)
        except Exception as e:
            self.logger.warning("Failed to restart old resolver {}.".format(e))
        else:
            try:
                await self.upgrade_worker_method(service, self.dockerConnector.remove_container)
                await self.upgrade_worker_method("resolver-old", self.dockerConnector.rename_container, service)
            except Exception as e:
                self.logger.warning("Failure during healthcheck rollback, {}".format(e))
        self.logger.warning("New resolver is unhealthy, resolving failed")
        return {"status": "failure", "message": "New resolver is unhealthy, resolving failed",
                    "body": "Resolving health check failed"}

    async def upgrade_container_fallback(self, service: str) -> dict:
        try:
            await self.upgrade_worker_method(service, self.dockerConnector.remove_container)
        except Exception as re:
            return {"status": "failure", "message": "failed to remove new {}".format(service), "body": str(re)}
        else:
            try:
                await self.upgrade_worker_method("{}-old".format(service), self.dockerConnector.rename_container,
                                                 service)
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

    async def upgrade_check_resolver_resolving(self, old_config: list, service: str) -> dict:
        await asyncio.sleep(int(os.environ.get("UPGRADE_SLEEP", 0)))
        if not await self.upgrade_check_binding(old_config):
            raise ContainerException("New resolver is not healthy due to port not bound, rollback")
        try:
            await self.upgrade_worker_method("resolver-old", self.dockerConnector.stop_container)
        except Exception as se:
            raise ContainerException("Failed to stop old resolver, {}".format(se))
        else:
            if self.sysinfo_connector.check_resolving() == "fail":
                return await self.upgrade_translation_fallback(service, old_config)

    def upgrade_check_service_state(self, service: str) -> bool:
        try:
            return True if self.dockerConnector.inspect_config(service)["State"]["Running"] else False
        except Exception:
            return False

    def upgrade_get_error_message(self, message: str, exception):
        return {"status": "failure", "message": message, "body": str(exception)}

    async def upgrade_without_downtime(self, service: str, parsed_compose: dict, old_config: list=None) -> dict:
        if service == "resolver" and self.sysinfo_connector.check_port() == "fail":
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
                                                              service)
                    except Exception as ren:
                        return self.upgrade_get_error_message("failed to rollback name for {}".format(service), ren)
                    else:
                        return self.upgrade_get_error_message("failed to start new service {}".format(service), se)
                else:
                    try:
                        if service == "resolver":
                            status = await self.upgrade_check_resolver_resolving(old_config, service)
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

    async def check_named_volumes(self, config: dict):
        try:
            volume_names = [volume.name for volume in self.dockerConnector.get_volumes()]
            for volume_name, volume_attr in config.items():
                if volume_name not in volume_names:
                    await self.dockerConnector.create_volume(volume_name, **volume_attr)
        except Exception as e:
            self.logger.warning("Failed to create named volume due to {}.".format(e))

    def upgrade_save_files(self, compose: str = None, config: list = None):
        try:
            if compose:
                self.save_file("etc/agent/docker-compose.yml", "yml", compose)
            if config:
                self.save_file("etc/kres/kres.conf", "config", config)
        except IOError as e:
            raise Exception(e)

    def upgrade_load_compose(self, compose: str) -> str:
        if compose:
            return compose
        else:
            try:
                with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose_file:
                    return compose_file.read()
            except FileNotFoundError:
                raise Exception("Compose not supplied and local compose not present")

    async def upgrade_pull_image(self, name: str):
        try:
            await self.dockerConnector.pull_image(name)  # pulls image before removal, upgrade is instant
        except Exception as e:
            self.logger.info("Failed to pull image before upgrade, {}".format(e))

    async def upgrade_worker_method(self, service: str, action, name: str = None):
        try:
            if service in [container.name for container in self.dockerConnector.get_containers(stopped=True)]:
                if name:
                    await action(service, name)
                else:
                    await action(service)
        except ContainerException as e:
            self.logger.info("Failed to execute action {} for service {} due to {}".format(action, service, e))
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
            raise Exception(e)

    async def upgrade_start_service(self, service: str, compose: dict):
        try:
            if service not in [container.name for container in self.dockerConnector.get_containers(stopped=True)]:
                await self.dockerConnector.start_service(compose)  # tries to start new service
            else:
                await self.dockerConnector.remove_container(service)  # deletes orphaned service
                await self.dockerConnector.start_service(compose)  # tries to start new service
        except ContainerException as e:
            self.logger.warning("Failed to create {} service, error {}".format(service, e))
            raise Exception(e)

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

    # async def rename_container(self, response: dict, request: dict) -> dict:
    #     status = {}
    #     for old_name, new_name in request["data"].items():
    #         status[old_name] = {}
    #         try:
    #             await self.dockerConnector.rename_container(old_name, new_name)
    #         except ContainerException as e:
    #             status[old_name] = {"status": "failure", "body": str(e)}
    #             self.logger.info(e)
    #         else:
    #             status[old_name]["status"] = "success"
    #     response["data"] = status
    #     return response

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

    # async def restart_container(self, response: dict, request: dict) -> dict:
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

    # async def stop_container(self, response: dict, request: dict) -> dict:
    #     if "cli" not in request:
    #         await self.send_acknowledgement(response)
    #     status = {}
    #     try:
    #         for container in request["data"]["containers"]:
    #             status[container] = {}
    #             try:
    #                 await self.dockerConnector.stop_container(container)
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

    # async def remove_container(self, response: dict, request: dict) -> dict:
    #     if "cli" not in request:
    #         await self.send_acknowledgement(response)
    #     status = {}
    #     try:
    #         for container in request["data"]["containers"]:
    #             status[container] = {}
    #             try:
    #                 await self.dockerConnector.remove_container(container)
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

    async def list_containers(self, **_) -> dict:
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
        return data

    # async def container_logs(self, response: dict, request: dict) -> dict:
    #     try:
    #         logs = self.dockerConnector.container_logs(**request["data"])
    #     except ConnectionError as e:
    #         response["data"] = {"status": "failure", "body": str(e)}
    #         self.logger.info(e)
    #     else:
    #         response["data"] = {"body": self.encode_base64_string(logs), "status": "success"}
    #     return response
    #
    # async def firewall_rules(self, response: dict) -> dict:
    #     try:
    #         data = self.firewall_connector.active_rules()
    #     except (ConnectionError, Exception) as e:
    #         self.logger.info(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     else:
    #         response["data"] = data
    #     return response
    #
    # async def create_rule(self, response: dict, request: dict) -> dict:
    #     status = {}
    #     try:
    #         for rule in request["data"]["rules"]:
    #             status[rule] = {}
    #             try:
    #                 data = self.firewall_connector.create_rule(rule)
    #             except (ConnectionError, Exception) as e:
    #                 self.logger.info(e)
    #                 status[rule] = {"status": "failure", "body": str(e)}
    #             else:
    #                 status[rule] = {"status": "success", "rule": data}
    #     except KeyError:
    #         response["data"] = {"status": "failure", "message": "No rules specified in 'rules' key."}
    #         return response
    #     successful_rules = [rule for rule in status.keys() if status[rule]["status"] == "success"]
    #     if len(successful_rules) > 0:
    #         try:
    #             self.save_file("kres/firewall.conf", "json", successful_rules)
    #         except IOError as e:
    #             self.logger.info(e)
    #             response["data"] = {"status": "failure", "body": str(e)}
    #     response["data"] = status
    #     return response
    #
    # async def fetch_rule(self, response: dict, request: dict) -> dict:
    #     try:
    #         data = self.firewall_connector.fetch_rule_information(request["data"])
    #     except (ConnectionError, Exception) as e:
    #         self.logger.info(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     else:
    #         response["data"] = data
    #     return response
    #
    # async def delete_rule(self, response: dict, request: dict) -> dict:
    #     status = {}
    #     try:
    #         for rule in request["data"]["rules_ids"]:
    #             status[rule] = {}
    #             try:
    #                 self.firewall_connector.delete_rule(rule)
    #             except (ConnectionError, Exception) as e:
    #                 self.logger.info(e)
    #                 status[rule] = {"status": "failure", "body": str(e)}
    #             else:
    #                 status[rule] = {"status": "success"}
    #     except KeyError:
    #         response["data"] = {"status": "failure", "message": "No rules_ids specified in 'rules' key."}
    #         return response
    #     response["data"] = status
    #     return response
    #
    # async def modify_rule(self, response: dict, request: dict) -> dict:
    #     try:
    #         self.firewall_connector.modify_rule(*request["data"]["rule"])
    #     except (ConnectionError, Exception) as e:
    #         self.logger.info(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     except KeyError:
    #         response["data"] = {"status": "failure", "message": "No rule specified in 'rule' key."}
    #         return response
    #     else:
    #         response["data"] = {"status": "success"}
    #     return response

    # async def agent_log_files(self, response: dict) -> dict:
    #     try:
    #         files = self.log_reader.list_files()
    #     except FileNotFoundError as e:
    #         self.logger.info(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     else:
    #         response["data"] = files
    #     return response
    #
    # async def agent_all_logs(self, response: dict, request: dict) -> dict:
    #     try:
    #         lines = self.log_reader.view_log(request["data"])
    #     except IOError as e:
    #         self.logger.info(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     else:
    #         response["data"] = lines
    #     return response
    #
    # async def agent_filtered_logs(self, response: dict, request: dict) -> dict:
    #     try:
    #         lines = self.log_reader.filter_logs(**request["data"])
    #     except Exception as e:
    #         self.logger.info(e)
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     else:
    #         response["data"] = lines
    #     return response
    #
    # async def agent_delete_logs(self, response: dict, request: dict) -> dict:
    #     status = {}
    #     try:
    #         for file in request["data"]["files"]:
    #             status[file] = {}
    #             try:
    #                 self.log_reader.delete_log(file)
    #             except IOError as e:
    #                 status[file] = {"status": "failure", "body": str(e)}
    #             else:
    #                 status[file] = {"status": "success"}
    #     except KeyError:
    #         response["data"] = {"status": "failure", "message": "No files specified in 'files' key."}
    #         return response
    #     response["data"] = status
    #     return response

    async def agent_test_message(self, **_) -> dict:
        return {"status": "success", "message": "Agent seems ok"}

    def check_rpz_file(self, path: str) -> bool:
        pattern = re.compile(
            "^(\*[\.-]?)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\s+CNAME\s+\.$")
        with open(path, "r") as file:
            try:
                for line in file:
                    if not pattern.match(line.strip()):
                        return False
            except Exception as e:
                self.logger.warning("Failed to validate rpz file {}, {}.".format(path, e))
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
        message = b"prefill.config({['.'] = { url = 'https://www.internic.net/domain/root.zone', interval = 86400 }})\n"
        for tty in os.listdir("/etc/whalebone/tty/"):
            try:
                self.send_to_socket(message, tty)
            except Exception:
                self.logger.warning("Failed to send prefetch data to socket")
            else:
                self.logger.info("Tlds successfully pre fetched.")

    def get_kresman_credentials(self) -> str:
        try:
            listener = os.environ.get("KRESMAN_LISTENER", "http://127.0.0.1:8080")
            req = requests.post("{}/api/authorization/Login".format(listener), verify=False,
                                headers={'Content-Type': 'application/json'},
                                json={'emailAddress': os.environ.get("KRESMAN_LOGIN", 'admin@whalebone.io'),
                                      'password': os.environ.get("KRESMAN_PASSWORD",
                                                                 '47cd985a73d1af0f0ee2283437fb0176')})
        except requests.RequestException as re:
            self.logger.warning("Failed to login to Kresman due to {}.".format(re))
        else:
            try:
                return req.json()['accessToken']
            except Exception as e:
                self.logger.warning("Failed to get request token from Kresman {}, {}.".format(req.content, e))
        return ""

    async def update_cache(self,  **_) -> dict:
        address = os.environ.get("KRESMAN_LISTENER", "http://127.0.0.1:8080")
        try:
            # async with aiohttp.ClientSession() as session:
            #     async with session.get("{}/api/general/updatenow".format(address), json={}, ssl=False) as response:
            #         if response.ok:
            #             return {"status": "success", "message": "Cache update successful"}
            #         else:
            #             return {"status": "failure", "message": "Cache update failed"}
            msg = requests.get("{}/api/general/updatenow".format(address), json={}, verify=False,
                               # headers={'accept': '*/*', 'Content-Type': 'application/json',
                               #          'Authorization': 'Bearer {}'.format(self.kresman_token)}
                               )
        except requests.exceptions.RequestException as e:
            return {"status": "failure", "body": str(e)}
        else:
            if msg.ok:
                return {"status": "success", "message": "Cache update successful"}
            else:
                return {"status": "failure", "message": "Cache update failed"}

    async def trace_domain(self, domain: str, query_type: str = "", **_):
        try:
            address = os.environ["TRACE_LISTENER"]
        except KeyError:
            address = "http://127.0.0.1:8453"
        try:
            msg = requests.get("{}/trace/{}/{}".format(address, domain, query_type),
                               timeout=int(os.environ.get("HTTP_TIMEOUT", 10)))
        except requests.exceptions.RequestException as e:
            return {"status": "failure", "body": str(e)}
        else:
            if msg.ok:
                return {"status": "success", "trace": msg.content.decode("utf-8")}
            else:
                return {"status": "failure", "message": "Trace failed",
                                    "error": msg.content.decode("utf-8")}

    async def resolver_cache_clear(self, clear: str = "all", **_) -> dict:
        message = "cache.clear()\n" if clear == "all" else "cache.clear('{}', true)\n".format(clear)
        for tty in os.listdir("/etc/whalebone/tty/"):
            try:
                response = self.send_to_socket(message.encode("utf-8"), tty)
            except Exception as e:
                self.logger.warning("Failed to clear cache on tty {}, {}.".format(tty, e))
            else:
                if isinstance(response, str) and "count" in response:
                    return {"status": "success"}
                else:
                    return {"status": "failure", "message": response}
        return {"status": "failure", "message": "Failed to send command."}

    def send_to_socket(self, message: bytes, tty) -> str:
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
                amount_received, amount_expected = 0, len(message)
                while amount_received < amount_expected:
                    data = sock.recv(65535)
                    amount_received += len(data)
                return data.decode("utf-8")
            except socket.timeout as re:
                self.logger.warning("Failed to get data from socket {}, {}".format(tty, re))
            except Exception as e:
                self.logger.warning("Failed to get data from {}, {}".format(tty, e))
            finally:
                sock.close()

    async def resolver_suicide(self, **_):
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
            await self.upgrade_container(services=["kresman"], compose=yaml.dump(parsed_compose))

    async def suicide_delete_containers(self, status: dict):
        for name in ["logstream", "lr-agent"]:
            if name == "lr-agent":
                try:
                    await self.send({"action": "suicide", "status": status,
                                     "message": "All those moments will be lost in time, like tears in rain. Time to die."})
                except Exception as e:
                    self.logger.info("Failed to acknowledge suicide, {}.".format(e))
            await self.dockerConnector.remove_container(name)

    def write_nameservers(self):
        with open("{}resolv/resolv.conf".format(self.folder), "w") as config:
            for ip in self.nameservers_from_config():
                config.write("nameserver {}\n".format(ip))

    def nameservers_from_config(self) -> set:
        try:
            ips, pattern = set(), re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            for line in self.load_file("etc/kres/kres.conf"):
                if any(key in line for key in ("policy.suffix", "policy.all")):
                    ips.update(pattern.findall(line))
            return ips if ips else {"8.8.8.8"}
        except Exception as e:
            self.logger.warning("Failed to get nameservers from config, {}.".format(e))
        return {"8.8.8.8"}

    async def pack_files(self, url: str, **_) -> dict:
        folder = "{}{}".format(self.folder, "temp")
        try:
            os.mkdir(folder)
        except FileExistsError:
            rmtree(folder)
            os.mkdir(folder)
        await self.gather_static_files(folder)
        customer_id, resolver_id = self.create_client_ids()
        logs_zip = "/opt/agent/{}-{}-{}-wblogs.zip".format(customer_id, datetime.now().strftime("%Y-%m-%d_%H:%M:%S"),
                                                           resolver_id)
        self.pack_logs(logs_zip, folder)
        status = self.upload_logs(logs_zip, url)
        try:
            rmtree(folder)
            os.remove(logs_zip)
        except Exception:
            pass
        return status

    def upload_logs(self, logs_zip: str, target_url: str) -> dict:
        try:
            files = {'upload_file': open(logs_zip, 'rb')}
            req = requests.post("https://transfer.whalebone.io", files=files)
        except Exception as e:
            self.logger.info("Failed to send files to transfer.whalebone.io, {}".format(e))
            return {"status": "failure", "message": "Data upload failed", "body": str(e)}
        else:
            if req.ok:
                try:
                    requests.post(target_url,
                                  json={"text": "New customer log archive was uploaded:\n{}".format(
                                      req.content.decode("utf-8"))}, timeout=int(os.environ.get("HTTP_TIMEOUT", 10)))
                except Exception as e:
                    self.logger.info("Failed to send notification to Slack, {}".format(e))
                else:
                    return {"status": "success", "message": "Data uploaded"}
            else:
                self.logger.warning("Failed to upload file to transfer {}, {}.".format(req.status_code, req.content))

    def load_container_info(self, folder: str):
        with open("{}etc/agent/docker-compose.yml".format(self.folder), "r") as compose:
            parsed_compose = self.compose_parser.create_service(compose)
            for service in parsed_compose["services"]:
                try:
                    with open("{}/docker.{}.logs".format(folder, service), "w") as file:
                        file.write(self.dockerConnector.container_logs(service, tail=1000))
                    with open("{}/docker.{}.inspect".format(folder, service), "w") as file:
                        json.dump(self.dockerConnector.inspect_config(service), file)
                except Exception as e:
                    self.logger.info("Service {} not found, {}".format(service, e))

    def move_agent_logs(self, log_directory: str, target_directory: str):
        for file in os.listdir(log_directory):
            try:
                if "agent-ws" not in file:
                    copyfile(os.path.join(log_directory, file), target_directory)
            except Exception as me:
                self.logger.warning("Failed to move file {} to {} due to {}".format(file, target_directory, me))

    async def gather_static_files(self, folder: str):
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
                   "list_containers": {"action": "docker", "command": await self.docker_ps(),
                                       "path": "{}/docker_ps".format(folder)},
                   "docker_stats": {"action": "docker", "command": await self.docker_stats(),
                                    "path": "{}/docker_stats".format(folder)}
                   }
        self.load_container_info(folder)
        for action, specification in actions.items():
            try:
                if specification["action"] == "copy_file":
                    copyfile(*specification["command"])
                elif specification["action"] == "copy_dir":
                    if action == "agent_log":
                        self.move_agent_logs(*specification["command"])
                    else:
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
            with open("/opt/agent/certs/client.crt", "r") as file:
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
            self.logger.info("Error when creating zip file {}.".format(ze))
        else:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    if os.path.exists(os.path.join(root, file)):
                        if os.path.getsize(os.path.join(root, file)) >= 20000000:
                            try:
                                self.tail_file(os.path.join(root, file), 2000)
                            except Exception:
                                pass
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

    async def docker_ps(self) -> str:
        result = []
        try:
            for container in [container for container in self.dockerConnector.get_containers(stopped=True)]:
                result.append("{} {} {}\n".format(container.image.tags[0], container.status, container.name))
        except Exception as e:
            self.logger.info("Failed to acquire docker ps info, {}".format(e))
        return "".join(result)

    def convert_bytes(self, size: int):
        for x in ['bytes', 'KiB', 'MiB', 'GiB', 'TiB']:
            if size < 1024.0:
                return "{:3.1f}{}".format(size, x)
            size /= 1024.0
        return size

    def calculate_blkio_bytes(self, container_metrics: dict) -> str:
        reads, writes = 0, 0
        try:
            for value in container_metrics["blkio_stats"]["io_service_bytes_recursive"]:
                if value["op"] == "Read":
                    reads += value["value"]
                elif value["op"] == "Write":
                    writes += value["value"]
        except KeyError as ke:
            self.logger.warning("Failed to get io info {} key is missing.".format(ke))
        return "{} / {}".format(self.convert_bytes(reads), self.convert_bytes(writes))

    def calculate_network_bytes(self, container_metrics: dict) -> str:
        if "networks" not in container_metrics:
            return "0bytes / 0bytes"
        receive, transmit = 0, 0
        try:
            for if_name, data in container_metrics["networks"].items():
                receive += data["rx_bytes"]
                transmit += data["tx_bytes"]
        except KeyError as ke:
            self.logger.warning("Failed to get network info {} key is missing.".format(ke))
        return "{} / {}".format(self.convert_bytes(receive), self.convert_bytes(transmit))

    def calculate_cpu_percent(self, container_metrics: dict) -> str:
        cpu_percent = 0.0
        try:
            cpu_count = container_metrics["cpu_stats"]["online_cpus"]
            cpu_delta = float(container_metrics["cpu_stats"]["cpu_usage"]["total_usage"]) - \
                        float(container_metrics["precpu_stats"]["cpu_usage"]["total_usage"])
            system_delta = float(container_metrics["cpu_stats"]["system_cpu_usage"]) - \
                           float(container_metrics["precpu_stats"]["system_cpu_usage"])
            if system_delta > 0.0 and cpu_delta > 0.0:
                cpu_percent = (cpu_delta / system_delta) * 100.0 * cpu_count
        except Exception as e:
            self.logger.warning("Failed to get cpu info due to {}.".format(e))
        return "{:.2f}%".format(cpu_percent)

    def calculate_memory(self, container_metrics: dict) -> str:
        try:
            return "{} / {}".format(self.convert_bytes(
                container_metrics["memory_stats"]["usage"] - container_metrics["memory_stats"]["stats"]["cache"]),
                                    self.convert_bytes(container_metrics["memory_stats"]["limit"]))
        except KeyError as ke:
            self.logger.warning("Failed to get memory info {} key is missing.".format(ke))
            return "0bytes / 0bytes"

    async def get_container_statistics(self, container) -> str:
        try:
            stats = (await container.stats(stream=False))[0]
            name = (await container.show())["Name"][1:]
            return "{}:\t{}\t{}\t{}\t{}\n".format(name, self.calculate_cpu_percent(stats),
                                                         self.calculate_memory(stats),
                                                         self.calculate_network_bytes(stats),
                                                         self.calculate_blkio_bytes(stats))
        except Exception as e:
            self.logger.warning("Failed to get data for {}, {}".format(container.name, e))

    async def docker_stats(self) -> str:
        results = []
        async_docker = Docker()
        try:
            tasks = [self.get_container_statistics(container) for container in await async_docker.containers.list()]
            for stats in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(stats, str) and stats:
                    results.append(stats)
        except Exception as e:
            self.logger.warning("Failed to acquire docker stats info, {}".format(e))
        finally:
            await async_docker.close()
        return "".join(results)

    # def docker_stats(self) -> str:
    #     result = []
    #     try:
    #         for container in [container for container in self.dockerConnector.get_containers()]:
    #             try:
    #                 stats = container.stats(stream=False)
    #                 result.append("{}:\t{}\t{}\t{}\t{}\n".format(container.name, self.calculate_cpu_percent(stats),
    #                                                              self.calculate_memory(stats),
    #                                                              self.calculate_network_bytes(stats),
    #                                                              self.calculate_blkio_bytes(stats)))
    #             except Exception as e:
    #                 self.logger.warning("Failed to get data for {}, {}".format(container.name, e))
    #     except Exception as e:
    #         self.logger.warning("Failed to acquire docker stats info, {}".format(e))
    #     return "".join(result)

    # async def write_config(self, response: dict, request: dict) -> dict:
    #     write_type = {"base64": "wb", "json": "w", "text": "w"}
    #     status = {}
    #     for key, value in request["data"]["config"].items():
    #         if not os.path.exists("{}/{}".format(self.folder, key)):
    #             os.mkdir("{}/{}".format(self.folder, key))
    #         for data in value:
    #             try:
    #                 with open("{}/{}/{}".format(self.folder, key, data["path"]), write_type[data["type"]]) as file:
    #                     if data["type"] == "json":
    #                         json.dump(data["data"], file)
    #                     elif data["type"] == "base64":
    #                         file.write(self.decode_base64_string(data["data"]))
    #                     else:
    #                         for line in data["data"]:
    #                             file.write("{}\n".format(line))
    #             except Exception as e:
    #                 status[key] = {"status": "failure", "message": "Failed to dump config", "body": str(e)}
    #             else:
    #                 status[key] = {"status": "success", "message": "Config dump successful"}
    #     response["data"] = status
    #     return response

    # async def whitelist_add(self, response: dict, request: dict) -> dict:
    #     try:
    #         response["data"] = request["data"]
    #     except KeyError as e:
    #         response["data"] = {"status": "failure", "body": str(e)}
    #     return response

    # async def local_api_check(self, response: dict):
    #     port = os.environ.get("LOCAL_API_PORT", "8765")
    #     async with websockets.connect('ws://localhost:{}'.format(port)) as websocket:
    #         try:
    #             await websocket.send(json.dumps({"action": "test"}))
    #             resp = await websocket.recv()
    #         except Exception as e:
    #             self.logger.info("Local api healthcheck failed, {}".format(e))
    #             response["data"] = {"status": "failure", "body": str(e)}
    #         else:
    #             if json.loads(resp)["data"]["status"] == "success":
    #                 response["data"] = {"status": "success", "message": "Local api is up"}
    #         return response

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
                elif file_type == "config":
                    for rule in content:
                        file.write(rule + "\n")
                else:
                    file.write(content)
        except Exception as e:
            self.logger.info("Failed to save file {} due to {}".format(location, e))
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

    def decode_request(self, message: dict) -> dict:
        if "data" in message:
            if not isinstance(message["data"], dict):
                '''
                 If data field is dict, it arrived from local services and is not encoded in base64
                 Was therefore correctly decoded in process().
                '''
                if not message["data"]:
                    message["data"] = {}
                else:
                    decoded_string = self.decode_base64_string(message["data"])
                    try:
                        message["data"] = json.loads(decoded_string)
                    except json.JSONDecodeError as je:
                        self.logger.warning("Failed to json parse data {} due to {}.".format(decoded_string, je))
                        # message["data"] = decoded_string
        return message

    def encode_request(self, message: dict) -> dict:
        if "data" in message:
            message["data"] = self.encode_base64_string(json.dumps(message["data"]))
        return message

    def decode_base64_string(self, b64_string: str) -> str:
        return base64.b64decode(b64_string.encode("utf-8")).decode("utf-8")

    def encode_base64_string(self, input_string: str) -> str:
        return base64.b64encode(input_string.encode("utf-8")).decode("utf-8")

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
