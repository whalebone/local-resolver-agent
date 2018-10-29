import json
import asyncio
import base64

import yaml
import os
import requests
import websockets
import time

from shutil import copyfile, copytree, rmtree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from subprocess import call
import zipfile
from datetime import datetime

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
                        self.logger.info("Error during exception persistance, {}".format(e))
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
        if os.path.exists("{}compose/upgrade.json".format(self.folder)):
            with open("{}compose/upgrade.json".format(self.folder), "r") as upgrade:
                request = json.loads(upgrade.read())
            try:
                response = await self.upgrade_container({"action": "upgrade"}, request)
            except Exception as e:
                self.logger.warning("Failed to resume upgrade, {}".format(e))
            else:
                self.logger.info("Done persisted upgrade with response: {}".format(response))
                self.process_response(response)
            os.remove("{}compose/upgrade.json".format(self.folder))
        elif not os.path.exists("{}compose/docker-compose.yml".format(self.folder)):
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
                            except Exception as e:
                                self.logger.warning(
                                    "Service: {} is offline, automatic start failed due to: {}".format(service, e))
                                continue
                        if service in self.error_stash:
                            del self.error_stash[service]
            except Exception as e:
                self.logger.warning(e)

    def process_response(self, response: dict):
        for service, error_message in response["data"].items():
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

    async def process(self, request_json):
        try:
            request = self.decode_base64_json(json.loads(request_json))
        except Exception as e:
            self.logger.info("Failed to parse request: {}, {}".format(e, request_json))
            return {"action": "request",
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
                        "localtest": self.local_api_check, "datacollect": self.pack_files}
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
                            "whitelistadd": [response, request], "localtest": [response],
                            "datacollect": [response, request]}

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
            if "requestId" in response:
                del response["requestId"]
            response["data"] = status
        return response

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
            self.logger.warning(e)
            response["data"] = {"status": "failure", "body": str(e)}
        else:
            if len(request["data"]["services"]) > 0:
                services = request["data"]["services"]
            else:
                services = list(parsed_compose["services"].keys())
            if "lr-agent" in services:
                if len(services) != 1:
                    request["data"]["services"] = [service for service in services if service != "lr-agent"]
                    request["data"]["compose"] = json.dumps(
                        {key: value for key, value in parsed_compose["services"].items() if key != "lr-agent"})
                    self.save_file("compose/upgrade.json".format(self.folder), "json", request)
                    services = ["lr-agent"]
            if "resolver" in services:
                try:
                    old_config = self.load_file("resolver/kres.conf")
                except IOError as e:
                    status["load"] = {"status": "failure", "body": str(e)}
                result = self.upgrade_save_files(request, compose, ["config"])
                if result != {}:
                    status["dump"] = result
            for service in services:
                status[service] = {}
                if service not in parsed_compose["services"]:
                    status[service] = {"status": "failure", "message": "{} not present in compose".format(service)}
                    continue
                if service not in ["lr-agent", "resolver"]:
                    await self.upgrade_pull_image(parsed_compose["services"][service]['image'])
                    remove = await self.upgrade_worker_method(service, service,
                                                              self.dockerConnector.remove_container,
                                                              "remove old container")
                    if remove == {}:
                        start = await self.upgrade_start_service(service, parsed_compose["services"][service])
                        if isinstance(start, str):
                            status[service]["status"] = start
                        else:
                            status[service] = start
                    else:
                        status[service] = remove
                else:
                    if service == "resolver" and check_port(self.dockerConnector) == "fail":
                        remove = await self.upgrade_worker_method(service, service,
                                                                  self.dockerConnector.remove_container,
                                                                  "Failed to remove unhealthy container")
                        if remove == {}:
                            start = await self.upgrade_start_service(service, parsed_compose["services"][service],
                                                                     "Failed to create new container from unhealthy")
                            if start != "success":
                                status[service] = start
                            else:
                                status[service]["status"] = "success"
                        else:
                            status[service] = remove

                    else:
                        rename = await self.upgrade_rename_service(service)
                        if rename != "success":
                            status[service] = rename
                        else:
                            start = await self.upgrade_start_service(service, parsed_compose["services"][service])
                            if start != "success":
                                status[service] = start
                                rename = await self.upgrade_worker_method(service, "{}-old".format(service),
                                                                          self.dockerConnector.rename_container,
                                                                          "rename rollback")
                                if rename != {}:
                                    status[service] = rename
                            else:
                                try:
                                    if service == "resolver":
                                        for interval in range(10):
                                            if check_port(self.dockerConnector) == "ok" and \
                                                    check_port(self.dockerConnector, "resolver-old") == "ok":
                                                break
                                            await asyncio.sleep(1)
                                        else:
                                            try:
                                                self.save_file("resolver/kres.conf", "text", old_config)
                                            except Exception as e:
                                                self.logger.warning("Failed to back up to old config".format(e))
                                            raise ContainerException("New resolver is not healthy rollback")
                                        stop = await self.upgrade_worker_method("resolver-old", "resolver-old",
                                                                                self.dockerConnector.stop_container,
                                                                                "Failed to stop old resolver")
                                        if stop != {}:
                                            raise ContainerException("Failed to stop old resolver")
                                        else:
                                            if check_resolving() == "fail":
                                                try:
                                                    self.save_file("resolver/kres.conf", "text", old_config)
                                                except Exception as e:
                                                    self.logger.warning("Failed to back up to old config".format(e))
                                                restart = await self.upgrade_worker_method("resolver-old",
                                                                                           "resolver-old",
                                                                                           self.dockerConnector.restart_container,
                                                                                           "failed to restart old resolver")
                                                if restart == {}:
                                                    try:
                                                        await self.upgrade_worker_method(service, service,
                                                                                         self.dockerConnector.remove_container,
                                                                                         "Filed to remove new resolver.")
                                                        await self.upgrade_worker_method(service, "resolver-old",
                                                                                         self.dockerConnector.rename_container,
                                                                                         "Filed to remove new resolver.")
                                                    except Exception as e:
                                                        self.logger.warning(
                                                            "Failure during healthcheck rollback, {}".format(e))
                                                    self.logger.warning(
                                                        "New resolver is unhealthy, resolving failed")
                                                    status[service] = {"status": "failure",
                                                                       "message": "New resolver is unhealthy, resolving failed",
                                                                       "body": "Resolving healthcheck failed"}
                                                else:
                                                    status[service] = restart
                                    inspect = self.dockerConnector.inspect_config(service)
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
                                        raise ContainerException("New {} is not running".format(service))
                                except ContainerException as e:
                                    status[service] = {"status": "failure", "message": "removal of old service",
                                                       "body": str(e)}
                                    self.logger.info(e)
                                    remove = await self.upgrade_worker_method(service, service,
                                                                              self.dockerConnector.remove_container,
                                                                              "removal of old and new service")
                                    if remove == {}:
                                        rename = await self.upgrade_worker_method(service, "{}-old".format(service),
                                                                                  self.dockerConnector.rename_container,
                                                                                  "removal and rename of old agent")
                                        if rename != {}:
                                            status[service] = rename
                                    else:
                                        status[service] = remove

                                else:
                                    if "status" not in status[service]:
                                        status[service]["status"] = "success"
                                        if service == "resolver":
                                            await self.update_cache({})
            try:
                if all(state["status"] == "success" for state in status.values()):
                    result = self.upgrade_save_files(request, compose, ["compose"])
                    if result != {}:
                        status["dump"] = result
            except Exception as e:
                self.logger.warning("Failed to check status {}".format(e))
            if "requestId" in response:
                del response["requestId"]
            response["data"] = status
        return response

    def upgrade_save_files(self, request: dict, decoded_data, keys: list) -> dict:
        try:
            if "compose" in keys:
                if "compose" in request["data"]:
                    self.save_file("compose/docker-compose.yml", "yml", decoded_data)
            if "config" in keys:
                if "config" in request["data"]:
                    self.save_file("resolver/kres.conf", "text", request["data"]["config"])
        except IOError as e:
            return {"status": "failure", "body": str(e)}
        else:
            return {}

    def upgrade_load_compose(self, request: dict, response: dict):
        if "compose" in request["data"]:
            return request["data"]["compose"]  # str
        else:
            try:
                with open("{}compose/docker-compose.yml".format(self.folder), "r") as compose:
                    return compose.read()  # str
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
    #         self.save_file("compose/upgrade.json".format(self.folder), "json", request)

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

    async def pack_files(self, response: dict, request: dict) -> dict:
        folder = "{}/{}".format(self.folder, "temp")
        try:
            os.mkdir(folder)
        except FileExistsError:
            rmtree(folder)
            os.mkdir(folder)
        actions = {"release": {"action": "copy", "command": copyfile("/etc/os-release", "{}/release".format(folder))},
                   "etc": {"action": "copy", "command": copytree("/opt/host/etc/whalebone/", "{}/etc".format(folder))},
                   "log": {"action": "copy", "command": copytree("/opt/host/var/log/whalebone/", "{}/logs".format(folder))},
                   "agent_log": {"action": "copy",
                                 "command": copytree("/etc/whalebone/logs/", "{}/agent-logs".format(folder))},
                   "syslog": {"action": "copy", "command": copyfile("/opt/host/var/log/syslog", "{}/syslog".format(folder))},
                   "list": {"action": "list", "command": ["ls", "-lh", "/opt/host/opt/whalebone/"], "path": "{}/ls_opt".format(folder)},
                   "df": {"action": "list", "command": ["df", "-h"], "path": "{}/df".format(folder)},
                   "netstat": {"action": "list", "command": ["netstat", "-tupan"], "path": "{}/netstat".format(folder)},
                   "ip": {"action": "list", "command": ["ifconfig"], "path": "{}/ifconfig".format(folder)},
                   "docker_logs": {"action": "list", "command": ["journalctl", "-u", "docker.service"],
                                   "path": "{}/docker.service".format(folder)},
                   "ps": {"action": "list", "command": ["ps", "-aux"], "path": "{}/ps".format(folder)},
                   "list_containers": {"action": "docker", "command": self.docker_ps(),
                                       "path": "{}/docker_ps".format(folder)},
                   }
        with open("{}compose/docker-compose.yml".format(self.folder), "r") as compose:
            parsed_compose = self.compose_parser.create_service(yaml.load(compose))
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
                if specification["action"] == "copy":
                    specification["command"]
                elif specification["action"] == "docker":
                    with open(specification["path"], "w") as file:
                        file.write(specification["command"])
                else:
                    with open(specification["path"], "w") as file:
                        call(specification["command"], stdout=file)
            except Exception as e:
                self.logger.info("Failed to perform pack of {} action, {}".format(action, e))

        customer_id, resolver_id = "unknown", "unknown"
        try:
            with open("/opt/whalebone/certs/client.crt", "r") as file:
                cert = x509.load_pem_x509_certificate(file.read().encode("utf-8"), default_backend())
        except FileNotFoundError as e:
            self.logger.info("Failed to load cert {}".format(e))
        else:
            for name, attr in {"customer_id": NameOID.LOCALITY_NAME, "resolver_id": NameOID.COMMON_NAME}.items():
                try:
                    locals()[name] = cert.subject.get_attributes_for_oid(attr)[0].value
                except Exception as err:
                    self.logger.info("Failed to get parameter {}, error: {}".format(name, err))

        logs_zip = "/opt/whalebone/{}-{}-{}-wblogs.zip".format(customer_id, datetime.now().strftime("%Y-%m-%d_%H:%M:%S"), resolver_id)
        try:
            zip_file = zipfile.ZipFile(logs_zip, "w", zipfile.ZIP_DEFLATED)
        except zipfile.BadZipFile as ze:
            self.logger.info("Error when creating zip file")
            response["data"] = {"status": "failure", "message": "Zip pack failed", "body": str(ze)}
        else:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    zip_file.write(os.path.join(root, file))
            zip_file.close()

            try:
                files = {'upload_file': open(logs_zip, 'rb')}
                req = requests.post("https://transfer.whalebone.io", files=files)
            except Exception as e:
                self.logger.info("Failed to send files to transfer,whalebone.io, {}".format(e))
                response["data"] = {"status": "failure", "message": "Data upload failed", "body": str(e)}
            else:
                if req.ok:
                    try:
                        requests.post(request["data"], json={"text": "New customer log archive was uploaded:\n{}".format(
                            req.content.decode("utf-8"))})
                    except Exception as e:
                        self.logger.info("Failed to send notification to Slack, {}".format(e))
                    else:
                        response["data"] = {"status": "success", "message": "Data uploaded"}
            try:
                rmtree(folder)
            except Exception:
                pass
            return response

    def docker_ps(self) -> str:
        result = []
        for container in [container for container in self.dockerConnector.get_containers(stopped=True)]:
            result.append("{} {} {}\n".format(container.image.tags[0], container.status, container.name))
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
            self.logger.info("Failed to save file: {}".format(e))
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
