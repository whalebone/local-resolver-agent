import argparse
import base64
import difflib
import json
import asyncio
import os
import yaml

from lr_agent_client import LRAgentClient


class Cli:
    def __init__(self, cli_input: dict):
        self.cli_input = cli_input

    def params_to_dict(self, params: list, action: str) -> dict:
        keys = {"trace": ["domain", "type"]}
        if len(params) % 2 == 0:
            return dict(zip(keys[action], params))
        else:
            return {"domain": params[0]}

    def create_params(self, action: str) -> dict:
        arg_list = list(filter(None, self.cli_input["args"]))
        action_mapping = {"remove": {"containers": arg_list},
                          "stop": {"containers": arg_list},
                          "restart": {"containers": arg_list},
                          "trace": self.params_to_dict(arg_list, action),
                          "clearcache": {"clear": arg_list[0]},
                          "create": {},  # "compose": self.cli_input["args"]
                          "upgrade": {"services": arg_list}}
        return action_mapping[action]

    def get_old_config(self) -> list:
        try:
            with open("/etc/whalebone/etc/kres/kres.conf", "r") as file:
                return [line.strip() for line in file]
        except Exception as e:
            print("Failed to load old resolver configuration: {}.".format(e))

    def view_requests(self):
        request = self.prepare_request()
        if request:
            if request["action"] in ["create", "suicide"]:
                print("There is a scheduled action '{}' to be run.".format(request["action"]))
                return
            else:
                request = request["data"]
            try:
                with open("/etc/whalebone/etc/agent/docker-compose.yml", "r") as file:
                    original_compose = yaml.load(yaml.load(file, Loader=yaml.SafeLoader), Loader=yaml.SafeLoader)
            except FileNotFoundError:
                print("Could not found docker-compose.yml in /etc/whalebone/etc/agent/.")
            except Exception as e:
                print("Failed to load docker-compose.yml due to {}.".format(e))
            else:
                print("Pending changes will affect following services: {}".format(", ".join(request["services"])))
                for service, config in yaml.load(request["compose"], Loader=yaml.SafeLoader)["services"].items():
                    if service in request["services"]:
                        self.view_changes(service, original_compose, config)
                        if service == "resolver":
                            self.view_config_changes(request["config"], self.get_old_config())
                print("-------------------------------")

    def view_changes(self, service: str, original_compose: dict, config: dict):
        print("-------------------------------")
        print("Changes for {}".format(service))
        if service in original_compose["services"]:
            self.view_compose_changes(config, original_compose, service)
        else:
            print("New service added with following configuration:")
            print(config)

    def view_compose_changes(self, config: dict, original_compose: dict, service: str):
        change = False
        for key, value in config.items():
            try:
                if original_compose["services"][service][key] != value:
                    change = True
                    if not isinstance(value, dict):
                        print("New docker-compose value for {}: {}".format(key, value))
                        print("   Old docker-compose value for {}: {}".format(key,
                                                                            original_compose["services"][service][key]))
                    else:
                        for attr_name, attr_value in value.items():
                            if original_compose["services"][service][key][attr_name] != attr_value:
                                print("New docker-compose value for {} {}: {}".format(key, attr_name, attr_value))
                                print("   Old docker-compose value for {} {}: {}".format(key, attr_name,
                                                                original_compose["services"][service][key][attr_name]))
            except KeyError as ke:
                print("Key {} was not found in original compose.".format(ke))
        if not change:
            print("There are no changes in docker-compose for service {}, the service will be recreated.".format(service))

    def view_config_changes(self, new_config: list, old_config: list):
        if new_config and old_config:
            try:
                config_diff = list(difflib.unified_diff(old_config, new_config, fromfile="current configuration",
                                                        tofile="new configuration", lineterm='', n=0))
            except Exception as e:
                print("Failed to get changes between new and current resolver configuration, {}.".format(e))
            else:
                if config_diff:
                    print("The following changes have been made to resolver configuration:")
                    for line in config_diff:
                        print(line)

    # def prepare_request(self) -> dict:
    #     request = {"cli": "true", "action": "upgrade"}
    #     data = {}
    #     services = set()
    #     with open("/etc/whalebone/requests/requests.txt", "r") as file:
    #         for line in file:
    #             line = json.loads(line)
    #             if line:
    #                 for keyword in ["config", "compose"]:
    #                     try:
    #                         data[keyword] = line["data"][keyword]
    #                     except KeyError:
    #                         pass
    #                 services.update(line["data"]["services"])
    #     data.update({"services": list(services)})
    #     request["data"] = data
    #     return request

    def prepare_request(self) -> dict:
        try:
            with open("/etc/whalebone/requests/requests.json", "r") as file:
                request = json.load(file)
        except FileNotFoundError:
            print("There are no pending requests")
        except json.JSONDecodeError:
            print("Failed to json parse persisted request, json format is not valid.")
        except Exception as e:
            print("Failed to load persisted request due to {}.".format(e))
        else:
            return request

    def delete_files(self, final_print: bool = False):
        try:
            os.remove("/etc/whalebone/requests/requests.json")
        except FileNotFoundError:
            print("There is no pending request to be deleted.")
        except Exception as e:
            print("Failed to delete stored requests, {}".format(e))
        else:
            if final_print:
                print("Pending configuration request deleted.")

    async def execute_request(self, request: dict):
        agent = LRAgentClient(None, True)
        try:
            response = await agent.process(json.dumps(request))
        except Exception as e:
            print("General error during request execution, reason: {}".format(e))
        else:
            if "data" in response:
                print(response["data"]["action_status"])
            else:
                print(response)

    async def run_command(self):
        has_params = ["stop", "remove", "create", "upgrade", "restart", "trace", "clearcache"]
        try:
            if self.cli_input["action"] in has_params:
                request = {"requestId": "666", "action": self.cli_input["action"],
                           "data": self.create_params(self.cli_input["action"])}
            elif self.cli_input["action"] == "list":
                self.view_requests()
            elif self.cli_input["action"] == "run":
                request = self.prepare_request()
                self.delete_files()
            elif self.cli_input["action"] == "delete_request":
                self.delete_files(True)
            else:
                request = {"requestId": "666", "action": self.cli_input["action"]}
        except Exception as e:
            print("Cannot assemble request, reason: {}".format(e))
        else:
            try:
                if request:
                    await self.execute_request(request)
            except NameError:
                pass



if __name__ == '__main__':
    supported_actions = ["sysinfo", "stop", "remove", "containers", "create", "upgrade", "updatecache", "list", "run",
                         "restart", "trace", "clearcache", "delete_request"]
    parser = argparse.ArgumentParser(prog='lr-agent-cli', usage='%(prog)s [options]',
                                     description="This code can be called to run commands of agent without wsproxy")
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')

    parser.add_argument('action', type=str, choices=supported_actions,
                        help='specify action to perform')
    parser.add_argument('--args', nargs='*', help='action parameters')

    args = parser.parse_args()
    cli = Cli(vars(args))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(cli.run_command())
    # loop.run_forever()
