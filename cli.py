import argparse
import base64
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

    def view_requests(self):
        request = self.prepare_request()["data"]
        with open("/etc/whalebone/compose/docker-compose.yml", "r") as file:
            original_compose = yaml.load(yaml.load(file, Loader=yaml.SafeLoader), Loader=yaml.SafeLoader)
        for service, config in yaml.load(request["compose"], Loader=yaml.SafeLoader)["services"].items():
            if service in request["services"]:
                print("-------------------------------")
                print("Changes for {}".format(service))
                if service in original_compose["services"]:
                    for key, value in config.items():
                        try:
                            if original_compose["services"][service][key] != value:
                                if type(value) != dict:
                                    print("New value for {}: {}".format(key, value))
                                    print("   Old value for {}: {}".format(key, original_compose["services"][service][key]))
                                else:
                                    for attr_name, attr_value in value.items():
                                        if original_compose["services"][service][key][attr_name] != attr_value:
                                            print("New value for {} {}: {}".format(key, attr_name, attr_value))
                                            print("   Old value for {} {}: {}".format(key, attr_name,
                                                                                  original_compose["services"][service][
                                                                                      key][attr_name]))
                        except KeyError:
                            print(service, config)
                else:
                    print(config)
        print("-------------------------------")

    def prepare_request(self) -> dict:
        request = {"cli": "true", "action": "upgrade"}
        data = {}
        services = set()
        with open("/var/whalebone/requests/requests.txt", "r") as file:
            for line in file:
                line = json.loads(line)
                if line:
                    for keyword in ["config", "compose"]:
                        try:
                            data[keyword] = line["data"][keyword]
                        except KeyError:
                            pass
                    services.update(line["data"]["services"])
        data.update({"services": list(services)})
        request["data"] = data
        return request

    def delete_files(self):
        try:
            os.remove("/etc/whalebone/requests/requests.txt")
        except Exception as e:
            print("Failed to delete stored requests, {}".format(e))

    async def run_command(self):
        agent = LRAgentClient(None)
        has_params = ["stop", "remove", "create", "upgrade", "restart", "trace", "clearcache"]
        try:
            if self.cli_input["action"] in has_params:
                request = {"requestId": "666", "cli": "true", "action": self.cli_input["action"],
                           "data": self.create_params(self.cli_input["action"])}
            elif self.cli_input["action"] == "list":
                self.view_requests()
            elif self.cli_input["action"] == "run":
                request = self.prepare_request()
                self.delete_files()
            else:
                request = {"requestId": "666", "cli": "true", "action": self.cli_input["action"]}
        except Exception as e:
            print("Cannot assemble request, reason: {}".format(e))
        else:
            try:
                response = await agent.process(json.dumps(request))
            except NameError:
                pass
            except Exception as e:
                print("General error during request execution, reason: {}".format(e))
            else:
                if "data" in response:
                    print(response["data"])
                else:
                    print(response)


if __name__ == '__main__':
    # upgrade works ass restart
    supported_actions = ["sysinfo", "stop", "remove", "containers", "create", "upgrade", "updatecache", "list", "run",
                         "restart", "trace", "clearcache"]
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
