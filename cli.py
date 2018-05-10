import argparse
import base64
import json
import asyncio

from lr_agent_client import LRAgentClient


class Cli:
    def __init__(self, cli_input: dict):
        self.cli_input = cli_input

    def encode_base64_json(self, message: dict) -> str:
        return base64.b64encode(json.dumps(message).encode("utf-8")).decode("utf-8")

    def create_params(self, action: str) -> str:
        action_mapping = {"remove": {"containers": self.cli_input["args"]},
                          "stop": {"containers": self.cli_input["args"]},
                          "create": {}, #"compose": self.cli_input["args"]
                          "upgrade": {"services": self.cli_input["args"]}}
        return self.encode_base64_json(action_mapping[action])

    async def run_command(self):
        agent = LRAgentClient(None)
        has_params = ["stop", "remove", "create", "upgrade"]
        try:
            if self.cli_input["action"] in has_params:
                request = {"requestId": "666", "cli": "true", "action": self.cli_input["action"],
                           "data": self.create_params(self.cli_input["action"])}
            else:
                request = {"requestId": "666", "action": self.cli_input["action"]}
        except Exception as e:
            print("Cannot assemble request, reason: {}".format(e))
        else:
            try:
                response = await agent.process(json.dumps(request))
            except Exception as e:
                print("General error during request execution, reason: {}".format(e))
            else:
                if "data" in response:
                    print(response["data"])
                else:
                    print(response)


if __name__ == '__main__':
    # upgrade works ass restart
    supported_actions = ["sysinfo", "stop", "remove", "containers", "create", "upgrade", "updatecache"]
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
    #loop.run_forever()