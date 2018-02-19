import os
import requests


class Tester():
    def __init__(self):
        self.proxy_address = os.environ["PROXY_ADDRESS"]
        self.agent_id = os.environ["AGENT_ID"]

    def build_request(self, action: str):
        return "http://wsproxy:8080/wsproxy/rest/message/{}/{}".format(self.agent_id, action)

    def view_logs(self):
        try:
            res = requests.post(self.build_request("logs"))
        except Exception as e:
            print(e)
        else:
            print(res.text)

    def view_log(self, file: str):
        try:
            res = requests.post(self.build_request("log"), data=file)
        except Exception as e:
            print(e)
        else:
            print(res.text)

    def container_logs(self, name, tail):
        try:
            res = requests.post(self.build_request("containerlogs"), data={"name": name, "tail": tail})
        except Exception as e:
            print(e)
        else:
            print(res.text)

    def custom_command(self, action, data):
        try:
            res = requests.post(self.build_request(action), data=data)
        except Exception as e:
            print(e)
        else:
            print(res.text)


if __name__ == '__main__':
    test = Tester()
