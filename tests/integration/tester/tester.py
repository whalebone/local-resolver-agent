import redis
import requests
import yaml
import docker
import os
import base64
import time
import json
import logging
import ast


class Tester():
    def __init__(self):
        self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
        self.api_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        self.firewall_rules = ["src = 127.0.0.1 pass", "qname = whalebone.io deny"]
        try:
            self.proxy_address = os.environ["PROXY_ADDRESS"]
        except KeyError:
            self.proxy_address = "localhost"
        try:
            self.agent_id = os.environ["AGENT_ID"]
        except KeyError:
            self.agent_id = 101
        try:
            self.redis = redis.Redis(os.environ["REDIS_ADDRESS"])
        except KeyError:
            self.redis = "localhost"
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

    def parse_volumes(self, volumes_list):
        volumes_dict = {}
        for volume in volumes_list:
            volume_def = volume.split(':')
            if len(volume_def) < 2 or len(volume_def) > 3:
                raise Exception(
                    "Invalid format(short syntax supported only) of 'volumes' definition: {0}".format(volume))
            volumes_dict[volume_def[0]] = {
                'bind': volume_def[1]
            }
            if len(volume_def) == 3:
                volumes_dict[volume_def[0]]['mode'] = volume_def[2]
            else:
                volumes_dict[volume_def[0]]['mode'] = 'rw'
        return volumes_dict

    def start_agent(self):
        compose = yaml.load(self.compose_reader("agent-compose.yml"))
        for k, v in compose["services"].items():
            if "volumes" in v:
                compose["services"][k]["volumes"] = self.parse_volumes(v["volumes"])
        self.docker_client.containers.run(detach=True, **compose["services"]["lr-agent"])

    def start_resolver(self):
        compose = self.compose_reader("resolver-compose.yml")
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/create".format(self.proxy_address, self.agent_id),
                json={"compose": base64.b64encode(compose.encode("utf-8")).decode("utf-8"),
                      "rules": self.firewall_rules})
        except Exception as e:
            self.logger.info(e)
        else:
            while True:
                if self.redis.exists("create"):
                    status = self.redis_output(self.redis.lpop("create"))
                    self.logger.info(status)
                    for key, value in status.items():
                        if value["status"] == "success":
                            self.logger.info("{} creation successful".format(key))
                        else:
                            self.logger.warning("{} upgrade unsuccessful with response: {}".format(key, value["body"]))
                    break
                else:
                    time.sleep(3)

    def redis_output(self, redis_in):
        return ast.literal_eval(redis_in.decode("utf-8"))

    def compose_reader(self, file):
        with open(file, "r") as f:
            return f.read()

    def inject_rules(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/fwcreate".format(self.proxy_address, self.agent_id),
                json=self.firewall_rules)
        except Exception as e:
            self.logger.info(e)
        else:
            if rec.ok:
                rec = json.loads(rec.text)
                self.logger.info(rec)
                successful_rules = [rule for rule, status in rec.items() if status["status"] == "success"]
                if set(successful_rules) == set(self.firewall_rules):
                    self.logger.info("Inject successful")
                else:
                    self.logger.warning("Inject unsuccessful at rules {}".format(rec))
            else:
                self.logger.warning("Inject failed", rec)

    def upgrade_resolver(self):
        compose = self.compose_reader("resolver-compose-upgraded.yml")
        services = ["resolver", "logrotate"]
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/upgrade".format(self.proxy_address, self.agent_id),
                json={"compose": base64.b64encode(compose.encode("utf-8")).decode("utf-8"),
                      "services": services})
        except Exception as e:
            self.logger.warning(e)
        else:
            while True:
                if self.redis.exists("upgrade"):
                    status = self.redis_output(self.redis.lpop("upgrade"))
                    self.logger.info(status)
                    for key, value in status.items():
                        if value["status"] == "success":
                            self.logger.info("{} upgrade successful".format(key))
                            for config in self.view_config():
                                if config["name"] in services and config["labels"][key] == "3.0":
                                    self.logger.info("{} upgrade config check successful".format(key))
                                else:
                                    self.logger.warning("{} upgrade config check unsuccessful".format(key))
                        else:
                            self.logger.warning("{} upgrade unsuccessful with response: {}".format(key, status))
                    break
                else:
                    time.sleep(3)

    def upgrade_agent(self):
        compose = self.compose_reader("agent-compose-upgraded.yml")
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/upgrade".format(self.proxy_address, self.agent_id),
                json={"compose": base64.b64encode(compose.encode("utf-8")).decode("utf-8"), "services": ["lr-agent"]})
        except Exception as e:
            self.logger.warning(e)
        else:
            rec = json.loads(rec.text)
            self.logger.info(rec)
            if rec["status"] == "success":
                time.sleep(5)
                for config in self.view_config():
                    if config["name"] == "lr-agent" and config["labels"]["lr-agent"] == "3.0":
                        self.logger.info("Agent upgrade config check successful")
            else:
                self.logger.warning("Agent upgrade unsuccessful with response: {}".format(rec))

    def get_sysinfo(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/sysinfo".format(self.proxy_address, self.agent_id))
        except Exception as e:
            self.logger.warning(e)
        else:
            rec = json.loads(rec.text)
            containers = ["lr-agent", "resolver", " logrotate", "passivedns", "logstream"]
            for key, value in rec:
                if key == "containers":
                    self.logger.info(value)
                if key == "containers" and set(containers).issubset(set(value)):
                    self.logger.info("All services containers are running")

                if key == "cpu":
                    self.logger.info("cpu: " + str(value))
                if key == "memory":
                    self.logger.info("memory: " + str(value))
                if key == "hdd":
                    self.logger.info("hdd: " + str(value))

    def rename_container(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/rename".format(self.proxy_address, self.agent_id),
                json={"logrotate": "mega_rotate"})
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            self.logger.info(rec)
            for key, value in rec.items():
                if value["status"] == "success":
                    self.logger.info("{} renamed successfully".format(key))
                else:
                    self.logger.info("{} rename failed".format(key))

    def stop_container(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/stop".format(self.proxy_address, self.agent_id),
                json=["mega_rotate"])
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            if rec["status"] == "success":
                while True:
                    if self.redis.exists("stop"):
                        status = self.redis_output(self.redis.lpop("stop"))
                        self.logger.info(status)
                        for key, value in status.items():
                            if value["status"] == "success":
                                self.logger.info("{} stop successful".format(key))
                            else:
                                self.logger.warning("{} stop unsuccessful with response: {}".format(key, status))
                        break
                    else:
                        time.sleep(3)
            else:
                self.logger.info("Failed to deliver stop")

    def remove_container(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/remove".format(self.proxy_address, self.agent_id),
                json=["passivedns"])
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            if rec["status"] == "success":
                while True:
                    if self.redis.exists("remove"):
                        status = self.redis_output(self.redis.lpop("remove"))
                        self.logger.info(status)
                        for key, value in status.items():
                            if value["status"] == "success":
                                self.logger.info("{} remove successful".format(key))
                            else:
                                self.logger.warning("{} remove unsuccessful with response: {}".format(key, status))
                        break
                    else:
                        time.sleep(3)
            else:
                self.logger.info("Failed to deliver remove")

    def view_config(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/containers".format(self.proxy_address, self.agent_id))
        except Exception as e:
            self.logger.warning(e)
        else:
            return json.loads(rec.text)

    def run_test(self):
        time.sleep(10)
        try:
            self.start_agent()
        except Exception:
            pass
        time.sleep(8)
        try:
            self.start_resolver()
        except Exception:
            pass
        try:
            self.inject_rules()
        except Exception:
            pass
        time.sleep(8)
        try:
            self.upgrade_resolver()
        except Exception:
            pass
        time.sleep(8)
        # try:
        #     self.upgrade_agent()
        # except Exception:
        #     pass
        try:
            self.get_sysinfo()
        except Exception:
            pass
        try:
            self.rename_container()
        except Exception:
            pass
        try:
            self.stop_container()
        except Exception:
            pass
        try:
            self.remove_container()
        except Exception:
            pass


if __name__ == '__main__':
    tester = Tester()
    tester.run_test()
