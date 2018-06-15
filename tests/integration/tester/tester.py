import redis
import requests
import yaml
import docker
import json
import logging
import os
import ast
import time
import asyncio
import websockets
from dns import resolver
# from scapy.all import *


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
        try:
            self.docker_client.images.pull(compose["services"]["lr-agent"]["image"])
        except Exception:
            self.logger.info("Failed to pull agent")
        self.docker_client.containers.run(detach=True, **compose["services"]["lr-agent"])

    def start_resolver(self):
        compose = self.compose_reader("resolver-compose.yml")
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/create".format(self.proxy_address, self.agent_id),
                json={"compose": compose,
                      "config": ["net.ipv6 = false", "net.listen('0.0.0.0')", "net.listen('0.0.0.0', {tls=true})",
                                 "trust_anchors.file = '/etc/kres/root.keys'",
                                 "modules = { 'hints', 'policy', 'stats', 'predict', 'whalebone' }",
                                 "cache.storage = 'lmdb:///var/lib/kres/cache'",
                                 "cache.size = os.getenv('KNOT_CACHE_SIZE') * MB"]
                      # "config": {"resolver": [{"path": "kres.conf",
                      #                          "data": ["net.ipv6 = false", "net.listen('0.0.0.0')",
                      #                                   "net.listen('0.0.0.0', {tls=true})",
                      #                                   "trust_anchors.file = '/etc/kres/root.keys'",
                      #                                   "modules = { 'hints', 'policy', 'stats', 'predict', 'whalebone' }",
                      #                                   "cache.storage = 'lmdb://var/lib/kres/cache'",
                      #                                   "cache.size = os.getenv('KNOT_CACHE_SIZE') * MB"],
                      #                          "type": "text"}]}
                      })
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
                json={"compose": compose,
                      "config": ["net.ipv6 = false", "net.listen('0.0.0.0')", "net.listen('0.0.0.0', {tls=true})",
                                 "trust_anchors.file = '/etc/kres/root.keys'",
                                 "modules = { 'hints', 'policy', 'stats', 'predict', 'whalebone' }",
                                 "cache.storage = 'lmdb:///var/lib/kres/cache'",
                                 "cache.size = os.getenv('KNOT_CACHE_SIZE') * MB"],
                      # "config": {"resolver": [{"path": "kres.conf",
                      #                          "data": ["net.ipv6 = false", "net.listen('0.0.0.0')",
                      #                                   "net.listen('0.0.0.0', {tls=true})",
                      #                                   "trust_anchors.file = '/etc/kres/root.keys'",
                      #                                   "modules = { 'hints', 'policy', 'stats', 'predict', 'whalebone' }",
                      #                                   "cache.storage = 'lmdb://var/lib/kres/cache'",
                      #                                   "cache.size = os.getenv('KNOT_CACHE_SIZE') * MB"],
                      #                          "type": "text"}]},
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
                json={"compose": compose, "services": ["lr-agent"]})
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
            for key, value in rec.items():
                if key == "containers":
                    self.logger.info("Containers: {}".format(value))
                    if set(containers).issubset(set(value.keys())):
                        self.logger.info("All services are up")
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
                json={"containers": ["mega_rotate"]})
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
                json={"containers": ["passivedns"]})
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

    # def dns_queries(self):
    #     try:
    #         dst_ip = os.environ["RESOLVER_IP"]
    #     except KeyError:
    #         dst_ip = "localhost"
    #     res = resolver.Resolver()
    #     res.nameservers = [dst_ip]
    #     # src_ips = ["192.168.1.2", "192.168.1.3", "127.0.0.1"]
    #     try:
    #         src_ips = os.environ["SOURCE_IP"].split(",")
    #     except KeyError:
    #         src_ips = ["localhost"]
    #     tested_domains = {"malware.com": {"192.168.1.2": "block", "192.168.1.3": "block"},
    #                       "test.com": {"192.168.1.2": "block", "192.168.1.3": "block"}}
    #     for domain in tested_domains:
    #         for ip in src_ips:
    #             answer = res.query(domain, source=ip)
    #             # send(IP(dst=dst_ip, src=ip) / UDP(sport=17395) / DNS(rd=1, qd=DNSQR(qname=domain)))
    #     if self.check_resolver_logs(tested_domains):
    #         self.logger.info("Resolver test successful")
    #     else:
    #         self.logger.info("Resolver test failed, failures are shown above")

    def check_resolver_logs(self, domains: dict) -> bool:
        result = True
        with open("/etc/whalebone/log/whalebone.log", "r") as log_file:
            for log in log_file:
                log = json.loads(log)
                try:
                    if domains[log["domain"]][log["client_ip"]] == log["action"]:
                        continue
                    else:
                        result = False
                        self.logger.info(
                            "Action mismatch for domain {} with action".format(log["domain"], log["action"]))
                except KeyError as e:
                    self.logger.info("Something not found in data {}".format(e))
            return result

    def view_config(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/containers".format(self.proxy_address, self.agent_id))
        except Exception as e:
            self.logger.warning(e)
        else:
            return json.loads(rec.text)

    def get_rules(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/fwrules".format(self.proxy_address, self.agent_id))
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            self.logger.info(rec)
            for rule in rec:
                if rule["info"] in self.firewall_rules:
                    self.logger.info("Rule found with rule text: {}".format(rule["info"]))
                else:
                    self.logger.info("Rule not found: {}".format(rule["info"]))

    def get_rule_info(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/fwfetch".format(self.proxy_address, self.agent_id), data="0")
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            self.logger.info(rec)
            if rec["info"] in self.firewall_rules:
                self.logger.info("Rule found with rule text: {}".format(rec["info"]))
            else:
                self.logger.info("Rule not found: {}".format(rec["info"]))

    def delete_rule(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/fwdelete".format(self.proxy_address, self.agent_id),
                json={"rules_ids": ["0"]})
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            if rec["0"]["status"] == "success":
                self.logger.info("Rule deleted successfuly")
            else:
                self.logger.info("Rule not deleted: {}".format(rec["info"]))

    def modify_rule(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/fwmodify".format(self.proxy_address, self.agent_id),
                json={"rule": ["1", "active", "false"]})
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            if rec["status"] == "success":
                self.logger.info("Rule modified successfully")
            else:
                self.logger.info("Rule not deleted: {}".format(rec["info"]))

    def get_logs(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/logs".format(self.proxy_address, self.agent_id))
        except Exception as e:
            self.logger.info(e)
        else:
            files = ["agent-docker-connector.log", "agent-lr-agent.log", "agent-local-api.log"]
            rec = json.loads(rec.text)
            if set(rec) == set(files):
                self.logger.info("Log files are identical")
            else:
                self.logger.info("Log files are different: {}".format(rec))

    def delete_log(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/dellogs".format(self.proxy_address, self.agent_id),
                json={"files": ["agent-docker-connector.log"]})
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            if rec["agent-docker-connector.log"]["status"] == "success":
                self.logger.info("Log deleted successfully")
            else:
                self.logger.info("Log not deleted: {}".format(rec["info"]))

    def update_cache(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/updatecache".format(self.proxy_address, self.agent_id))
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            if rec["status"] == "success":
                self.logger.info("Cache updated successfully")
            else:
                self.logger.info("Cache update failed")

    def save_config(self):
        try:
            rec = requests.post(
                "http://{}:8080/wsproxy/rest/message/{}/saveconfig".format(self.proxy_address, self.agent_id), json={
                    "config": {"passivends":[{"path": "image.png",
                                            "data": "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",
                                            "type": "base64"}, {"path": "config.json", "data": {"test":"test"},
                                                                "type": "json"}]}})
        except Exception as e:
            self.logger.info(e)
        else:
            rec = json.loads(rec.text)
            self.logger.info(rec)
            for key, value in rec.items():
                if value["status"] == "success":
                    self.logger.info("Service {} config dumped successfuly".format(key))
                else:
                    self.logger.info("Config dump failed {}".format(value))

    async def local_test_remove(self):
        async with websockets.connect('ws://localhost:8765') as websocket:
            # remove all services
            try:
                request = json.dumps({"action": "remove", "data": {
                    "containers": ["resolver", "kresman", "passivedns", "logstream", "logrotate"]}})
                await websocket.send(request)
            except Exception as e:
                self.logger.info("Error at remove {}".format(e))
            else:
                response = await websocket.recv()
                response = json.loads(response)
                for key, value in response["data"].items():
                    if value["status"] == "success":
                        self.logger.info("{} removed successfully".format(key))
                    else:
                        self.logger.info("{} failed to remove".format(key))

    async def local_test_create(self):
        async with websockets.connect('ws://localhost:8765') as websocket:
            try:
                # compose = self.compose_reader("resolver-compose.yml")
                # request = json.dumps(
                #     {"action": "create", "data": {"config": {"resolver": [{"path": "kres.conf",
                #                                                                                "data": [
                #                                                                                    "net.ipv6 = false",
                #                                                                                    "net.listen('0.0.0.0')",
                #                                                                                    "net.listen('0.0.0.0', {tls=true})",
                #                                                                                    "trust_anchors.file = '/etc/kres/root.keys'",
                #                                                                                    "modules = { 'hints', 'policy', 'stats', 'predict', 'whalebone' }",
                #                                                                                    "cache.storage = 'lmdb://var/lib/kres/cache'",
                #                                                                                    "cache.size = os.getenv('KNOT_CACHE_SIZE') * MB"],
                #                                                                                "type": "text"}]}}})
                request = json.dumps({"action": "create", "data": {}})
                await websocket.send(request)
                response = await websocket.recv()
            except Exception as e:
                self.logger.info("Error at start {}".format(e))
            else:
                response = json.loads(response)
                for key, value in response["data"].items():
                    if value["status"] == "success":
                        self.logger.info("{} started successfully".format(key))
                    else:
                        self.logger.info("{} failed to start".format(key))

    async def local_test_restart(self):
        async with websockets.connect('ws://localhost:8765') as websocket:
            try:
                request = json.dumps({"action": "upgrade", "data": {"services": ["passivedns", "logrotate"]}})
                await websocket.send(request)
                response = await websocket.recv()
            except Exception as e:
                self.logger.info("Error at restart {}".format(e))
            else:
                response = json.loads(response)
                for key, value in response["data"].items():
                    if value["status"] == "success":
                        self.logger.info("{} restarted successfully".format(key))
                    else:
                        self.logger.info("{} failed to restart".format(key))

    async def local_test_rename(self):
        async with websockets.connect('ws://localhost:8765') as websocket:
            try:
                request = json.dumps({"action": "rename", "data": {"passivedns": "megarotate"}})
                await websocket.send(request)
                response = await websocket.recv()
            except Exception as e:
                self.logger.info("Error at rename {}".format(e))
            else:
                response = json.loads(response)
                for key, value in response["data"].items():
                    if value["status"] == "success":
                        self.logger.info("{} renamed successfully".format(key))
                    else:
                        self.logger.info("{} failed to rename".format(key))

    async def local_test_stop(self):
        async with websockets.connect('ws://localhost:8765') as websocket:
            try:
                request = json.dumps({"action": "stop", "data": {"containers": ["megarotate"]}})
                await websocket.send(request)
                response = await websocket.recv()
            except Exception as e:
                self.logger.info("Error at stop {}".format(e))
            else:
                response = json.loads(response)
                for key, value in response["data"].items():
                    if value["status"] == "success":
                        self.logger.info("{} stoped successfully".format(key))
                    else:
                        self.logger.info("{} failed to stop".format(key))

    async def local_test_sysinfo(self):
        async with websockets.connect('ws://localhost:8765') as websocket:
            try:
                request = json.dumps({"action": "sysinfo"})
                await websocket.send(request)
                response = await websocket.recv()
            except Exception as e:
                self.logger.info("Error at restart {}".format(e))
            else:
                response = json.loads(response)
                for key, value in response["data"].items():
                    if key == "containers":
                        self.logger.info("Containers: {}".format(value))
                    if key == "cpu":
                        self.logger.info("cpu: " + str(value))
                    if key == "memory":
                        self.logger.info("memory: " + str(value))
                    if key == "hdd":
                        self.logger.info("hdd: " + str(value))


    def run_test(self):
        time.sleep(10)
        try:
            self.start_agent()
        except Exception as e:
            self.logger.info(e)
        time.sleep(8)
        try:
            self.start_resolver()
        except Exception as e:
            self.logger.info(e)
        time.sleep(8)
        try:
            self.upgrade_agent()
        except Exception as e:
            self.logger.info(e)
        time.sleep(8)
        # try:
        #     self.inject_rules()
        # except Exception as e:
        #     self.logger.info(e)
        try:
            self.upgrade_resolver()
        except Exception as e:
            self.logger.info(e)
        # try:
        #     self.dns_queries()
        # except Exception as e:
        #     self.logger.info(e)
        try:
            self.get_sysinfo()
        except Exception as e:
            self.logger.info(e)
        try:
            self.rename_container()
        except Exception as e:
            self.logger.info(e)
        try:
            self.stop_container()
        except Exception as e:
            self.logger.info(e)
        try:
            self.remove_container()
        except Exception as e:
            self.logger.info(e)
        # try:
        #     self.get_rules()
        # except Exception as e:
        #     self.logger.info(e)
        # try:
        #     self.get_rule_info()
        # except Exception:
        #     pass
        # try:
        #     self.delete_rule()
        # except Exception as e:
        #     self.logger.info(e)
        # try:
        #     self.modify_rule()
        # except Exception as e:
        #     self.logger.info(e)
        try:
            self.get_logs()
        except Exception as e:
            self.logger.info(e)
        try:
            self.delete_log()
        except Exception as e:
            self.logger.info(e)
        try:
            self.update_cache()
        except Exception as e:
            self.logger.info(e)
        try:
            self.save_config()
        except Exception as e:
            self.logger.info(e)
        time.sleep(60)
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.local_test_remove())
        except Exception as e:
            self.logger.info(e)
        try:
            loop.run_until_complete(self.local_test_create())
        except Exception as e:
            self.logger.info(e)
        try:
            loop.run_until_complete(self.local_test_restart())
        except Exception as e:
            self.logger.info(e)
        try:
            loop.run_until_complete(self.local_test_rename())
        except Exception as e:
            self.logger.info(e)
        try:
            loop.run_until_complete(self.local_test_stop())
        except Exception as e:
            self.logger.info(e)
        try:
            loop.run_until_complete(self.local_test_sysinfo())
        except Exception as e:
            self.logger.info(e)

if __name__ == '__main__':
    tester = Tester()
    tester.run_test()
