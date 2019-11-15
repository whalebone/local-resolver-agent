import traceback
import json
import psutil
import platform
import socket
import re
import os
from datetime import datetime
from dns import resolver


class SystemInfo:

    def __init__(self, docker_connector, logger, error_stash: dict = None, request: dict = None):
        if error_stash is None:
            error_stash = {}
        if request is None:
            request = {}
        self.docker_connector = docker_connector
        self.error_stash = error_stash
        self.request = request
        self.logger = logger

    def get_interfaces(self):
        interfaces = []
        for interface_name, interface_info_list in psutil.net_if_addrs().items():
            interface = {'name': interface_name, 'addresses': []}
            for addr_info in interface_info_list:
                interface['addresses'].append(addr_info.address)
            interfaces.append(interface)
        return interfaces

    def get_platform(self):
        try:
            with open("/opt/host/etc/os-release", "r") as file:
                for line in file:
                    if line.startswith("PRETTY"):
                        return line.split("\"")[1]
        except Exception:
            return "Unknown"

    def get_images(self):
        containers = {}
        for container in self.docker_connector.get_containers():
            try:
                containers[container.name] = container.image.tags[0]
            except IndexError:
                pass
        return containers

    def to_gigabytes(self, stat):
        return round(stat / (1024 ** 3), 1)

    def check_resolving(self):
        domains = ["google.com", "microsoft.com", "apple.com", "facebook.com"]
        res = resolver.Resolver()
        res.nameservers = ["127.0.0.1"]
        res.timeout = 1
        res.lifetime = 1
        for domain in domains:
            try:
                res.query(domain)
                return "ok"
            except Exception:
                pass
        return "fail"

    def check_port(self, service: str = "resolver"):
        try:
            if "kresd" in self.docker_connector.container_exec(service,
                                                               ["sh", "-c", "netstat -tupan | grep kresd | grep 53"]):
                return "ok"
        except Exception:
            pass
        return "fail"

    def result_manipulation(self, mode: str, results: dict = None):
        with open("/etc/whalebone/kres_stats.json", mode) as file:
            if mode == "w":
                json.dump(results, file)
            else:
                return json.load(file)

    def resurrect_resolver(self, pid: str) -> bool:
        try:
            returned_text = self.docker_connector.container_exec("resolver", ["sh", "-c", "kill -9 {}".format(pid)])
        except Exception as e:
            self.logger.warning("Failed to kill tty {}, {}".format(pid, e))
        else:
            self.logger.info("Recovery: kill sent with response: {}".format(returned_text))
        if self.docker_connector.container_exec("resolver",
                                                ["sh", "-c", "ps -A | grep kresd | grep {}".format(pid)]) != "":
            self.logger.info("Recovery: pid found in ps")
            if "resolver-old" not in [container.name for container in self.docker_connector.get_containers()]:
                try:
                    self.docker_connector.restart_resolver()
                except Exception as e:
                    self.logger.warning("Failed to restart resolver, {}".format(e))
                else:
                    self.logger.info("Recovery: resolver restart command sent")
                    return True

    def get_resolver_stats(self, tty: str) -> str:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(tty)
        except socket.timeout as te:
            self.logger.warning("Timeout of socket {} reading, {}".format(tty, te))
        except socket.error as msg:
            self.logger.warning("Connection error {} to socket {}".format(msg, tty))
        else:
            try:
                message = b"stats.list()"
                sock.sendall(message)
                amount_received, amount_expected = 0, len(message)
                while amount_received < amount_expected:
                    data = sock.recv(65535)
                    amount_received += len(data)
                return data.decode("utf-8")
            except socket.timeout as re:
                self.logger.warning("Failed to get data from scoket {}, {}".format(tty, re))
            except Exception as e:
                self.logger.warning("Failed to get data from {}, {}".format(tty, e))
            finally:
                sock.close()
        return ""

    def parse_stats_output(self, stats: str) -> dict:
        result = {}
        for line in stats.split("\n"):
            splitted_line = re.findall(r"[\w']+", line)
            if len(splitted_line) == 3:
                result["{}.{}".format(splitted_line[0], splitted_line[1])] = splitted_line[2]
        return result

    def result_diff(self, results: dict) -> dict:
        try:
            if results:
                if "requestId" in self.request and self.request["requestId"] == "666":
                    return results
                try:
                    previous = self.result_manipulation("r")
                except FileNotFoundError:
                    return results
                else:
                    return {stat: value - previous[stat] for stat, value in results.items() if stat in previous}
                finally:
                    self.result_manipulation("w", results)
        except Exception as e:
            self.logger.warning("Failed to create resolver diff {}".format(e))
        return {"error": "no data"}

    def process_stats_output(self) -> dict:
        stats_results = {}
        for tty in os.listdir("/etc/whalebone/tty/"):
            try:
                stats = self.get_resolver_stats("/etc/whalebone/tty/{}".format(tty))
                if stats:
                    stats = self.parse_stats_output(stats)
                    if stats:
                        for stat_name, count in stats.items():
                            try:
                                stats_results[stat_name] += int(count)
                            except KeyError:
                                stats_results[stat_name] = int(count)
                else:
                    if self.resurrect_resolver(tty):
                        break
            except Exception as e:
                self.logger.warning("Failed to get data from kres instance {}, {}".format(tty, e))
        return self.result_diff(stats_results)

    def get_info_static(self) -> dict:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        du = psutil.disk_usage('/')
        return {
            'hostname': platform.node(),
            'system': platform.system(),
            'platform': self.get_platform(),
            'cpu': {
                'count': psutil.cpu_count(),
                'usage': psutil.cpu_percent()
            },
            'memory': {
                'total': self.to_gigabytes(mem.total),
                'available': self.to_gigabytes(mem.available),
                'usage': mem.percent,
            },
            'hdd': {
                'total': self.to_gigabytes(du.total),
                'free': self.to_gigabytes(du.free),
                'usage': du.percent,
            },
            "swap": {
                'total': self.to_gigabytes(swap.total),
                'free': self.to_gigabytes(swap.free),
                'usage': swap.percent,
            },
            "docker": self.docker_connector.docker_version(),
            "check": {"resolve": self.check_resolving(), "port": self.check_port()},
            "containers": {container.name: container.status for container in self.docker_connector.get_containers()},
            "images": self.get_images(),
            "error_messages": self.error_stash,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            'interfaces': self.get_interfaces()
        }

    def get_system_info(self):
        static_info = self.get_info_static()
        resolver_data = self.process_stats_output()
        if "error" in resolver_data:
            static_info["check"]["resolve"] = "recovery"
        static_info["resolver"] = resolver_data
        return static_info
