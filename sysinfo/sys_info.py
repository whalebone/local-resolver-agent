import requests
import json
import psutil
import errno
import platform
import socket
import re
import os
from datetime import datetime
from dns import resolver


class SystemInfo:

    def __init__(self, docker_connector, logger):
        self.docker_connector = docker_connector
        self.logger = logger
        # self.kresman_token = token
        self.kresman_timeout = int(os.environ.get("HTTP_TIMEOUT", 10))
        self.net_mapping = {"bytes_sent": "bytes_sent", "bytes_received": "bytes_received", "packets_sent": "packets_sent",
                            "packets_recv": "packets_received", "errin": "err_receiving", "errout": "err_sending",
                            "dropin": "dropped_in", "dropout": "dropped_out"}
        self.disk_mapping = ("read_count", "write_count", "read_bytes", "write_bytes", "read_time", "write_time",
                             "busy_time")

    def get_interfaces(self) -> list:
        interfaces = []
        for interface_name, interface_info_list in psutil.net_if_addrs().items():
            interfaces.append(
                {'name': interface_name, 'addresses': [addr_info.address for addr_info in interface_info_list if
                                                       addr_info.family in (socket.AF_INET, socket.AF_INET6)]})
        return interfaces

    def get_network_info(self) -> dict:
        try:
            counters = psutil.net_io_counters()
        except Exception as e:
            self.logger.warning("Failed to get network counters {}.".format(e))
            return {}
        else:
            return {attr_name: getattr(counters, psutil_attr, 0) for psutil_attr, attr_name in self.net_mapping.items()}

    def get_disk_info(self) -> dict:
        try:
            counters = psutil.disk_io_counters()
        except Exception as e:
            self.logger.warning("Failed to get disk iops counters {}.".format(e))
            return {}
        else:
            return {attr_name: getattr(counters, attr_name, 0) for attr_name in self.disk_mapping}

    def get_platform(self) -> str:
        try:
            with open("/opt/host/etc/os-release", "r") as file:
                for line in file:
                    if line.startswith("PRETTY"):
                        return line.split("\"")[1]
        except Exception:
            return "Unknown"

    def get_images(self) -> dict:
        containers = {}
        for container in self.docker_connector.get_containers():
            try:
                containers[container.name] = container.attrs["Config"]["Image"]
            except KeyError:
                pass
        return containers

    def to_gigabytes(self, stat: int) -> int:
        return round(stat / (1024 ** 3), 1)

    def check_resolving(self) -> str:
        domains = ("google.com", "microsoft.com", "apple.com", "facebook.com")
        res = resolver.Resolver()
        res.nameservers = ["127.0.0.1"]
        res.timeout = int(os.environ.get("DNS_TIMEOUT", 3))
        res.lifetime = int(os.environ.get("DNS_LIFETIME", 3))
        for domain in domains:
            try:
                res.resolve(domain)
                return "ok"
            except Exception:
                pass
        return "fail"

    def check_port(self, service: str = "resolver") -> str:
        try:
            if "kresd" in self.docker_connector.container_exec(service,
                                                               ["sh", "-c", "netstat -tupan | grep kresd | grep 53"]):
                return "ok"
        except Exception:
            pass
        return "fail"

    def result_manipulation(self, mode: str, results: dict = None):
        with open("/etc/whalebone/logs/kres_stats.json", mode) as file:
            if mode == "w":
                json.dump(results, file)
            else:
                return json.load(file)

    def get_kresman_metrics(self) -> dict:
        address = os.environ.get("KRESMAN_LISTENER", "http://127.0.0.1:8080")
        try:
            msg = requests.get("{}/api/general/countentities".format(address), timeout=self.kresman_timeout,
                               # headers={'accept': '*/*', 'Content-Type': 'application/json',
                               #          'Authorization': 'Bearer {}'.format(self.kresman_token)}
                               verify=False)
        except requests.exceptions.RequestException as e:
            self.logger.info("Failed to get data from kresman, {}".format(e))
            return {"error": str(e)}
        else:
            try:
                return {metric["id"]: metric["count"] for metric in msg.json()}
            except Exception as e:
                return {"error": str(e)}

    def get_kresman_internal(self) -> dict:
        address = os.environ.get("KRESMAN_LISTENER", "http://127.0.0.1:8080")
        try:
            msg = requests.get("{}/api/general/metrics".format(address), timeout=self.kresman_timeout,
                               # headers={'accept': '*/*', 'Content-Type': 'application/json',
                               #          'Authorization': 'Bearer {}'.format(self.kresman_token)}
                               verify=False)
        except requests.exceptions.RequestException as e:
            self.logger.info("Failed to get data from kresman, {}".format(e))
            return {"error": str(e)}
        else:
            try:
                return {metric["id"]: metric["value"] for metric in msg.json()}
            except Exception as e:
                return {"error": str(e)}

    def check_resolver_process(self, pid: str) -> str:
        return self.docker_connector.container_exec("resolver",
                                                    ["sh", "-c", "ps -A | grep kresd | grep {}".format(pid)])

    def delete_orphaned_tty(self, tty: str):
        try:
            os.remove(tty)
        except Exception as e:
            self.logger.warning("Failed to delete orphaned tty {}, reason: {}".format(tty, e))
        else:
            self.logger.info("Successfully deleted orphaned tty {}".format(tty))

    def resurrect_resolver(self, pid: str) -> bool:
        if self.check_resolver_process(pid) != "":
            try:
                returned_text = self.docker_connector.container_exec("resolver", ["sh", "-c", "kill -9 {}".format(pid)])
            except Exception as e:
                self.logger.warning("Failed to kill tty {}, {}".format(pid, e))
            else:
                self.logger.info("Recovery: kill sent with response: {}".format(returned_text))
            if self.check_resolver_process(pid) != "":
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
            if msg.errno == errno.ECONNREFUSED and self.check_resolver_process(tty.split("/")[-1]) == "":
                self.delete_orphaned_tty(tty)
                return "cleanup"
        else:
            try:
                message = b"stats.list()\n"
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
        return ""

    def parse_stats_output(self, stats: str) -> dict:
        result = {}
        for line in stats.split("\n"):
            splitted_line = re.findall(r"[\w']+", line)
            if len(splitted_line) == 3:
                result["{}.{}".format(splitted_line[0], splitted_line[1])] = splitted_line[2]
        return result

    def result_diff(self, results: dict, cli_request: bool) -> dict:
        try:
            if results:
                # if "requestId" in request and request["requestId"] == "666":
                #     return results
                if cli_request:
                    return results
                try:
                    previous = self.result_manipulation("r")
                except FileNotFoundError:
                    return {}
                else:
                    pattern = re.compile(r"answer.*|query.*|request.*")
                    stats = {}
                    for stat, value in results.items():
                        if stat in previous:
                            if pattern.match(stat):
                                diff = value - previous[stat]
                                if diff >= 0:
                                    stats[stat] = diff
                            else:
                                stats[stat] = value
                    return stats
                    # stats = {stat:  value - previous[stat] for stat, value in results.items() if stat in previous}
                    # if any(stat_value < 0 for stat_value in stats.values()):
                    #     return {}
                    # else:
                    #     return stats
                finally:
                    self.result_manipulation("w", results)
        except Exception as e:
            self.logger.warning("Failed to create resolver diff {}".format(e))
        return {"error": "no data"}

    def process_stats_output(self, cli_request: bool) -> dict:
        stats_results = {}
        for tty in os.listdir("/etc/whalebone/tty/"):
            try:
                stats = self.get_resolver_stats("/etc/whalebone/tty/{}".format(tty))
                if stats == "cleanup":
                    continue
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
        return self.result_diff(stats_results, cli_request)

    def get_info_static(self, error_stash: dict) -> dict:
        if error_stash is None:
            error_stash = {}
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
            "network_info": self.get_network_info(),
            "disk_iops": self.get_disk_info(),
            "docker": self.docker_connector.docker_version(),
            "check": {"resolve": self.check_resolving(), "port": self.check_port()},
            "containers": {container.name: container.status for container in self.docker_connector.get_containers()},
            "images": self.get_images(),
            "kresman": self.get_kresman_metrics(),
            "kresman_internal": self.get_kresman_internal(),
            "error_messages": error_stash,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            'interfaces': self.get_interfaces()
        }

    def get_system_info(self, error_stash: dict = None, cli_request: bool = False):
        static_info = self.get_info_static(error_stash)
        resolver_data = self.process_stats_output(cli_request)
        if "error" in resolver_data:
            static_info["check"]["resolve"] = "recovery"
        static_info["resolver"] = resolver_data
        return static_info
