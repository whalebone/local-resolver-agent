import traceback

import psutil
import platform
import socket
import re
import os
from dns import resolver


def get_system_info(docker_connector, error_stash: dict):
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    du = psutil.disk_usage('/')
    return {
        'hostname': platform.node(),
        'system': platform.system(),
        'platform': get_platform(),
        'cpu': {
            'count': psutil.cpu_count(),
            'usage': psutil.cpu_percent()
        },
        'memory': {
            'total': to_gigabytes(mem.total),
            'available': to_gigabytes(mem.available),
            'usage': mem.percent,
        },
        'hdd': {
            'total': to_gigabytes(du.total),
            'free': to_gigabytes(du.free),
            'usage': du.percent,
        },
        "swap": {
            'total': to_gigabytes(swap.total),
            'free': to_gigabytes(swap.free),
            'usage': swap.percent,
        },
        "resolver": process_stats_output(),
        "docker": docker_connector.docker_version(),
        "check": {"resolve": check_resolving(), "port": check_port(docker_connector)},
        "containers": {container.name: container.status for container in docker_connector.get_containers()},
        "images": get_images(docker_connector),
        "error_messages": error_stash,
        'interfaces': get_interfaces()
    }


def get_interfaces():
    interfaces = []
    for interface_name, interface_info_list in psutil.net_if_addrs().items():
        interface = {'name': interface_name, 'addresses': []}
        for addr_info in interface_info_list:
            interface['addresses'].append(addr_info.address)
        interfaces.append(interface)
    return interfaces


def get_platform():
    try:
        with open("/opt/host/etc/os-release", "r") as file:
            for line in file:
                if line.startswith("PRETTY"):
                    return line.split("\"")[1]
    except Exception:
        return "Unknown"


def get_images(docker_connector):
    containers = {}
    for container in docker_connector.get_containers():
        try:
            containers[container.name] = container.image.tags[0]
        except IndexError:
            pass
    return containers


def to_gigabytes(stat):
    return round(stat / (1024**3), 1)


def check_resolving():
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


def check_port(docker_connector, service: str = "resolver"):
    try:
        if "kresd" in docker_connector.container_exec(service,
                                                      ["sh", "-c", "netstat -tupan | grep kresd | grep 53"]):
            return "ok"
    except Exception:
        pass
    return "fail"


def get_resolver_stats(tty: str) -> str:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(tty)
    except socket.error as msg:
        print("Connection error {} to socket {}".format(msg, tty))
    else:
        try:
            message = b"map 'stats.list()'"
            sock.sendall(message)

            amount_received, amount_expected = 0,  len(message)
            while amount_received < amount_expected:
                data = sock.recv(65535)
                amount_received += len(data)
            return data.decode("utf-8")
        except Exception as e:
            print("Failed to get data, {}".format(e))
        finally:
            sock.close()
    return ""


def parse_stats_output(stats: str) -> dict:
    result = {}
    for line in stats.split("\n"):
        splitted_line = re.findall(r"[\w']+", line)
        if len(splitted_line) == 3:
            result["{}.{}".format(splitted_line[0], splitted_line[1])] = splitted_line[2]
    return result


def process_stats_output() -> dict:
    stats_results = {}
    for tty in os.listdir("/etc/whalebone/tty/"):
        try:
            stats = get_resolver_stats("/etc/whalebone/tty/{}".format(tty))
            if stats:
                stats = parse_stats_output(stats)
                if stats:
                    for stat_name, count in stats.items():
                        try:
                            stats_results[stat_name] += int(count)
                        except KeyError:
                            stats_results[stat_name] = int(count)
        except Exception as e:
            print("Failed to get data from kres instance {}, {}".format(tty, e))
    if stats_results:
        return stats_results
    else:
        return {"error": "no data"}
