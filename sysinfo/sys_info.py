import psutil
import platform
from dns import resolver


def get_system_info(docker_connector, error_stash: dict):
    mem = psutil.virtual_memory()
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
        "docker": docker_connector.docker_version(),
        # "check": {"resolve": check_resolving(), "port": check_port()},
        "containers": {container.name: container.status for container in docker_connector.get_containers()},
        "images": get_images(docker_connector),
        "error_messages": error_stash,
        'interfaces': get_ifaces()
    }


def get_ifaces():
    interfaces = list()
    for iface_name, iface_addr_info_list in psutil.net_if_addrs().items():
        iface = dict()
        iface['name'] = iface_name
        iface['addresses'] = list()
        for addr_info in iface_addr_info_list:
            iface['addresses'].append(addr_info.address)
        interfaces.append(iface)
    return interfaces


def get_platform():
    try:
        with open("/etc/os-release", "r") as file:
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
    return round(stat / (1024.0 ** 3), 1)


def check_resolving():
    domains = ["google.com", "microsoft.com", "apple.com", "facebook.com"]
    res = resolver.Resolver()
    res.nameservers = ["127.0.0.1"]
    for domain in domains:
        try:
            res.query(domain)
            return "ok"
        except Exception:
            pass
    return "fail"


def check_port():
    ports = {"SocketKind.SOCK_DGRAM": 53, "SocketKind.SOCK_STREAM": 53}
    for proc in psutil.process_iter():
        if proc.name() == "kresd":
            for con in proc.connections():
                port, prot = con.laddr[1], str(con.type)
                try:
                    if ports[prot] == port:
                        del ports[prot]
                except KeyError:
                    pass

    if len(ports) == 0:
        return "ok"
    else:
        return "fail"
