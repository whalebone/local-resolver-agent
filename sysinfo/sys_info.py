import psutil
import platform


def get_system_info(docker_connector, error_stash: dict):
    mem = psutil.virtual_memory()
    du = psutil.disk_usage('/')
    sysInfo = {
        'hostname': platform.node(),
        'system': platform.system(),
        'platform': platform.platform(),
        'cpu': {
            'count': psutil.cpu_count(),
            'usage': psutil.cpu_percent()
        },
        'memory': {
            'total': mem.total >> 30,
            'free': mem.free >> 30,
            'usage': mem.percent,
        },
        'hdd': {
            'total': du.total >> 30,
            'free': du.free >> 30,
            'usage': du.percent,
        },
        "docker": docker_connector.docker_version(),
        "containers": {container.name: container.status for container in docker_connector.get_containers(all=True)},
        "error_messages": error_stash,
        'interfaces': get_ifaces()
    }
    return sysInfo


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

