import base64
import netifaces


def create_docker_run_kwargs(compose_fragment: dict) -> dict:
    kwargs = {}
    for name, definition in compose_fragment.items():
        param_def = SUPPORTED_PARAMETERS[name]
        if isinstance(param_def, dict):
            parse_method = param_def['fn']
            kwarg_name = param_def['name']
        else:
            parse_method = param_def
            kwarg_name = name
        kwargs[kwarg_name] = parse_method(compose_fragment[name])
    return kwargs


def parse_value(value):
    return value


def parse_logging(logging: dict) -> dict:
    return {"type": logging["driver"], "config": logging["options"]}


def parse_envs(envs: dict) -> dict:
    file_mapping = {"CLIENT_CRT_BASE64": "client.crt", "CLIENT_KEY_BASE64": "client.key"}
    for name, value in envs.items():
        if name in file_mapping:
            envs[name] = read_file(file_mapping[name])
        if name == "DNS_INTERFACE" and value == "":
            for interface in netifaces.gateways()["default"].values():
                envs["DNS_INTERFACE"] = interface[1]
    return envs


def parse_ports(ports_list: list) -> dict:
    ports_dict = {}
    for port in ports_list:
        port_def = port.split(':')
        try:
            ports_dict[port_def[1]] = int(port_def[0])
        except IndexError:
            raise Exception("Invalid format of 'ports' definition: {0}".format(port))
    return ports_dict


def parse_volumes(volumes_list: list) -> dict:
    volumes = {}
    for volume in volumes_list:
        volume_def = volume.split(':')
        try:
            volumes[volume_def[0]] = {
                'bind': volume_def[1], 'mode': "rw"
            }
        except IndexError:
            raise Exception("Invalid format(short syntax supported only) of 'volumes' definition: {0}".format(volume))
        else:
            if len(volume_def) == 3:
                volumes[volume_def[0]]['mode'] = volume_def[2]
    return volumes


def parse_restart_policy(restart_policy: str):
    policies = {"on-failure": {'Name': restart_policy, 'MaximumRetryCount': 5}, "always": {'Name': restart_policy}}
    try:
        return policies[restart_policy]
    except KeyError:
        return None


def parse_tmpfs(value: str) -> dict:
    return {value: ""}


def read_file(file_name: str) -> str:
    with open("/opt/whalebone/certs/{}".format(file_name), "r") as file:
        return base64.b64encode(file.read().encode("utf-8")).decode("utf-8")


SUPPORTED_PARAMETERS = {
    'image': parse_value,
    'net': {'fn': parse_value, 'name': 'network_mode'},
    'network_mode': parse_value,
    'dns': parse_value,
    'pid_mode': parse_value,
    'mem_limit': parse_value,
    'ports': parse_ports,
    'volumes': parse_volumes,
    'labels': parse_value,
    'tmpfs': parse_tmpfs,
    'environment': parse_envs,
    'tty': parse_value,
    'privileged': parse_value,
    "cap_add": parse_value,
    'stdin_open': parse_value,
    'restart': {'fn': parse_restart_policy, 'name': 'restart_policy'},
    'cpu_shares': parse_value,
    'name': parse_value,
    'logging': {'fn': parse_logging, 'name': 'log_config'}
    # 'log_driver': None,  # special formatting together with log_opt <1
    # 'log_opt': None,  # special formatting together with log_driver <
}
