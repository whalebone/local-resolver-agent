import base64
import netifaces


def create_docker_run_kwargs(service_compose_fragmet):
    kwargs = {}
    # for compose_param_name in SUPPORTED_PARAMETERS_V1:
    #     param_def = SUPPORTED_PARAMETERS_V1[compose_param_name]
    #     if param_def is None or compose_param_name not in service_compose_fragmet:
    #         # skip this param since it has some specific or not specified in compose
    #         continue
    for name, definition in service_compose_fragmet.items():
        param_def = SUPPORTED_PARAMETERS_V1[name]
        # if param_def is not None:
        if isinstance(param_def, dict):
            parse_fn = param_def['fn']
            kwarg_param_name = param_def['name']
            # docker-compose key has different name than the kwarg of run method,'name' is kwarg key and fn fuction for value
        else:
            parse_fn = param_def
            kwarg_param_name = name
        kwargs[kwarg_param_name] = parse_fn(service_compose_fragmet[name])
            # kwarg_param_value = parse_fn(service_compose_fragmet[name])
            # if kwarg_param_value is not None:
            # kwargs[kwarg_param_name] = kwarg_param_value
    # if 'logging' in service_compose_fragmet:
    #     kwargs['log_config'] = {
    #         'type': service_compose_fragmet['logging']['driver'],
    #         'config': service_compose_fragmet['logging']['options']
    #     }
        # if 'log_opt' in service_compose_fragmet:
        #     kwargs['log_config']['config'] = service_compose_fragmet['logging']['options']
    return kwargs


def parse_value(value):
    return value


def parse_logging(logging):
    return {"type": logging["driver"], "config": logging["options"]}


def parse_envs(envs):
    file_mapping = {"CLIENT_CRT_BASE64": "client.crt", "CLIENT_KEY_BASE64": "client.key"}
    for name, value in envs.items():
        if name in file_mapping:
            envs[name] = read_file(file_mapping[name])
        if name == "DNS_INTERFACE" and value == "":
            for interface in netifaces.gateways()["default"].values():
                envs["DNS_INTERFACE"] = interface[1]
    return envs


def parse_ports(ports_list):
    # if len(ports_list) == 0:
    #     return None
    ports_dict = {}
    for port in ports_list:
        port_def = port.split(':')
        try:
            ports_dict[port_def[1]] = int(port_def[0])
        except IndexError:
            raise Exception("Invalid format of 'ports' definition: {0}".format(port))
    return ports_dict


def parse_volumes(volumes_list):
    # if len(volumes_list) == 0:
    #     return None
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


def parse_restart_policy(restart_policy):
    policies = {"on-failure": {'Name': restart_policy, 'MaximumRetryCount': 5}, "always": {'Name': restart_policy}}
    try:
        return policies[restart_policy]
    except KeyError:
        return None


def read_file(file_name:str)->str:
    with open("/opt/whalebone/certs/{}".format(file_name), "r") as file:
        return base64.b64encode(file.read().encode("utf-8")).decode("utf-8")


SUPPORTED_PARAMETERS_V1 = {
    'image': parse_value,  # not part of kwargs
    'net': {'fn': parse_value, 'name': 'network_mode'},  # <1
    'network_mode': parse_value,
    'dns': parse_value,
    'pid_mode': parse_value,
    'mem_limit': parse_value, # <1
    'ports': parse_ports,
    'volumes': parse_volumes,
    'labels': parse_value,
    'environment': parse_envs,
    'tty': parse_value,
    'privileged': parse_value,
    'stdin_open': parse_value,
    'restart': {'fn': parse_restart_policy, 'name': 'restart_policy'},
    'cpu_shares': parse_value,  # <1
    'name': parse_value,
    'logging': {'fn': parse_logging, 'name': 'log_config'}
    # 'log_driver': None,  # special formatting together with log_opt <1
    # 'log_opt': None,  # special formatting together with log_driver <
}
