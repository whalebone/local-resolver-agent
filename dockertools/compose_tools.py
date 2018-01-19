from exception.exc import ComposeException


def create_docker_run_kwargs(service_compose_fragmet):
    kwargs = dict()

    for compose_param_name in SUPPORTED_PARAMETERS_V1:
        param_def = SUPPORTED_PARAMETERS_V1[compose_param_name]
        if param_def is None or compose_param_name not in service_compose_fragmet:
            # skip this param since it has some specific or not specified in compose
            continue
        if isinstance(param_def, dict):
            parse_fn = param_def['fn']
            kwarg_param_name = param_def['name']
        else:
            parse_fn = param_def
            kwarg_param_name = compose_param_name
        kwarg_param_value = parse_fn(service_compose_fragmet[compose_param_name])
        if kwarg_param_value is not None:
            kwargs[kwarg_param_name] = kwarg_param_value

    if 'log_driver' in service_compose_fragmet and service_compose_fragmet['log_driver'] is not None:
        kwargs['log_config'] = {
            'type': service_compose_fragmet['log_driver']
        }
        if 'log_opt' in service_compose_fragmet and service_compose_fragmet['log_opt'] is not None:
            kwargs['log_config']['config'] = service_compose_fragmet['log_opt']
    return kwargs


def parse_value(value):
    return value


def parse_ports(ports_list):
    if ports_list is None or len(ports_list) == 0:
        return None
    ports_dict = dict()
    for port in ports_list:
        port_def = port.split(':')
        if len(port_def) != 2:
            raise ComposeException("Invalid format of 'ports' definition: {0}".format(port))
        try:
            ports_dict[port_def[1]] = int(port_def[0])
        except ValueError:
            raise ComposeException("Invalid format of 'ports' definition: {0}".format(port))
    return ports_dict


def parse_volumes(volumes_list):
    if volumes_list is None or len(volumes_list) == 0:
        return None
    volumes_dict = dict()
    for volume in volumes_list:
        volume_def = volume.split(':')
        if len(volume_def) < 2 or len(volume_def) > 3:
            raise ComposeException("Invalid format(short syntax supported only) of 'volumes' definition: {0}".format(volume))
        volumes_dict[volume_def[0]] = {
            'bind': volume_def[1]
        }
        if len(volume_def) == 3:
            volumes_dict[volume_def[0]]['mode'] = volume_def[2]
        else:
            volumes_dict[volume_def[0]]['mode'] = 'rw'
    return volumes_dict


def parse_restart_policy(restart_policy):
    if restart_policy is None:
        return None
    return {
        'Name': restart_policy,
        'MaximumRetryCount': 5
    }


SUPPORTED_PARAMETERS_V1 = {
    'image': None, # not part of kwargs
    'net': {'fn': parse_value, 'name': 'network_mode'},
    'ports': parse_ports,
    'volumes': parse_volumes,
    'environment': parse_value,
    'tty': parse_value,
    'privileged': parse_value,
    'stdin_open': parse_value,
    'restart': {'fn': parse_restart_policy, 'name': 'restart_policy'},
    'log_driver': None, # special formatting together with log_opt
    'log_opt': None, # special formatting together with log_driver
}