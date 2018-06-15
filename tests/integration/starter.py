import yaml
import docker
import json
import requests
import os
import logging


class ComposeParser:

    def __init__(self):
        self.supported_vesions = ['1', '3']


    def create_service(self, compose_yaml):
        compose = self.parse(compose_yaml)
        self.validate(compose)
        for service_name in compose['services']:
            compose['services'][service_name]["name"] = service_name
        return compose

    def parse(self, compose_yaml):
        try:
            parsed_compose = yaml.load(compose_yaml)
            if 'version' in parsed_compose:
                return parsed_compose
            else:
                # make version '1' compatible
                return {
                    'version': '1',
                    'services': parsed_compose
                }
        except yaml.YAMLError as e:
            raise IOError("Invalid compose YAML format")

    def validate(self, parsed_compose):
        if parsed_compose['version'] not in self.supported_vesions:
            raise IOError("Compose version '{0}' not supported. Supported versions: {1}"
                          .format(parsed_compose['version'], self.supported_vesions))
        if 'services' not in parsed_compose:
            raise IOError("Missing section 'services'")


class ComposeTranslator:

    def __init__(self):
        self.supported_params = {
            'image': None,  # not part of kwargs #
            'net': {'fn': self.parse_value, 'name': 'network_mode'},  # <1
            'network_mode': self.parse_value,
            'ports': self.parse_ports,
            'volumes': self.parse_volumes,
            'labels': self.parse_value,
            'environment': self.parse_value,
            'tty': self.parse_value,
            'privileged': self.parse_value,
            'stdin_open': self.parse_value,
            'restart': {'fn': self.parse_restart_policy, 'name': 'restart_policy'},
            'cpu_shares': self.parse_value,  # <1
            'name': self.parse_value,
            'logging': None,
            'log_driver': None,  # special formatting together with log_opt <1
            'log_opt': None,  # special formatting together with log_driver <
        }

    def create_docker_run_kwargs(self, service_compose_fragmet):
        kwargs = dict()

        for compose_param_name in self.supported_params:
            param_def = self.supported_params[compose_param_name]
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

        if 'logging' in service_compose_fragmet and service_compose_fragmet['logging']['driver'] is not None:
            kwargs['log_config'] = {
                'type': service_compose_fragmet['logging']['driver']
            }
            if 'log_opt' in service_compose_fragmet and service_compose_fragmet['log_opt'] is not None:
                kwargs['log_config']['config'] = service_compose_fragmet['logging']['options']
        return kwargs

    def parse_value(self, value):
        if isinstance(value, float):
            return int(value)
        else:
            return value

    def parse_ports(self, ports_list):
        if ports_list is None or len(ports_list) == 0:
            return None
        ports_dict = dict()
        for port in ports_list:
            port_def = port.split(':')
            if len(port_def) != 2:
                raise Exception("Invalid format of 'ports' definition: {0}".format(port))
            try:
                ports_dict[port_def[1]] = int(port_def[0])
            except ValueError:
                raise Exception("Invalid format of 'ports' definition: {0}".format(port))
        return ports_dict

    def parse_volumes(self, volumes_list):
        if volumes_list is None or len(volumes_list) == 0:
            return None
        volumes_dict = dict()
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

    def parse_restart_policy(self, restart_policy):
        policies = {"on-failure": {'Name': restart_policy, 'MaximumRetryCount': 5}, "always": {'Name': restart_policy}}
        try:
            return policies[restart_policy]
        except KeyError:
            return None


class Agent:
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        try:
            self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')  # hish level api
            self.api_client = docker.APIClient(base_url='unix://var/run/docker.sock')  # low level api
        except Exception:
            self.logger.info("Insufficient permissions to unix://var/run/docker.sock'")
            raise KeyboardInterrupt
        try:
            self.resolver_address = os.environ['LOCAL_RESOLVER_ADDRESS']
        except Exception:
            self.logger.info("Resolver address not found, using localhost")
            self.resolver_address = "localhost"
        self.compose_parser = ComposeParser()
        self.compoer_translator = ComposeTranslator()



    def start_service(self, parsed_compose: dict):
        kwargs = self.compoer_translator.create_docker_run_kwargs(parsed_compose)
        try:
            self.docker_client.containers.run(parsed_compose['image'], detach=True, **kwargs)
        except Exception as e:
            raise InterruptedError(e)

    def inject_all_rules(self):
        try:
            with open("firewall.conf", "r") as file:
                rules = json.load(file)
            for rule in rules:
                self.create_rule(rule)
        except Exception as e:
            raise ConnectionError(e)

    def create_rule(self, rule: str):
        try:
            req = requests.post("http://{}:8053/daf".format(self.resolver_address), data=rule)
        except Exception as e:
            self.logger.info("Error at rule injection, {}".format(e))
        else:
            return req.text

    def create_container(self):
        try:
            with open("docker-compose.yml", "r") as file:
                decoded_data = file.read()
        except Exception:
            self.logger.info("Docker compose not found")
        else:
            try:
                parsed_compose = self.compose_parser.create_service(decoded_data)
            except IOError as e:
                self.logger.info(e)
            else:
                # if "resolver" in parsed_compose["services"]:
                #     try:
                #         if "compose" in request["data"]:
                #             self.save_file("compose/docker-compose.yml", "yml", request["data"]["compose"])
                #         if "config" in request["data"]:
                #             self.save_file("kresd/kres.conf", "text", request["data"]["config"])
                #         if "rules" in request["data"]:
                #             self.save_file("kresd/firewall.conf", "json", request["data"]["rules"])
                #     except IOError as e:
                #         print(e)
                for service, config in parsed_compose["services"].items():
                    try:
                        self.start_service(config)
                    except InterruptedError as e:
                        self.logger.info(e)
                    else:
                        self.logger.info("Service : {}, start successful".format(service))
                    if service == "resolver":
                        try:
                            self.inject_all_rules()
                        except ConnectionError as e:
                            self.logger.info(e)


if __name__ == '__main__':
    agent = Agent()
    agent.create_container()
