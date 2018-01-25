import yaml
import docker

# from .exc import ComposeException

SUPPORTED_VERSIONS = ['1', '3']
LR_AGENT_SERVICE = "lr-agent"


class ComposeParser:

    # def __init__(self, docker_connector):
    #     self.dockerConnector = docker_connector

    def create_service(self, compose_yaml):
        compose = self.parse(compose_yaml)
        self.validate(compose)
        for service_name in compose['services']:
            if service_name == LR_AGENT_SERVICE:
                compose['services'][service_name]["name"] = "lr-agent-new"
            else:
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
        except yaml.YAMLError as exc:
            raise Exception("Invalid compose YAML format") from exc

    def validate(self, parsed_compose):
        if parsed_compose['version'] not in SUPPORTED_VERSIONS:
            raise Exception("Compose version '{0}' not supported. Supported versions: {1}"
                            .format(parsed_compose['version'], SUPPORTED_VERSIONS))
        if 'services' not in parsed_compose:
            raise Exception("Missing section 'services'")
