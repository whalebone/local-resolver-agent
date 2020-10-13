import yaml

from exception.exc import ComposeException

SUPPORTED_VERSIONS = ['1', '3']


class ComposeParser:

    def create_service(self, compose_yaml: str) -> dict:
        compose = self.parse(compose_yaml)
        self.validate(compose)
        for service_name in compose['services']:
            compose['services'][service_name]["name"] = service_name
        return compose

    def parse(self, compose_yaml: str) -> dict:
        try:
            parsed_compose = yaml.load(compose_yaml, Loader=yaml.SafeLoader)
            if isinstance(parsed_compose, str):
                parsed_compose = yaml.load(parsed_compose, Loader=yaml.SafeLoader)
        except yaml.YAMLError as e:
            raise ComposeException("Invalid compose YAML format {}".format(e))
        else:
            if 'version' in parsed_compose:
                return parsed_compose
            else:
                # make version '1' compatible
                return {
                    'version': '1',
                    'services': parsed_compose
                }

    def validate(self, parsed_compose: dict):
        if parsed_compose['version'] not in SUPPORTED_VERSIONS:
            raise ComposeException("Compose version '{0}' not supported. Supported versions: {1}"
                                   .format(parsed_compose['version'], SUPPORTED_VERSIONS))
        if 'services' not in parsed_compose:
            raise ComposeException("Missing section 'services'")
