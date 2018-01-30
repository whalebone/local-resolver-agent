import docker

from .compose_translator import create_docker_run_kwargs
from .compose_parser import ComposeParser
from local_resolver_agent.exception import exc
from local_resolver_agent.secret_directory import logger


class DockerConnector:
    def __init__(self):
        self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')  # hish level api
        self.api_client = docker.APIClient(base_url='unix://var/run/docker.sock')  # low level api
        self.compose_parser = ComposeParser()
        self.logger = logger.build_logger("docker-connector", "/tmp/logs/agent/")

    def get_images(self):
        return self.docker_client.images.list()

    def get_containers(self, stopped: bool = False):
        return self.docker_client.containers.list(all=stopped)

    def start_service(self, yml):
        parsed_compose = self.compose_parser.create_service(yml)
        kwargs = create_docker_run_kwargs(parsed_compose)
        status = {}
        for service in parsed_compose["services"]:
            try:
                self.docker_client.containers.run(parsed_compose["services"][service]['image'], detach=True, **kwargs)
            except Exception as e:
                self.logger.warning(e)
                status[service]["status"] = "failed"
                status[service]["body"] = e
                raise exc.ContainerException(e)
            else:
                status[service]["status"] = "sucess"
        return status

    def docker_version(self):
        try:
            return self.api_client.version()
        except Exception as e:
            self.logger.info(e)

    def restart_container(self, container_name):
        try:
            self.api_client.restart(container_name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    def stop_container(self, container_name):
        try:
            self.api_client.stop(container_name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    def rename_container(self, container_name, name):
        try:
            self.api_client.rename(container_name, name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    def remove_container(self, container_name):
        try:
            self.api_client.remove_container(container_name, force=True)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    def inspect_config(self, container_name):
        try:
            return self.api_client.inspect_container(container_name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)
