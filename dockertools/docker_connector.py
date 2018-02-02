import docker

from .compose_translator import create_docker_run_kwargs
from local_resolver_agent.exception import exc
from local_resolver_agent.secret_directory import logger


class DockerConnector:
    def __init__(self):
        self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')  # hish level api
        self.api_client = docker.APIClient(base_url='unix://var/run/docker.sock')  # low level api
        # keep socket connections uncaught so the exception propagates to main, adn the cycle restarts
        self.logger = logger.build_logger("docker-connector", "/home/narzhan/Downloads/agent_logs/")

    def get_images(self):
        try:
            return self.docker_client.images.list()
        except Exception as e:
            self.logger.info(e)
            return []

    def get_containers(self, stopped: bool = False):
        try:
            return self.docker_client.containers.list(all=stopped)
        except Exception as e:
            self.logger.info(e)
            return []

    async def start_service(self, parsed_compose):
        kwargs = create_docker_run_kwargs(parsed_compose)
        try:
            self.docker_client.containers.run(parsed_compose['image'], detach=True, **kwargs)
        except Exception as e:
            self.logger.warning(e)
            raise exc.ContainerException(e)

    def docker_version(self):
        try:
            return self.api_client.version()
        except Exception as e:
            self.logger.info(e)
            return "docker version unavailable"

    async def restart_container(self, container_name):
        try:
            self.api_client.restart(container_name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    async def stop_container(self, container_name):
        try:
            self.api_client.stop(container_name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    async def rename_container(self, container_name, name):
        try:
            self.api_client.rename(container_name, name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    async def remove_container(self, container_name):
        try:
            return self.api_client.remove_container(container_name, force=True)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)

    async def inspect_config(self, container_name):
        try:
            return self.api_client.inspect_container(container_name)
        except Exception as e:
            self.logger.info(e)
            raise exc.ContainerException(e)
