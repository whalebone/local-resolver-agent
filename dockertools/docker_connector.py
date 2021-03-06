import docker

from .compose_translator import create_docker_run_kwargs
from exception.exc import ContainerException
from loggingtools import logger
from datetime import datetime
from aiodocker import Docker


class DockerConnector:
    def __init__(self):
        self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')  # hish level api
        self.api_client = docker.APIClient(base_url='unix://var/run/docker.sock')  # low level api
        # keep socket connections uncaught so the exception propagates to main, and the cycle restarts
        self.logger = logger.build_logger("docker-connector", "/etc/whalebone/logs/")

    def get_images(self):
        try:
            return self.docker_client.images.list()
        except Exception as e:
            self.logger.info("Failed to get images {}.".format(e))
            return []

    def get_containers(self, stopped: bool = False) -> list:
        try:
            return self.docker_client.containers.list(all=stopped)
        except Exception as e:
            self.logger.info("Failed to get containers {}.".format(e))
            return []

    def get_container(self, name: str):
        try:
            return self.docker_client.containers.get(name)
        except Exception as e:
            self.logger.info("Failed to get container {}, {}.".format(name, e))
            return ""

    def get_volumes(self) -> list:
        try:
            return self.docker_client.volumes.list()
        except Exception as e:
            self.logger.warning("Failed to get volumes {}.".format(e))
            return []

    def container_exec(self, name: str, command: list) -> str:
        service = self.get_container(name)
        if service != "":
            try:
                result = service.exec_run(command)
            except Exception as e:
                self.logger.info("Failed to execute command {} in {} due to {}".format(command, name, e))
            else:
                return result.output.decode("utf-8")
        else:
            return ""

    async def create_volume(self, name: str, **options):
        try:
            self.docker_client.volumes.create(name, **options)
        except Exception as e:
            raise ContainerException(e)

    async def start_service(self, parsed_compose: dict):
        kwargs = create_docker_run_kwargs(parsed_compose)
        await self.pull_image(parsed_compose['image'])
        try:
            self.docker_client.containers.run(detach=True, **kwargs)
        except Exception as e:
            raise ContainerException(e)

    def docker_version(self) -> dict:
        try:
            return self.api_client.version()
        except Exception as e:
            self.logger.info("Failed to get docker version {}.".format(e))
            return {}

    def container_logs(self, name: str, timestamps: bool = False, tail: int = "all", since: str = None) -> str:
        if since is not None:
            since = datetime.strptime(since, '%Y-%m-%dT%H:%M:%S')
        try:
            return self.api_client.logs(name, timestamps=timestamps, tail=tail, since=since).decode("utf-8")
        except Exception as e:
            raise ConnectionError(e)

    async def restart_container(self, container_name: str):
        try:
            self.api_client.restart(container_name)
        except Exception as e:
            raise ContainerException(e)

    def restart_resolver(self):
        try:
            self.api_client.restart("resolver")
        except Exception as e:
            raise ContainerException(e)

    async def stop_container(self, container_name: str):
        try:
            self.api_client.stop(container_name)
        except Exception as e:
            raise ContainerException(e)

    async def rename_container(self, container_name: str, name: str):
        try:
            self.api_client.rename(container_name, name)
        except Exception as e:
            raise ContainerException(e)

    async def remove_container(self, container_name: str):
        try:
            self.api_client.remove_container(container_name, force=True)
        except Exception as e:
            raise ContainerException(e)

    def inspect_config(self, container_name: str):
        try:
            return self.api_client.inspect_container(container_name)
        except Exception as e:
            raise ContainerException(e)

    # async def pull_image(self, container_name: str):
    #     try:
    #         self.docker_client.images.pull(container_name)
    #     except Exception as e:
    #         self.logger.warning("Unable to pull image: {}, reason: {}".format(container_name, e))

    async def pull_image(self, image_name: str):
        async_client = Docker()
        try:
            await async_client.images.pull(image_name)
        except Exception as e:
            self.logger.warning("Unable to pull image: {}, reason: {}".format(image_name, e))
        finally:
            await async_client.close()