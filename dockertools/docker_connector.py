import docker
import time
from .compose_translator import create_docker_run_kwargs
from .compose_parser import ComposeParser



class DockerConnector:
    def __init__(self):
        self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock') # hish level api
        self.api_client = docker.APIClient(base_url='unix://var/run/docker.sock') # low level api
        self.compose_parser = ComposeParser()

    def get_images(self):
        return self.docker_client.images().list()

    def get_containers(self):
        return self.docker_client.containers.list()

    def start_service(self, yml):
        parsed_compose = self.compose_parser.create_service(yml)
        kwargs = create_docker_run_kwargs(parsed_compose)
        for service in parsed_compose["services"]:
            try:
                self.docker_client.containers.run(parsed_compose["services"][service]['image'], detach=True, **kwargs)
                if service == "lr-agent-new":
                    while True:
                        if self.inspect_config("lr-agent-new")["State"]["Running"] is True:
                            self.remove_container("lr-agent")
                            self.rename_container("lr-agent-new", "lr-agent")
                            break
                        else:
                            time.sleep(2)
            except Exception as e:
                pass
                #raise exc.StartException("{} start failed with exception {}".format(service, e))
                # TODO: logging for failure
        # TODO: return status of transaction

    def docker_version(self):
        return self.api_client.version()

    def restart_container(self, container_name):
        self.api_client.restart(container_name)

    def stop_container(self, container_name):
        self.api_client.stop(container_name)

    def rename_container(self, container_name, name):
        self.api_client.rename(container_name, name)

    def remove_container(self, container_name):
        self.api_client.remove_container(container_name, force=True)

    def inspect_config(self, container_name):
        return self.api_client.inspect_container(container_name)
