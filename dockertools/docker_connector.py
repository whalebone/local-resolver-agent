import docker
from dockertools.compose_tools import create_docker_run_kwargs


class DockerConnector:
    def __init__(self):
        self.client = docker.DockerClient(base_url='unix://var/run/docker.sock')

    def getImages(self):
        return self.client.images.list()

    def getContainers(self):
        return self.client.containers.list()

    def startService(self, service_name, service_compose):
        kwargs = create_docker_run_kwargs(service_compose)
        name = service_name + '_' + service_compose['image']
        kwargs['name'] = name
        return self.client.containers.run(service_compose['image'], **kwargs)

    def getContainersByPrefix(self, prefix):
        containers = []
        for container in self.getContainers():
            if container.name.startsWith(prefix):
                containers.append(container)
        return containers

    def restartContainer(self, container_id):
        self.client.containers.get(container_id).restart()

    def stopContainer(self, container_id):
        self.client.containers.get(container_id).stop()

    def runCompose(self, compose_file):
        # TODO compose
        pass


