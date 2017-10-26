import docker
from compose.cli.main import TopLevelCommand, project_from_options


class DockerConnector:
    def __init__(self):
        self.client = docker.DockerClient(base_url='unix://var/run/docker.sock')

    def get_images(self):
        return self.client.images.list()

    def getContainers(self):
        return self.client.containers.list()

    def start_container(self, image):
        return self.client.containers.run(image, detach = True)

    def restart_container(self, container_id):
        self.client.containers.get(container_id).restart()

    def stop_container(self, container_id):
        self.client.containers.get(container_id).stop()

    def run_compose(self, compose_file):
        # TODO compose
        pass


if __name__ == '__main__':
    docker = DockerConnector()
    print(docker.get_images())
    image = input("Image: ")
    container = docker.start_container(image)
    container.logs()

