import yaml
import docker
from exception.exc import ComposeException

SUPPORTED_VERSIONS = ['1','3']
LR_AGENT_SERVICE = 'lr-agent'


class ComposeLite:

    def __init__(self, docker_connector):
        self.dockerConnector = docker_connector

    def startService(self, compose_yaml):
        compose = ComposeLite.__parse(compose_yaml)
        ComposeLite.__validate(compose)
        for service_name in compose:
            if ComposeLite.__is_lr_agent_service(service_name):
                # TODO start
                pass
            service = compose[service_name]


        return compose

    def stopService(self, compose_yaml):
        compose = ComposeLite.__parse(compose_yaml)
        ComposeLite.__validate(compose)
        for service_name in compose:
            if ComposeLite.__is_lr_agent_service(service_name):
                # TODO start
                pass
            service = compose[service_name]

        return compose

    @staticmethod
    def __is_lr_agent_service(service_name):
        return service_name == LR_AGENT_SERVICE

    @staticmethod
    def __parse(compose_yaml):
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
            raise ComposeException("Invalid compose YAML format") from exc

    @staticmethod
    def __validate(parsed_compose):
        if parsed_compose['version'] not in SUPPORTED_VERSIONS:
            raise ComposeException("Compose version '{0}' not supported. Supported versions: {1}"
                                   .format(parsed_compose['version'], SUPPORTED_VERSIONS))
        if 'services' not in parsed_compose:
            raise ComposeException("Missing section 'services'")


compose = """resolver:
  image: whalebone/resolver:local-4
  net: host
  ports:
  - 53:53/udp
  - 53:53/tcp
  volumes:
  - /opt/whalebone:/data
  - /var/log/whalebone:/var/log/whalebone
  environment:
    SINKIT_LOG_LEVEL: 'INFO'
    SINKIT_LOG_FILE: '/var/log/godns.log'
    SINKIT_LOG_STDOUT: 'true'
    SINKIT_BIND_HOST: '0.0.0.0'
    SINKIT_BIND_PORT: '53'
    SINKIT_NUM_OF_CPUS: '4'
    SINKIT_GODNS_READ_TIMEOUT: '3000'
    SINKIT_GODNS_WRITE_TIMEOUT: '3000'
    SINKIT_RESOLV_CONF_FILE: '/etc/resolv.conf'
    SINKIT_BACKEND_RESOLVER_RW_TIMEOUT: '3000'
    SINKIT_BACKEND_RESOLVER_TICK: '100'
    SINKIT_BACKEND_RESOLVERS: '127.0.0.1:5353'
    SINKIT_BACKEND_RESOLVERS_EXCLUSIVELY: 'true'
    SINKIT_ORACULUM_CACHE_BACKEND: 'memory'
    SINKIT_ORACULUM_CACHE_EXPIRE: '120000'
    SINKIT_ORACULUM_CACHE_MAXCOUNT: '1000000'
    SINKIT_ORACULUM_API_FIT_TIMEOUT: '500'
    SINKIT_ORACULUM_API_TIMEOUT: '600'
    SINKIT_ORACULUM_SLEEP_WHEN_DISABLED: '20000'
    SINKIT_ORACULUM_DISABLED: 'false'
    SINKIT_ORACULUM_URL: '{$coreUrl}/sinkit/rest/blacklist/dns'
    SINKIT_ORACULUM_ACCESS_TOKEN_KEY: 'X-sinkit-token'
    SINKIT_ORACULUM_ACCESS_TOKEN_VALUE: 'kjdqgkjhgdajdsakgqq'
    SINKIT_SINKHOLE_ADDRESS: '{$sinkholeAddress}'
    SINKIT_ORACULUM_IP_ADDRESSES_ENABLED: 'false'
    SINKIT_GODNS_UDP_PACKET_SIZE: '65535'
    SINKIT_SINKHOLE_TTL: '10'
    SINKIT_LOCAL_RESOLVER: 'true'
    SINKIT_CA_CRT_BASE64: '{$caPublicCert|base64_encode}'
    SINKIT_CLIENT_CRT_BASE64: ''
    SINKIT_CLIENT_KEY_BASE64: ''
    SINKIT_INSECURE_SKIP_VERIFY: 'true'
    SINKIT_CLIENT_ID: '{$resolver->getCustomer()->getId()}'
    SINKIT_CLIENT_ID_HEADER: 'X-client-id'
    SINKIT_CACHE_URL: '{$coreUrl}/sinkit/rest/protostream'
    SINKIT_CACHE_REFRESH_WHITELIST: '1440'
    SINKIT_CACHE_REFRESH_IOC: '120'
    SINKIT_CACHE_REFRESH_CUSTOMLIST: '10'
    SINKIT_CACHE_REFRESH_IOCWITHCUSTOMLIST: '60'
    SINKIT_CACHE_RETRY_COUNT: '3'
    SINKIT_CACHE_RETRY_INTERVAL: '60'
    SINKIT_CACHE_REQUEST_TIMEOUT: '300'
    SINKIT_ORACULUM_API_MAX_REQUESTS: '50'
    UNBOUND_MODULE_CONFIG: 'validator iterator'
    SINKIT_AUDIT_FILE: '/var/log/whalebone/whalebone.log'
    SINKIT_AUDIT_LEVEL: 'ALL'
  tty: true
  privileged: true
  stdin_open: true
  restart: always
  log_driver: json-file
  log_opt:
    max-size: "500m"
    max-file: "1"
passivedns:
  image: whalebone/passivedns:local-3
  environment:
    DNS_INTERFACE: ''
    MAX_MEMORY: '256'
  volumes:
  - /var/log/whalebone:/var/log/whalebone
  net: host
  restart: always
  log_driver: json-file
  log_opt:
    max-size: "10m"
    max-file: "1"
logstream:
  image: whalebone/logstream:local-1
  net: host
  volumes:
  - /var/log/whalebone:/var/log/whalebone
  - registry:/usr/share/filebeat/data
  environment:
    LOGSTREAM_HOSTS: '["{$logCollectorHostname}:{$logCollectorPort}"]'
    LOGSTREAM_CA_CRT_BASE64: '{$caPublicCert|base64_encode}'
    LOGSTREAM_CLIENT_CRT_BASE64: ''
    LOGSTREAM_CLIENT_KEY_BASE64: ''
  restart: always
  log_opt:
    max-size: "10m"
    max-file: "1"
logrotate:
  image: whalebone/logrotate:local-1
  volumes:
  - /var/log/whalebone:/var/log/whalebone
  environment:
    LOGS_DIRECTORIES: "/var/log/whalebone"
    LOGROTATE_SIZE: "1G"
    LOGROTATE_COMPRESSION: "compress"
    LOGROTATE_CRONSCHEDULE: "* * * * * *"
    LOGROTATE_COPIES: 5
  restart: always
  log_driver: json-file
  log_opt:
    max-size: "10m"
    max-file: "1"
"""
#"""version: '3'
# services:
#     lr-agent:
#         image: bambula/lr-agent:latest
#         environment:
#           - WHALEBONE_CLIENT_CRT_BASE64:
#           - WHALEBONE_CLIENT_KEY_BASE64:
#           - WHALEBONE_PORTAL_ADDRESS:wss://localhost:8443/wsproxy/ws
#         volumes:
#           - /var/run/docker.sock:/var/run/docker.sock
# """

if __name__ == '__main__':
    parser = ComposeLite(docker.DockerClient(base_url='unix://var/run/docker.sock'))
    x = parser.start(compose)
    for service in x['services']:
        print(service)
        print(x['services'][service])

