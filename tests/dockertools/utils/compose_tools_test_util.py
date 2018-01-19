test_service_compose_fragment = {
    'image': 'whalebone/resolver:tag',
    'net': 'host',
    'ports': [
        '53:53/udp',
        '53:53/tcp'
    ],
    'volumes': [
        '/opt/whalebone:/data',
        '/var/log/whalebone:/var/log/whalebone:ro'
    ],
    'environment': {
        'SINKIT_LOG_LEVEL': 'INFO',
        'SINKIT_LOG_FILE': '/var/log/godns.log',
        'SINKIT_LOG_STDOUT': 'true',
        'SINKIT_BIND_HOST': '0.0.0.0',
        'SINKIT_BIND_PORT': '53',
        'SINKIT_NUM_OF_CPUS': '4',
        'SINKIT_ORACULUM_IP_ADDRESSES_ENABLED': 'false',
        'SINKIT_GODNS_UDP_PACKET_SIZE': '65535',
        'SINKIT_SINKHOLE_TTL': '10',
        'SINKIT_LOCAL_RESOLVER': 'true',
        'SINKIT_AUDIT_LEVEL': 'ALL'
    },
    'tty': True,
    'privileged': True,
    'stdin_open': True,
    'restart': 'always',
    'log_driver': 'json-file',
    'log_opt': {
        'max-size': "500m",
        'max-file': "1"
    }
}
