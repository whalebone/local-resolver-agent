import unittest

from dockertools.compose_tools import *
from tests.dockertools.utils.compose_tools_test_util import *


class ComposeToolsTest(unittest.TestCase):

    def test_parse_ports(self):
        ports = parse_ports(['53:54/udp', '54:53/tcp'])
        self.assertIsNotNone(ports)
        self.assertIsInstance(ports, dict)
        self.assertEqual(ports['54/udp'], 53)
        self.assertEqual(ports['53/tcp'], 54)

    def test_parse_ports_none(self):
        self.assertIsNone(parse_ports([]))
        self.assertIsNone(parse_ports(None))

    def test_parse_ports_failed(self):
        with self.assertRaises(ComposeException):
            parse_ports(['blabla', '54:53/tcp'])

    def test_parse_volumes(self):
        volumes = parse_volumes(['/opt/whalebone:/data','/var/log/whalebone:/var/log/whalebone:ro'])
        self.assertIsNotNone(volumes)
        self.assertIsInstance(volumes, dict)
        self.assertIsNotNone(volumes['/opt/whalebone'])
        self.assertIsInstance(volumes['/opt/whalebone'], dict)
        self.assertEqual(volumes['/opt/whalebone']['bind'], '/data')
        self.assertEqual(volumes['/opt/whalebone']['mode'], 'rw')
        self.assertIsNotNone(volumes['/var/log/whalebone'])
        self.assertIsInstance(volumes['/var/log/whalebone'], dict)
        self.assertEqual(volumes['/var/log/whalebone']['bind'], '/var/log/whalebone')
        self.assertEqual(volumes['/var/log/whalebone']['mode'], 'ro')

    def test_parse_volumes_fail(self):
        with self.assertRaises(ComposeException):
            parse_volumes(['/opt/whalebone'])

    def test_parse_volumes_none(self):
        self.assertIsNone(parse_volumes([]))
        self.assertIsNone(parse_volumes(None))

    def test_parse_restart_policy(self):
        restart_policy = parse_restart_policy('always')
        self.assertIsInstance(restart_policy, dict)
        self.assertEqual(restart_policy['Name'], 'always')
        self.assertEqual(restart_policy['MaximumRetryCount'], 5)

    def test_create_docker_run_kwargs(self):
        kwargs = create_docker_run_kwargs(test_service_compose_fragment)

        self.assertEqual(len(kwargs), 9)

        self.assertFalse('image' in kwargs)
        self.assertEqual(kwargs['network_mode'], 'host')

        self.assertIsInstance(kwargs['ports'], dict)
        self.assertEqual(len(kwargs['ports']), 2)
        self.assertEqual(kwargs['ports']['53/udp'], 53)
        self.assertEqual(kwargs['ports']['53/tcp'], 53)

        self.assertIsInstance(kwargs['volumes'], dict)
        self.assertEqual(len(kwargs['volumes']), 2)
        self.assertIsInstance(kwargs['volumes']['/opt/whalebone'], dict)
        self.assertEqual(len(kwargs['volumes']['/opt/whalebone']), 2)
        self.assertEqual(kwargs['volumes']['/opt/whalebone']['bind'], '/data')
        self.assertEqual(kwargs['volumes']['/opt/whalebone']['mode'], 'rw')
        self.assertIsInstance(kwargs['volumes']['/var/log/whalebone'], dict)
        self.assertEqual(len(kwargs['volumes']['/var/log/whalebone']), 2)
        self.assertEqual(kwargs['volumes']['/var/log/whalebone']['bind'], '/var/log/whalebone')
        self.assertEqual(kwargs['volumes']['/var/log/whalebone']['mode'], 'ro')

        self.assertIsInstance(kwargs['environment'], dict)
        self.assertEqual(len(kwargs['environment']), 11)
        self.assertEqual(kwargs['environment']['SINKIT_LOG_LEVEL'], 'INFO'),
        self.assertEqual(kwargs['environment']['SINKIT_LOG_FILE'], '/var/log/godns.log'),
        self.assertEqual(kwargs['environment']['SINKIT_LOG_STDOUT'], 'true'),
        self.assertEqual(kwargs['environment']['SINKIT_BIND_HOST'], '0.0.0.0'),
        self.assertEqual(kwargs['environment']['SINKIT_BIND_PORT'], '53'),
        self.assertEqual(kwargs['environment']['SINKIT_NUM_OF_CPUS'], '4'),
        self.assertEqual(kwargs['environment']['SINKIT_ORACULUM_IP_ADDRESSES_ENABLED'], 'false'),
        self.assertEqual(kwargs['environment']['SINKIT_GODNS_UDP_PACKET_SIZE'], '65535'),
        self.assertEqual(kwargs['environment']['SINKIT_SINKHOLE_TTL'], '10'),
        self.assertEqual(kwargs['environment']['SINKIT_LOCAL_RESOLVER'], 'true'),
        self.assertEqual(kwargs['environment']['SINKIT_AUDIT_LEVEL'], 'ALL')

        self.assertTrue(kwargs['tty'])
        self.assertTrue(kwargs['privileged'])
        self.assertTrue(kwargs['stdin_open'])

        self.assertIsInstance(kwargs['restart_policy'], dict)
        self.assertEqual(len(kwargs['restart_policy']), 2)
        self.assertEqual(kwargs['restart_policy']['Name'], 'always')
        self.assertEqual(kwargs['restart_policy']['MaximumRetryCount'], 5)

        self.assertIsInstance(kwargs['log_config'], dict)
        self.assertEqual(len(kwargs['log_config']), 2)
        self.assertEqual(kwargs['log_config']['type'], 'json-file')
        self.assertIsInstance(kwargs['log_config']['config'], dict)
        self.assertEqual(kwargs['log_config']['config']['max-size'], '500m')
        self.assertEqual(kwargs['log_config']['config']['max-file'], '1')


if __name__ == '__main__':
    unittest.main()
