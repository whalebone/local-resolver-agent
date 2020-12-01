import unittest
import base64
import json
from local_resolver_agent_backup import lr_agent_client

REQUEST = {"requestId": "42", "action": "create", "data": {"key": "value"}}
RESPONSE = {"requestId": "42", "action": "create",
            "data": {"message": "python error",
                     "body": {"key": "value"}}}


class ComposeToolsTest(unittest.TestCase):
    def __init__(self):
        self.lr_Agent = lr_agent_client.LRAgentClient("websocket")

    def test_process_response(self):
        self.lr_Agent.process_response(
            {"action": "create", "data": {"lr-agent": {"status": "success"}, "resolver": {"status": "succes"}}})
        self.assertEqual(self.lr_Agent.error_stash, {})
        self.lr_Agent.process_response({"action": "create", "data": {"lr-agent": {"status": "success"},
                                                                     "resolver": {"status": "failure",
                                                                                  "body": "Python error message"}}})
        self.assertEqual(self.lr_Agent.error_stash, {'resolver': {'create': 'Python error message'}})
        self.lr_Agent.process_response({"action": "upgrade", "data": {"lr-agent": {"status": "success"},
                                                                      "resolver": {"status": "failure",
                                                                                   "body": "Python error message"}}})
        self.assertEqual(self.lr_Agent.error_stash,
                         {'resolver': {'create': 'Python error message', 'upgrade': 'Python error message'}})
        self.lr_Agent.process_response(
            {"action": "create", "data": {"lr-agent": {"status": "success"}, "resolver": {"status": "success"}}})
        self.assertEqual(self.lr_Agent.error_stash, {'resolver': {'upgrade': 'Python error message'}})
        self.lr_Agent.process_response(
            {"action": "upgrade", "data": {"lr-agent": {"status": "success"}, "resolver": {"status": "success"}}})
        self.assertEqual(self.lr_Agent.error_stash, {})

    def test_validate_host(self):
        pass

    def test_base64_encode(self):
        message = {"data": "testing string"}
        self.assertEqual(self.lr_Agent.encode_request(message),
                         {"data": base64.encode("testing string".encode("utf-8")).decode("utf-8")})

    def test_base64_decode(self):
        message = {"data": base64.encode("testing string".encode("utf-8")).decode("utf-8")}
        self.assertEqual(self.lr_Agent.decode_request(message), {"data": "testing string"})
        message = {"data": base64.encode(json.dumps({"key": "value"}).encode("utf-8")).decode("utf-8")}
        self.assertEqual(self.lr_Agent.decode_request(message), {"data": {"key": "value"}})

    def test_get_error(self):
        self.assertEqual(self.lr_Agent.getError("python error", REQUEST), RESPONSE)


if __name__ == '__main__':
    unittest.main()
