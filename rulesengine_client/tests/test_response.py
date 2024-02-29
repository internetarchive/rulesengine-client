import json
import unittest

from ..exceptions import MalformedResponseException
from ..response import Response


class StubResponse(object):

    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body

    def json(self):
        return json.loads(self.body)


class ResponseTestCase(unittest.TestCase):

    def test_success(self):
        response = Response(
            StubResponse(200, '{"status": "success", "message": "ok", "result": []}')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status, "success")
        self.assertEqual(response.message, "ok")
        self.assertEqual(response.result, [])

    def test_parse_result_rule(self):
        response = Response(
            StubResponse(
                200,
                """{"status": "success", "message": "ok", "result": {
                "surt": "com,",
                "policy": "block"
            }}""",
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status, "success")
        self.assertEqual(response.message, "ok")
        self.assertEqual(response.rules.rules[0].surt, "com,")
        self.assertEqual(response.rules.rules[0].policy, "block")
        self.assertEqual(len(response.rules.rules), 1)

    def test_parse_result_rule_collection(self):
        response = Response(
            StubResponse(
                200,
                """{"status": "success", "message": "ok", "result": [{
                "surt": "com,",
                "policy": "block"
            }]}""",
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status, "success")
        self.assertEqual(response.message, "ok")
        self.assertEqual(response.rules.rules[0].surt, "com,")
        self.assertEqual(response.rules.rules[0].policy, "block")
        self.assertEqual(len(response.rules.rules), 1)

    def test_parse_result_malformed_response(self):
        with self.assertRaises(MalformedResponseException):
            Response(
                StubResponse(
                    200,
                    """{"status": "success", "message": "ok",
                "result": "bad-wolf"}""",
                )
            )
        with self.assertRaises(MalformedResponseException):
            Response(
                StubResponse(
                    200,
                    """{"status": "success", "message": "ok",
                "result": {"bad-wolf": "oh no"}""",
                )
            )

    def test_malformed_response(self):
        with self.assertRaises(MalformedResponseException):
            Response(StubResponse(500, "bad-wolf"))
