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
        response = Response(StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status, 'success')
        self.assertEqual(response.message, 'ok')
        self.assertEqual(response.result, [1, 2, 3])

    def test_malformed_response(self):
        with self.assertRaises(MalformedResponseException):
            Response(StubResponse(500, 'bad-wolf'))
