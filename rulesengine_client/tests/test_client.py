import unittest
try:
    from unittest.mock import (
        call,
        patch,
    )
except ImportError:
    from mock import (
        call,
        patch,
    )

from ..client import Client
from .test_response import StubResponse


class ClientTestCase(unittest.TestCase):

    @patch('requests.get')
    def test_get_rules(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.get_rules()
        self.assertEqual(result.status_code, 200)
        mock_request.assert_called_once_with('http://localhost/rules')

    @patch('requests.post')
    def test_create_rule(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.create_rule({})
        self.assertEqual(result.status_code, 200)
        mock_request.assert_called_once_with('http://localhost/rules', data={})

    @patch('requests.get')
    def test_get_rule(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.get_rule(1)
        self.assertEqual(result.status_code, 200)
        mock_request.assert_called_once_with('http://localhost/rule/1')

    @patch('requests.put')
    def test_update_rule(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.update_rule(1, {})
        self.assertEqual(result.status_code, 200)
        mock_request.assert_called_once_with(
            'http://localhost/rule/1', data={})

    @patch('requests.delete')
    def test_delete_rule(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.delete_rule(1)
        self.assertEqual(result.status_code, 200)
        mock_request.assert_called_once_with('http://localhost/rule/1')

    @patch('requests.get')
    def test_tree_for_surt(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.tree_for_surt('http://(org,archive,)')
        self.assertEqual(result.status_code, 200)
        mock_request.assert_called_once_with(
            'http://localhost/rules/tree/http://(org,archive,)')

    @patch('requests.get')
    def test_rules_for_request(self, mock_request):
        mock_request.return_value = StubResponse(
            200,
            '{"status": "success", "message": "ok", "result": [1, 2, 3]}')
        c = Client('http://localhost')
        result = c.rules_for_request('http://(org,archive,)', 'today')
        self.assertEqual(result.status_code, 200)
        result = c.rules_for_request(
            'http://(org,archive,)', 'today', neg_surt='foo')
        self.assertEqual(result.status_code, 200)
        result = c.rules_for_request(
            'http://(org,archive,)', 'today', collection='bar')
        self.assertEqual(result.status_code, 200)
        result = c.rules_for_request(
            'http://(org,archive,)', 'today', partner='baz')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(mock_request.call_args_list, [
            call(
                'http://localhost/rules/for-request',
                params={
                    'surt': 'http://(org,archive,)',
                    'capture-date': 'today',
                }),
            call(
                'http://localhost/rules/for-request',
                params={
                    'surt': 'http://(org,archive,)',
                    'capture-date': 'today',
                    'neg-surt': 'foo',
                }),
            call(
                'http://localhost/rules/for-request',
                params={
                    'surt': 'http://(org,archive,)',
                    'capture-date': 'today',
                    'collection': 'bar',
                }),
            call(
                'http://localhost/rules/for-request',
                params={
                    'surt': 'http://(org,archive,)',
                    'capture-date': 'today',
                    'partner': 'baz',
                }),
        ])
