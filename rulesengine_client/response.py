from .exceptions import MalformedResponseException
from .models import RuleCollection


class Response(object):

    def __init__(self, response):
        self.status_code = response.status_code
        try:
            self.json = response.json()
        except ValueError:
            raise MalformedResponseException(
                'received non-JSON response', response.body)
        self.status = self.json['status']
        self.message = self.json['message']
        if 'result' in self.json:
            self.result = self.json['result']
        self.rules = None
        if self.status == 'success':
            self._parse_result()

    def _parse_result(self):
        if isinstance(self.result, list):
            self.rules = RuleCollection.from_response(self.result)
        elif isinstance(self.result, dict):
            self.rules = RuleCollection.from_response([self.result])
        else:
            raise MalformedResponseException(
                'received unexpected result', self.result)
