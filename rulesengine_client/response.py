from .exceptions import MalformedResponseException


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
