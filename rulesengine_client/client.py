import logging
import requests

from .response import Response


class Client(object):

    def __init__(self, host):
        self.host = host
        self._log = logging.getLogger(
            '{0.__module__}'.format(Client))

    def get_rules(self):
        response = requests.get('{}/rules'.format(self.host))
        return Response(response)

    def create_rule(self, rule_dict):
        response = requests.post('{}/rules'.format(self.host), data=rule_dict)
        return Response(response)

    def get_rule(self, rule_id):
        response = requests.get('{}/rule/{}'.format(self.host, rule_id))
        return Response(response)

    def update_rule(self, rule_id, rule_dict):
        response = requests.put(
            '{}/rule/{}'.format(self.host, rule_id), data=rule_dict)
        return Response(response)

    def delete_rule(self, rule_id):
        response = requests.delete('{}/rule/{}'.format(self.host, rule_id))
        return Response(response)

    def tree_for_surt(self, surt):
        response = requests.get('{}/rules/tree/{}'.format(self.host, surt))
        return Response(response)

    def rules_for_request(self, surt, capture_date, neg_surt=None,
                          collection=None, partner=None):
        p = {
            'surt': surt,
        }
        if capture_date is not None:
            p['capture-date'] = capture_date
        if neg_surt is not None:
            p['neg-surt'] = neg_surt
        if collection is not None:
            p['collection'] = collection
        if partner is not None:
            p['partner'] = partner
        response = requests.get(
            '{}/rules/for-request'.format(self.host), params=p)
        return Response(response)
