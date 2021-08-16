import logging
import psycopg2
from psycopg2 import extras
import requests

from .response import Response
from .models import RuleCollection


class Client(object):

    def __init__(self, host, datasource):
        self.host = host
        self.datasource = datasource
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

    def rules_from_postgres(self, surt, capture_date, neg_surt=None,
                            collection=None, partner=None):
        query_start = ('SELECT policy, surt, '
                       'capture_date_start, capture_date_end, '
                       'collection, partner, '
                       'rewrite_from, rewrite_to, '
                       'warc_match, neg_surt, '
                       'retrieve_date_start, retrieve_date_end, '
                       'seconds_since_capture, '
                       'ip_range_start, ip_range_end, '
                       'environment, protocol '
                       'from rules_rule where %s like surt and enabled = true'
                       )
        if collection:
            query_end = " and (collection = %s or collection = '');"
            who = collection
        elif partner:
            query_end = " and (partner = %s or partner = '');"
            who = partner
        else:
            query_end = ';'
            who = None
        rules_query = ''.join([query_start, query_end])
        try:
            conn = psycopg2.connect(self.datasource,
                    cursor_factory=extras.DictCursor)
        except Exception as e:
            self._log.warning(f'db connection failure: {e}')
            return None
        cur = conn.cursor()
        try:
            if collection or partner:
                cur.execute(rules_query, (surt, who, ))
            else:
                cur.execute(rules_query, (surt, ))
        except Exception as e:
            self._log.warning(f'exception querying for {surt} and {who}: {e}')
            return None
        rules = cur.fetchall()
        if rules:
            self._log.debug('returning {}...'.format(rules[0]))
        else:
            self._log.debug('no rules returned')
        return RuleCollection.from_pg_response(rules)
