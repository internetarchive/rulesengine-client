from wayback.cdxserver import BlockedException
from wayback.timestamp import datetime2timestamp, timestamp2datetime

from datetime import (
    datetime,
    timedelta,
)
import ipaddr
import logging
from pytz import utc
import re2 as re

from .exceptions import MalformedResponseException


class Rule(object):
    """Rule represents a rule received from the rulesengine server."""

    def __init__(self, surt, policy, neg_surt=None, capture_date=None,
                 retrieve_date=None, ip_range=None, seconds_since_capture=None,
                 collection=None, partner=None, protocol=None, warc_match=None,
                 rewrite_from=None, rewrite_to=None, private_comment=None,
                 public_comment=None, enabled=True, environment='prod'):
        self.surt = surt
        self.policy = policy
        self.neg_surt = neg_surt
        self.seconds_since_capture = seconds_since_capture
        self.collection = collection
        self.partner = partner
        self.protocol = protocol
        self.warc_match = warc_match
        self.rewrite_from = rewrite_from
        self.rewrite_to = rewrite_to
        self.private_comment = private_comment
        self.public_comment = public_comment
        self.enabled = enabled
        self.environment = environment
        self._log = logging.getLogger(
            '{0.__module__}'.format(Rule))

        # Parse dates out of capture and retrieval date fields if necessary.
        # We compare capture date to a bytes timestamp from a cdx record.
        self.capture_date = {
            'start': capture_date['start'] if capture_date['start'] else None,
            'end':   capture_date['end']   if capture_date['end']   else None
        } if capture_date else None

        # We compare retrieve_date only to datetime.
        self.retrieve_date = {
            'start': retrieve_date['start'] if retrieve_date['start'] else None,
            'end':   retrieve_date['end']   if retrieve_date['end']   else None
        } if retrieve_date else None

        # Parse IP addresses if necessary. note: ip checks disabled 202107
        if (ip_range and ip_range['start'] and ip_range['end']):
            self.ip_range = {
                'start': ipaddr.IPAddress(ip_range['start']),
                'end': ipaddr.IPAddress(ip_range['end']),
            }
        else:
            self.ip_range = None

    @classmethod
    def from_response(cls, response):
        """Build a Rule from the results of a query to the server."""
        if 'surt' not in response or 'policy' not in response:
            raise MalformedResponseException(
                'rules must contain at least a surt and a policy')
        if 'capture_date' in response:
            capture_date = {'start': None, 'end': None}
            if 'start' in response['capture_date']:
                capture_date['start'] = response['capture_date']['start']
            if 'end' in response['capture_date']:
                capture_date['end'] = response['capture_date']['end']
        else:
            capture_date = None
        if 'retrieve_date' in response:
            retrieve_date = {'start': None, 'end': None}
            if 'start' in response['retrieve_date']:
                retrieve_date['start'] = response['retrieve_date']['start']
            if 'end' in response['retrieve_date']:
                retrieve_date['end'] = response['retrieve_date']['end']
        else:
            retrieve_date = None
        return cls(
            response['surt'],
            response['policy'],
            capture_date = capture_date,
            retrieve_date = retrieve_date,
            neg_surt=response.get('neg_surt'),
            seconds_since_capture=response.get('seconds_since_capture'),
            collection=response.get('collection'),
            partner=response.get('partner'),
            warc_match=response.get('warc_match'),
            rewrite_from=response.get('rewrite_from'),
            rewrite_to=response.get('rewrite_to'),
            private_comment=response.get('private_comment'),
            public_comment=response.get('public_comment'),
            enabled=response.get('enabled'),
            environment=response.get('environment'))

    @classmethod
    def from_pg_response(cls, response):
        """Build a Rule from the results of a query to postgres."""
        if 'surt' not in response or 'policy' not in response:
            raise MalformedResponseException(
                'rules must contain at least a surt and a policy')
        capture_date = {'start': None, 'end': None}
        if 'capture_date_start' in response and response['capture_date_start']:
            capture_date['start'] = datetime2timestamp(response['capture_date_start'])
        if 'capture_date_end' in response and response['capture_date_end']:
            capture_date['end'] = datetime2timestamp(response['capture_date_end'])
        if not capture_date['start'] and not capture_date['end']:
            capture_date = None
        retrieve_date = {'start': None, 'end': None}
        if 'retrieve_date_start' in response and response['retrieve_date_start']:
            retrieve_date['start'] = response['retrieve_date_start']
        if 'retrieve_date_end' in response and response['retrieve_date_end']:
            retrieve_date['end'] = response['retrieve_date_end']
        if not retrieve_date['start'] and not retrieve_date['end']:
            retrieve_date = None
        neg_surt=response.get('neg_surt')
        seconds_since_capture=response.get('seconds_since_capture')
        collection=response.get('collection')
        partner=response.get('partner')
        protocol=response.get('protocol')
        warc_match=response.get('warc_match')
        rewrite_from=response.get('rewrite_from')
        rewrite_to=response.get('rewrite_to')
        private_comment=response.get('private_comment')
        public_comment=response.get('public_comment')
        environment=response.get('environment')
        return cls(
            response['surt'],
            response['policy'],
            capture_date = capture_date,
            retrieve_date = retrieve_date,
            neg_surt = neg_surt if neg_surt else None,
            seconds_since_capture = seconds_since_capture,
            collection = collection if collection else None,
            partner = partner if partner else None,
            protocol = protocol if protocol else None,
            warc_match = warc_match.encode() if warc_match else None,
            rewrite_from = rewrite_from.encode() if rewrite_from else None,
            rewrite_to = rewrite_to.encode() if rewrite_to else None,
            private_comment = private_comment,
            public_comment = public_comment,
            environment = environment)

    def applies(self, warc_name, capture_date, client_ip=None,
                retrieve_date=datetime.now(tz=utc), collection=None,
                partner=None, protocol=None, server_side_filters=True):
        """Checks to see whether a rule applies given request and playback
        information.

        :param bytes warc_name: the name of the WARC file containing the capture.
        :param client_ip: the client's IP address
        :type client_ip: str or ipaddr.IPv[46]Address
        :param bytes timestamp capture_date: the date of the requested capture.
        :param str collection: the collection to which the capture belongs.
        :param str partner: the partner to which the capture belongs.
        :param str protocol: the protocol of the capture.
        :param bool server_side_filters: whether or not filters have already
            been run server side. This includes capture and retrieval dates,
            collection, and partner.

        :return: True if the rule applies to the request, otherwise False.
        """
        if server_side_filters:
            return (self.warc_match_applies(warc_name) and
                    self.protocol_applies(protocol) and
                    self.seconds_since_capture_applies(capture_date))

        return (
            self.seconds_since_capture_applies(capture_date) and
            self.capture_date_applies(capture_date) and
            self.retrieve_date_applies(retrieve_date) and
            self.warc_match_applies(warc_name) and
            self.collection_applies(collection) and
            self.partner_applies(partner) and
            self.protocol_applies(protocol))

    def ip_range_applies(self, client_ip):
        """Checks to see whether the rule applies based on the client's IP
        address.

        If the rule has an associated IP range, it will check to see wether the
        client's IP falls within that range. If not, it's assumed that the rule
        applies.

        :param client_ip: the client's IP address.
        :type client_ip: str or ipaddr.IPv[46]Address

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.ip_range is None:
            return True
        if isinstance(client_ip, str):
            client_ip = ipaddr.IPAddress(client_ip)
        return (self.ip_range['start'] <= client_ip and
                self.ip_range['end'] >= client_ip)

    def protocol_applies(self, protocol):
        """Check to see whether the rule applies based on the query protocol.

        If the rule defines a protocol, we check to see if the
        query protocol matches.

        :param protocol: the query's protocol
        :type protocol: str

        :return: True if the rule defines no protocol, or rule protocol
        matches param protocol, otherwise False.
        """
        if self.protocol is None:
            return True
        return self.protocol == protocol

    def seconds_since_capture_applies(self, capture_date):
        """Checks to see whether the rule applies based on the date of
        capture in terms of seconds since capture.

        If the rule has an seconds-since-capture field, it will check to see
        whether it has been less than that number of seconds since capture.
        If not, it's assumed that the rule applies.

        :param bytes timestamp capture_date: the date of the capture.

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.seconds_since_capture is None:
            return True
        return (timedelta(seconds=int(self.seconds_since_capture)) >=
                (datetime.now(tz=utc) - timestamp2datetime(capture_date).replace(tzinfo=utc)))

    def capture_date_applies(self, capture_date):
        """Checks to see whether the rule applies based on the date of
        capture.

        If the rule has a capture date range, it will check to see whether the
        capture date falls within that range. If not, it's assumed that the
        rule applies.

        :param bytes timestamp capture_date: the date of the capture.

        :return: True if the rule applies for this check, otherwise False.
        """
        if not self.capture_date:
            return True
        return ((not self.capture_date['start'] or self.capture_date['start'] <= capture_date) and
                (not self.capture_date['end'] or self.capture_date['end'] >= capture_date))

    def retrieve_date_applies(self, retrieve_date=datetime.now(tz=utc)):
        """Checks to see whether the rule applies based on the date of
        retrieval.

        If the rule has an retrieve date range, it will check to see whether
        the current date falls within that range. If not, it's assumed that the
        rule applies.

        :param datetime retrieve_date: the date of retrieval (likely now).

        :return: True if the rule applies for this check, otherwise False.
        """
        if not self.retrieve_date:
            return True
        return ((not self.retrieve_date['start'] or self.retrieve_date['start'] <= retrieve_date) and
                (not self.retrieve_date['end'] or self.retrieve_date['end'] >= retrieve_date))

    def warc_match_applies(self, warc_name):
        """Checks to see whether the rule applies based on a regex of the WARC
        name.

        If the rule has a warc_match regex, it will check to see if it matches.
        If not, it's assumed the rule applies.

        :param bytes warc_name: the name of the WARC file to check.

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.warc_match is None:
            return True
        return re.search(self.warc_match, warc_name) is not None

    def collection_applies(self, collection):
        """Checks to see whether the rule applies based on the capture's
        collection.

        If the rule has an collection, it will check to see wether the
        capture's collection matches. If not, it's assumed that the
        rule applies.

        :param str collection: the collection.

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.collection is None:
            return True
        return self.collection == collection

    def partner_applies(self, partner):
        """Checks to see whether the rule applies based on the capture's
        partner.

        If the rule has a partner, it will check to see whether the
        capture's partner matches. If not, it's assumed that the
        rule applies.

        :param str partner: the partner.

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.partner is None:
            return True
        return self.partner == partner


class RuleCollection(object):
    """RuleCollection represents a group of rules applying to a request."""

    def __init__(self, rules):
        self.rules = rules
        self.sort_rules()
        self._log = logging.getLogger(
            '{0.__module__}'.format(RuleCollection))

    @classmethod
    def from_response(cls, response):
        """Build a RuleCollection from the results of a query to the server."""
        rules = []
        for rule in response:
            rules.append(Rule.from_response(rule))
        return cls(rules)

    @classmethod
    def from_pg_response(cls, response):
        """Build a RuleCollection from the results of a query to the server."""
        rules = []
        for rule in response:
            rules.append(Rule.from_pg_response(rule))
        return cls(rules)

    def sort_rules(self):
        """Sorts the rules on the surts."""
        self.rules.sort(key=lambda x: x.surt)

    def filter_applicable_rules(self, warc_name, client_ip=None, capture_date=None,
                                retrieve_date=datetime.now(tz=utc),
                                collection=None, partner=None, protocol=None,
                                server_side_filters=True):
        """Filters the rules to only those which apply to the request.

        Before checking whether a request is allowed or applying any rewrites,
        this method should be run on the rule collection to ensure that only
        the appropriate rules are included.

        :param bytes warc_name: the name of the WARC file containing the capture.
        :param client_ip: the client's IP address
        :type client_ip: str or ipaddr.IPv[46]Address
        :param bytes timestamp capture_date: the date of the requested capture.
        :param str collection: the collection to which the capture belongs.
        :param str partner: the partner to which the capture belongs.
        :param str protocol: the protocol of the capture.
        :param bool server_side_filters: whether or not filters have already
            been run server side. This includes capture and retrieval dates,
            collection, and partner.
        """
        self.rules = [rule for rule in self.rules if rule.applies(
            warc_name,
            capture_date=capture_date,
            collection=collection,
            partner=partner,
            protocol=protocol,
            server_side_filters=server_side_filters)]
        self.sort_rules()

    def allow(self):
        """Decides whether to allow a playback based on the collection of
        rules.

        :return: True if the playback is allowed.
        """
        policies = [rule.policy for rule in self.rules]
        allow = True
        message = False
        for policy in policies:
            # Allow decisions only rely on 'allow' and 'block' policies. No
            # decision is made for rewrite policies.
            if policy == 'allow':
                allow = True
            elif policy == 'block':
                allow = False
            elif policy == 'message':
                allow = False
                message = True
        if message and not allow:
            self._log.warning('blocking url')
            raise BlockedException
        return allow

    def rewrites_only(self):
        """Finds only the rules with rewrite policies.

        :return: A new RuleCollection with only rewrite rules.
        """
        return RuleCollection(
            [rule for rule in self.rules if rule.policy.startswith('rewrite')])

    def rewrite(self, response):
        """ Rewrites response according to matching rewrite rules.

        :return: rewritten response
        """
        headers_r = response.headers
        content_r = response.data
        for r in self.rules:
            if r.policy == 'rewrite-headers':
                #  todo: support rewrite-headers, use, e.g.,
                #   response.headers['X-Archive-Guessed-Content-Type']
                #  is this bytes or string?
                #  also, we're rewriting only "rewritable" mimetypes in wsgiapp.py
                continue
            if r.policy == 'rewrite-all':
                try:
                    content_r = re.sub(r.rewrite_from, r.rewrite_to, content_r)
                    self._log.info(f'rewriting response.data with {r.rewrite_from[:80]}... with rewrite to {r.rewrite_to[:80]}')
                except Exception as e:
                    self._log.warn(f'exception rewriting response.data with rewrite from {r.rewrite_from[:80]}: {e}')
                    content_r = response.data
            elif r.policy == 'rewrite-js':
                # do we need to support this?  here?
                    continue
            else:
                self._log.warn('unexpected policy; nothing rewritten!')
        return headers_r, content_r

