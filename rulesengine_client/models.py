from datetime import (
    datetime,
    timedelta,
    timezone,
)
from dateutil.parser import parse as parse_date
import ipaddr
import re


class Rule(object):
    """Rule represents a rule received from the rulesengine server."""

    def __init__(self, surt, policy, neg_surt=None, capture_date=None,
                 retrieve_date=None, ip_range=None, seconds_since_capture=None,
                 collection=None, partner=None, warc_match=None,
                 rewrite_from=None, rewrite_to=None, private_comment=None,
                 public_comment=None):
        self.surt = surt
        self.policy = policy
        self.neg_surt = neg_surt
        self.seconds_since_capture = seconds_since_capture
        self.collection = collection
        self.partner = partner
        self.warc_match = warc_match
        self.rewrite_from = rewrite_from
        self.rewrite_to = rewrite_to
        self.private_comment = private_comment
        self.public_comment = public_comment

        # Parse dates out of capture and retrieval date fields if necessary.
        if (capture_date and self.capture_date['start'] and
                capture_date['end']):
            self.capture_date = {
                'start': parse_date(capture_date['start']),
                'end': parse_date(capture_date['end']),
            }
        else:
            self.capture_date = None
        if (self.retrieve_date and self.retrieve_date['start'] and
                self.retrieve_date['end']):
            self.retrieve_date = {
                'start': parse_date(self.retrieve_date['start']),
                'end': parse_date(self.retrieve_date['end']),
            }
        else:
            self.retrieve_date = None

        # Parse IP addresses if necessary.
        if (self.ip_range and self.ip_range['start'] and self.ip_range['end']):
            self.ip_range = {
                'start': ipaddr.IPAddress(self.ip_range['start']),
                'end': ipaddr.IPAddress(self.ip_range['end']),
            }
        else:
            self.ip_range = None

    def applies(self, warc_name, client_ip, capture_date, collection=None,
                partner=None, server_side_filters=True):
        """Checks to see whether a rule applies given request and playback
        information.

        :param str warc_name: the name of the WARC file containing the capture.
        :param client_ip: the client's IP address
        :type client_ip: str or ipaddr.IPv[46]Address
        :param datetime capture_date: the date of the requested capture.
        :param str collection: the collection to which the capture belongs.
        :param str partner: the partner to which the capture belongs.
        :param bool server_side_filters: whether or not filters have already
            been run server side. This includes capture and retrieval dates,
            collection, and partner.

        :return: True if the rule applies to the request, otherwise False.
        """
        if server_side_filters:
            return (self.warc_match_applies(warc_name) and
                    self.ip_range_applies(client_ip) and
                    self.seconds_since_capture_applies(capture_date))
        return (
            self.enabled and
            self.ip_range_applies(client_ip) and
            self.capture_date_applies(capture_date) and
            self.retrieve_date_applies(datetime.now(timezone.utc)) and
            self.warc_match_applies(warc_name) and
            self.collection_applies(collection) and
            self.partner_applies(partner))

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

    def seconds_since_capture_applies(self, capture_date):
        """Checks to see whether the rule applies based on the date of
        capture in terms of seconds since capture.

        If the rule has an seconds-since-capture field, it will check to see
        whether it has been less than that number of seconds since capture.
        If not, it's assumed that the rule applies.

        :param int capture_date: the date of the capture.

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.seconds_since_capture is None:
            return True
        return (timedelta(seconds=int(self.seconds_since_capture)) >=
                (datetime.now(timezone.utc) - capture_date))

    def capture_date_applies(self, capture_date):
        """Checks to see whether the rule applies based on the date of
        capture.

        If the rule has an capture date range, it will check to see whether the
        capture date falls within that range. If not, it's assumed that the
        rule applies.

        :param datetime capture_date: the date of the capture.

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.capture_date is None:
            return True
        return (self.capture_date['start'] <= capture_date and
                self.capture_date['end'] >= capture_date)

    def retrieve_date_applies(self, retrieve_date):
        """Checks to see whether the rule applies based on the date of
        retrieval.

        If the rule has an retrieve date range, it will check to see whether
        the current date falls within that range. If not, it's assumed that the
        rule applies.

        :param datetime retrieve_date: the date of retrieval (likely now).

        :return: True if the rule applies for this check, otherwise False.
        """
        if self.retrieve_date is None:
            return True
        return (self.retrieve_date['start'] <= retrieve_date and
                self.retrieve_date['end'] >= retrieve_date)

    def warc_match_applies(self, warc_name):
        """Checks to see whether the rule applies based on a regex of the WARC
        name.

        If the rule has a warc_match regex, it will check to see if it matches.
        If not, it's assumed the rule applies.

        :param str warc_name: the name of the WARC file to check.

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

        If the rule has an partner, it will check to see wether the
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

    def filter_applicable_rules(self, warc_name, client_ip, capture_date=None,
                                collection=None, partner=None,
                                server_side_filters=True):
        """Filters the rules to only those which apply to the request.

        Before checking whether a request is allowed or applying any rewrites,
        this method should be run on the rule collection to ensure that only
        the appropriaterules are included.

        :param str warc_name: the name of the WARC file containing the capture.
        :param client_ip: the client's IP address
        :type client_ip: str or ipaddr.IPv[46]Address
        :param datetime capture_date: the date of the requested capture.
        :param str collection: the collection to which the capture belongs.
        :param str partner: the partner to which the capture belongs.
        :param bool server_side_filters: whether or not filters have already
            been run server side. This includes capture and retrieval dates,
            collection, and partner.
        """
        self.rules = [rule for rule in self.rules if rule.applies(
            warc_name,
            client_ip,
            capture_date=capture_date,
            collection=collection,
            partner=partner,
            server_side_filters=server_side_filters)]
        self.sort_rules()

    def sort_rules(self):
        """Sorts the rules on the surts."""
        self.rules.sort(key=lambda x: x.surt)

    def allow(self):
        """Decies whether to allow a playback based on the collection of
        rules.

        :return: True if the playback is allowed.
        """
        policies = [rule.policy for rule in self.rules]
        allow = False
        for policy in policies:
            allow = policy == 'allow'
        return allow

    def rewrites_only(self):
        """Finds only the rules with rewrite policies.

        :return: A new RuleCollection with only rewrite rules.
        """
        return RuleCollection(
            [rule for rule in self.rules if rule.policy.startswith('rewrite')])
