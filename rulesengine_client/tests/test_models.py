from wayback.timestamp import datetime2timestamp

from datetime import (
    datetime,
    timedelta,
)
import ipaddr
from pytz import utc
import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from ..models import (
    Rule,
    RuleCollection,
)


class RuleModelTestCase(unittest.TestCase):

    def test_init(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            neg_surt='http://(com,example,api)',
            capture_date={
                'start': '2000-01-01T12:00:00.000Z',
                'end': '2001-01-01T12:00:00.000Z',
            },
            retrieve_date={
                'start': '2000-01-01T12:00:00.000Z',
                'end': '2001-01-01T12:00:00.000Z',
            },
            ip_range={
                'start': '4.4.4.4',
                'end': '8.8.8.8',
            },
            seconds_since_capture=31536000,
            collection='The Planets',
            partner='Gustav Holst',
            protocol='http',
            subdomain='www',
            warc_match='.*jupiter.*')
        self.assertEqual(
            rule.capture_date['start'],
            '2000-01-01T12:00:00.000Z')
        self.assertEqual(
            rule.capture_date['end'],
            '2001-01-01T12:00:00.000Z')
        self.assertEqual(
            rule.retrieve_date['start'],
            '2000-01-01T12:00:00.000Z')
        self.assertEqual(
            rule.retrieve_date['end'],
            '2001-01-01T12:00:00.000Z')
        self.assertEqual(
            rule.ip_range['start'],
            ipaddr.IPAddress('4.4.4.4'))
        self.assertEqual(
            rule.ip_range['end'],
            ipaddr.IPAddress('8.8.8.8'))
        self.assertEqual(
            rule.protocol,
            'http')
        self.assertEqual(
            rule.subdomain,
            'www')

    @patch('rulesengine_client.models.Rule.protocol_applies')
    @patch('rulesengine_client.models.Rule.subdomain_applies')
    @patch('rulesengine_client.models.Rule.ip_range_applies')
    @patch('rulesengine_client.models.Rule.seconds_since_capture_applies')
    @patch('rulesengine_client.models.Rule.capture_date_applies')
    @patch('rulesengine_client.models.Rule.retrieve_date_applies')
    @patch('rulesengine_client.models.Rule.warc_match_applies')
    @patch('rulesengine_client.models.Rule.collection_applies')
    @patch('rulesengine_client.models.Rule.partner_applies')
    def test_applies(self, partner_applies, collection_applies,
                     warc_match_applies, retrieve_date_applies,
                     capture_date_applies, seconds_since_capture_applies,
                     ip_range_applies, protocol_applies, subdomain_applies):
        rule = Rule('http://(com,example,)', 'block')
        rule.applies('warc', '0.0.0.0', datetime.now(tz=utc))
        self.assertEqual(warc_match_applies.call_count, 1)
        self.assertEqual(seconds_since_capture_applies.call_count, 1)
        self.assertEqual(protocol_applies.call_count, 1)
        self.assertEqual(subdomain_applies.call_count, 1)
        self.assertEqual(capture_date_applies.call_count, 0)
        self.assertEqual(retrieve_date_applies.call_count, 0)
        self.assertEqual(collection_applies.call_count, 0)
        self.assertEqual(partner_applies.call_count, 0)
        self.assertEqual(ip_range_applies.call_count, 0)
        rule.applies('warc', '0.0.0.0', datetime.now(tz=utc),
                     server_side_filters=False)
        self.assertEqual(seconds_since_capture_applies.call_count, 2)
        self.assertEqual(protocol_applies.call_count, 2)
        self.assertEqual(subdomain_applies.call_count, 2)
        self.assertEqual(warc_match_applies.call_count, 2)
        self.assertEqual(capture_date_applies.call_count, 1)
        self.assertEqual(retrieve_date_applies.call_count, 1)
        self.assertEqual(collection_applies.call_count, 1)
        self.assertEqual(partner_applies.call_count, 1)
        self.assertEqual(ip_range_applies.call_count, 0)

    def test_ip_range_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            ip_range={
                'start': '4.4.4.4',
                'end': '8.8.8.8',
            })
        self.assertEqual(rule.ip_range_applies('5.5.5.5'), True)
        self.assertEqual(rule.ip_range_applies('9.9.9.9'), False)
        rule = Rule('http://(com,example,)', 'block')
        self.assertEqual(rule.ip_range_applies('5.5.5.5'), True)

    def test_seconds_since_capture_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            seconds_since_capture=500)
        now = datetime.now(tz=utc)
        self.assertEqual(
            rule.seconds_since_capture_applies(datetime2timestamp(now)), True)
        self.assertEqual(
            rule.seconds_since_capture_applies(datetime2timestamp(now - timedelta(days=1))),
            False)
        rule = Rule('http://(com,example,)', 'block')
        self.assertEqual(rule.seconds_since_capture_applies('5.5.5.5'), True)

    def test_capture_date_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            # compare block rule capture dates to timestamps as bytes
            capture_date={
                'start': '20000101120000'.encode(),
                'end': '20010101120000'.encode(),
            })
        self.assertEqual(
            rule.capture_date_applies('20000102000000'.encode()),
            True)
        self.assertEqual(
            rule.capture_date_applies('20020102000000'.encode()),
            False)
        rule = Rule('http://(com,example,)', 'block')
        self.assertEqual(
            rule.capture_date_applies('20000102000000'.encode()),
            True)

    def test_retrieve_date_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            retrieve_date={
                'start': (datetime.now(tz=utc) -
                          timedelta(days=1)),
                'end': (datetime.now(tz=utc) + timedelta(days=1)),
            })
        self.assertEqual(rule.retrieve_date_applies(), True)
        self.assertEqual(
            rule.retrieve_date_applies(
                retrieve_date=datetime(2000, 1, 1, tzinfo=utc)),
            False)

    def test_collection_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            collection='Planets')
        self.assertEqual(rule.collection_applies('Planets'), True)
        self.assertEqual(rule.collection_applies('bad-wolf'), False)
        rule = Rule(
            'http://(com,example,)',
            'block')
        self.assertEqual(rule.collection_applies('Planets'), True)

    def test_partner_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            partner='Holst')
        self.assertEqual(rule.partner_applies('Holst'), True)
        self.assertEqual(rule.partner_applies('bad-wolf'), False)
        rule = Rule(
            'http://(com,example,)',
            'block')
        self.assertEqual(rule.partner_applies('Holst'), True)

    def test_protocol_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            protocol='http')
        self.assertEqual(rule.protocol_applies('http'), True)
        self.assertEqual(rule.protocol_applies('https'), False)
        rule = Rule(
            'http://(com,example,)',
            'block')
        self.assertEqual(rule.protocol_applies('https'), True)

    def test_subdomain_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            subdomain='www')
        self.assertEqual(rule.subdomain_applies('www'), True)
        self.assertEqual(rule.subdomain_applies('web'), False)
        rule = Rule(
            'http://(com,example,)',
            'block')
        self.assertEqual(rule.subdomain_applies('web'), True)

class RuleCollectionModelTestCase(unittest.TestCase):

    def test_init_and_sort(self):
        rules = [
            Rule('http://(com,example,a)', 'block'),
            Rule('http://(com,example,c)', 'block'),
            Rule('http://(com,example,b)', 'block'),
        ]
        collection = RuleCollection(rules)
        self.assertEqual(
            [rule.surt for rule in collection.rules],
            [
                'http://(com,example,a)',
                'http://(com,example,b)',
                'http://(com,example,c)',
            ])

    def test_filter_applicable_rules(self):
        collection = RuleCollection([
            Rule('http://(com,example,a)', 'block', partner='Holst'),
            Rule('http://(com,example,c)', 'block', partner='Holst'),
            Rule('http://(com,example,b)', 'block', partner='Bizet'),
        ])
        applicable_rules = collection.filter_applicable_rules(
            'warc', partner='Holst', server_side_filters=False)
        self.assertEqual(
            [rule.surt for rule in applicable_rules.rules],
            [
                'http://(com,example,a)',
                'http://(com,example,c)',
            ])

    def test_allow(self):
        collection = RuleCollection([
            Rule('http://(com,', 'block'),
            Rule('http://(com,example,', 'block'),
            Rule('http://(com,example,a)', 'allow'),
        ])
        self.assertEqual(collection.allow(), True)
        collection = RuleCollection([
            Rule('http://(com,', 'block'),
            Rule('http://(com,example,', 'allow'),
            Rule('http://(com,example,a)', 'block'),
        ])
        self.assertEqual(collection.allow(), False)
        collection = RuleCollection([
            Rule('http://(com,', 'block'),
            Rule('http://(com,example,', 'allow'),
            Rule('http://(com,example,a)', 'rewrite-js'),
        ])
        self.assertEqual(collection.allow(), True)

    def test_rewrites_only(self):
        collection = RuleCollection([
            Rule('http://(com,', 'block'),
            Rule('http://(com,example,', 'block'),
            Rule('http://(com,example,a)', 'rewrite-js'),
        ])
        rewrites_only = collection.rewrites_only()
        self.assertEqual([rule.surt for rule in rewrites_only.rules],
                         ['http://(com,example,a)'])
