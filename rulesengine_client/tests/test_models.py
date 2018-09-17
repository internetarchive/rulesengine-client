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
    # RuleCollection,
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
            warc_match='.*jupiter.*')
        self.assertEqual(
            rule.capture_date['start'],
            datetime(year=2000, month=1, day=1, hour=12, minute=0, second=0,
                     tzinfo=utc))
        self.assertEqual(
            rule.capture_date['end'],
            datetime(year=2001, month=1, day=1, hour=12, minute=0, second=0,
                     tzinfo=utc))
        self.assertEqual(
            rule.retrieve_date['start'],
            datetime(year=2000, month=1, day=1, hour=12, minute=0, second=0,
                     tzinfo=utc))
        self.assertEqual(
            rule.retrieve_date['end'],
            datetime(year=2001, month=1, day=1, hour=12, minute=0, second=0,
                     tzinfo=utc))
        self.assertEqual(
            rule.ip_range['start'],
            ipaddr.IPAddress('4.4.4.4'))
        self.assertEqual(
            rule.ip_range['end'],
            ipaddr.IPAddress('8.8.8.8'))

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
                     ip_range_applies):
        rule = Rule('http://(com,example,)', 'block')
        rule.applies('warc', '0.0.0.0', datetime.now(tz=utc))
        self.assertEqual(ip_range_applies.call_count, 1)
        self.assertEqual(seconds_since_capture_applies.call_count, 1)
        self.assertEqual(capture_date_applies.call_count, 0)
        self.assertEqual(retrieve_date_applies.call_count, 0)
        self.assertEqual(warc_match_applies.call_count, 1)
        self.assertEqual(collection_applies.call_count, 0)
        self.assertEqual(partner_applies.call_count, 0)
        rule.applies('warc', '0.0.0.0', datetime.now(tz=utc),
                     server_side_filters=False)
        self.assertEqual(ip_range_applies.call_count, 2)
        self.assertEqual(seconds_since_capture_applies.call_count, 2)
        self.assertEqual(capture_date_applies.call_count, 1)
        self.assertEqual(retrieve_date_applies.call_count, 1)
        self.assertEqual(warc_match_applies.call_count, 2)
        self.assertEqual(collection_applies.call_count, 1)
        self.assertEqual(partner_applies.call_count, 1)

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
            rule.seconds_since_capture_applies(now), True)
        self.assertEqual(
            rule.seconds_since_capture_applies(now - timedelta(days=1)),
            False)
        rule = Rule('http://(com,example,)', 'block')
        self.assertEqual(rule.seconds_since_capture_applies('5.5.5.5'), True)

    def test_capture_date_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            capture_date={
                'start': '2000-01-01T12:00:00.000Z',
                'end': '2001-01-01T12:00:00.000Z',
            })
        self.assertEqual(
            rule.capture_date_applies(datetime(2000, 1, 2, tzinfo=utc)),
            True)
        self.assertEqual(
            rule.capture_date_applies(datetime(2002, 1, 2, tzinfo=utc)),
            False)
        rule = Rule('http://(com,example,)', 'block')
        self.assertEqual(
            rule.capture_date_applies(datetime(2000, 1, 2, tzinfo=utc)),
            True)

    def test_retieve_date_applies(self):
        rule = Rule(
            'http://(com,example,)',
            'block',
            retrieve_date={
                'start': (datetime.now(tz=utc) -
                          timedelta(days=1)).isoformat(),
                'end': (datetime.now(tz=utc) + timedelta(days=1)).isoformat(),
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
