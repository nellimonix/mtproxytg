import unittest
from recovery_model import ConservativeBridge, LogMatcher, Sessionizer, technical_identity


def event(timestamp='2026-10-21 21:00:00.000', identity='old'):
    return {'timestamp':timestamp[:19], 'timestamp_ms':timestamp, 'hostname':'sample.invalid',
            'user_id':identity,'browser':'Browser','browser_version':'1','operating_system':'OS',
            'operating_system_version':'1','screen_width':400,'screen_height':800,'language':'en'}


def log(start_ms, identity='client-a', native='native-a'):
    value=event()
    value.update({'start_ms':start_ms,'end_ms':start_ms+10,'old_id':'old',
                  'target_identity':identity,'native_id':native})
    return value


class RecoveryTests(unittest.TestCase):
    def anchor(self, timestamp, identity='visitor-a', legacy='old'):
        record=event()
        record.update(time_ms=timestamp,canonical_id=identity,legacy_id=legacy)
        return record

    def test_bridge_requires_anchors_on_both_sides(self):
        bridge=ConservativeBridge([self.anchor(1792616390000)])
        self.assertIsNone(bridge.match(event(),'old'))

    def test_bridge_reuses_confirmed_identity(self):
        bridge=ConservativeBridge([self.anchor(1792616390000),self.anchor(1792616410000)])
        self.assertEqual(bridge.match(event(),'old'),'visitor-a')

    def test_bridge_rejects_conflicting_nearby_identity(self):
        bridge=ConservativeBridge([self.anchor(1792616390000),self.anchor(1792616410000),
                                   self.anchor(1792616420000,'visitor-b','other')])
        self.assertIsNone(bridge.match(event(),'old'))

    def test_bridge_does_not_extrapolate_to_old_days(self):
        bridge=ConservativeBridge([self.anchor(1792616300000),self.anchor(1792616500000)])
        self.assertIsNone(bridge.match(event(),'old'))

    def test_shared_time_with_different_ips_is_ambiguous(self):
        matcher=LogMatcher([log(1792616400000),log(1792616400000,'client-b')])
        matched,status=matcher.match(event())
        self.assertIsNone(matched)
        self.assertEqual(status,'ambiguous')

    def test_repeated_requests_from_same_identity_are_safe(self):
        matcher=LogMatcher([log(1792616400000),log(1792616400010)])
        matched,status=matcher.match(event())
        self.assertEqual(status,'ip_correlated')
        self.assertEqual(matched['target_identity'],'client-a')

    def test_clock_alignment_uses_known_postfix_identities(self):
        logs=[]
        events=[]
        for second in range(0,120,4):
            value=event('2026-10-21 21:%02d:%02d.120'%(second//60,second%60),'native-a')
            events.append(value)
            logs.append(log(1792616400000+second*1000))
        matcher=LogMatcher(logs)
        result=matcher.calibrate(events)
        self.assertEqual(result['clock_offset_ms'],120)
        self.assertEqual(result['validation_precision'],1)

    def test_sessions_expire_after_thirty_minutes(self):
        sessions=Sessionizer(b'key')
        first=sessions.session('one',0)
        self.assertEqual(first,sessions.session('one',1000))
        self.assertNotEqual(first,sessions.session('one',1801000))

    def test_known_proxy_aliases_validate_against_canonical_identity(self):
        logs=[]
        events=[]
        for second in range(0,120,4):
            value=event('2026-10-21 21:%02d:%02d.120'%(second//60,second%60),'canonical-a')
            events.append(value)
            record=log(1792616400000+second*1000,native='rotating-ip')
            record['canonical_id']='canonical-a'
            logs.append(record)
        result=LogMatcher(logs).calibrate(events)
        self.assertEqual(result['validation_precision'],1)
        self.assertEqual(result['known_identity_aliases'],len(logs))

    def test_profile_identity_is_separate_from_observed_user_id(self):
        first=event(identity='old-a')
        second=event(identity='old-b')
        self.assertEqual(technical_identity(b'key',first),technical_identity(b'key',second))
        second['screen_width']=600
        self.assertNotEqual(technical_identity(b'key',first),technical_identity(b'key',second))


if __name__=='__main__':
    unittest.main()
