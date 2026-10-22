import unittest

from promote import MUTABLE, approved_pair, key_expression, selection, update_sql
from refine import LABELS


class PromotionTests(unittest.TestCase):
    def original(self):
        return {'site_id':1,'timestamp':'2026-10-21 21:00:00','timestamp_ms':'2026-10-21 21:00:00.100',
                'user_id':'aaaaaaaaaaaa','session_id':'old-session','ip':None,'pathname':'/','country':'\0\0'}

    def recovered(self):
        result = self.original()
        result.update(site_id=2,user_id='bbbbbbbbbbbb',session_id='new-session',country='GB',tag=LABELS['ip_correlated'])
        return result

    def test_only_confirmed_ip_records_are_eligible(self):
        recovered = self.recovered()
        recovered['tag'] = LABELS['unresolved']
        self.assertFalse(approved_pair(self.original(),recovered,0,2000000000))

    def test_recovery_cannot_modify_urls(self):
        recovered = self.recovered()
        recovered['pathname'] = '/changed'
        with self.assertRaises(ValueError):
            approved_pair(self.original(),recovered,0,2000000000)

    def test_recovery_cannot_import_raw_ips(self):
        recovered = self.recovered()
        recovered['ip'] = '192.0.2.1'
        with self.assertRaises(ValueError):
            approved_pair(self.original(),recovered,0,2000000000)

    def test_outside_interval_is_never_eligible(self):
        self.assertFalse(approved_pair(self.original(),self.recovered(),0,1))

    def test_key_is_unchanged_by_all_mutable_fields(self):
        expression = key_expression(['site_id','timestamp_ms','pathname',*MUTABLE])
        self.assertIn('`pathname`',expression)
        self.assertNotIn('`user_id`',expression)
        self.assertNotIn('`country`',expression)

    def test_mutation_always_has_site_time_and_membership_guards(self):
        manifest = {'site_id':7,'start_epoch':100,'end_epoch':200,'new_map':'verified_map',
                    'key_expression':'immutable_key'}
        sql = update_sql('events','verified_map',manifest)
        self.assertIn('WHERE '+selection(manifest),sql)
        self.assertIn('site_id=7',sql)
        self.assertIn('timestamp<toDateTime(200)',sql)
        self.assertNotIn('INSERT',sql)
        self.assertNotIn('DELETE',sql)


if __name__=='__main__':
    unittest.main()
