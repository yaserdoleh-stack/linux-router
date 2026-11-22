import unittest
import kea_http_sync as sync

class SyncTests(unittest.TestCase):
    def test_merge_preserves_backup_settings(self):
        primary = {k: 'primary-value' for k in sync.SHARED_FIELDS}
        backup = {'interface': 'lan0', 'ha_role': 'backup', 'ha_peer_ip': '172.16.2.253', 'sync_enabled': True}
        merged = sync.merge(primary, backup)
        for key in ('interface', 'ha_role', 'ha_peer_ip', 'sync_enabled'):
            self.assertEqual(merged[key], backup[key])
        self.assertEqual(merged['subnet'], 'primary-value')
    def test_hash_validation(self):
        shared = {k: 'example' for k in sync.SHARED_FIELDS}
        payload = {'config': shared, 'sha256': sync.config_hash(shared)}
        sync.verify_payload(payload)
        payload['sha256'] = 'invalid'
        with self.assertRaises(ValueError):
            sync.verify_payload(payload)
    def test_host_validation(self):
        self.assertEqual(sync.validate_host('172.16.2.253'), '172.16.2.253')
        with self.assertRaises(ValueError):
            sync.validate_host('http://172.16.2.253')

if __name__ == '__main__':
    unittest.main()
