import unittest
import json
from Crypto.PublicKey import RSA
from Crypto import Random
from storage import storage
import base64
import ui


class tests(unittest.TestCase):
    def setUp(self):
        random_generator = Random.new().read
        self.test_private_key = RSA.generate(2048, random_generator)
        self.test_public_key = self.test_private_key.publickey()
        storage(db = 3)
        ui.redis_db = 3
        self.app = ui.app.test_client()

    def unwrap_request(self, b64_encrypted_request):
        encrypted_request = base64.b64decode(b64_encrypted_request)

        request_data = self.test_private_key.decrypt(encrypted_request)
        return json.loads(request_data.decode('utf-8'))

    def clear_requests(self):
        req = ''

        while req != None:
            req = storage.lpop('requests')

    def test_crypto(self):
        random_generator = Random.new().read
        key = RSA.generate(2048, random_generator)
        to_encrypt = 'abcdefgh'.encode('utf-8')

        public_key = key.publickey()
        enc_data = public_key.encrypt(to_encrypt, random_generator)

        dec_data = key.decrypt(enc_data)

        self.assertEqual(dec_data, to_encrypt)

    def test__store_request__whenCalledWithValidData__storesInRedis(self):
        ui.public_key = self.test_public_key
        ui.store_request('123', '456', {'req': 789})

        b64_encrypted_request = storage.lpop('requests')

        self.assertIsNotNone(b64_encrypted_request, 'Request was not stored in Redis')

    def test__store_request__whenCalledWithValidData__storesInRedisAndIsRetrievableUsingPrivateKey(self):
        self.clear_requests()

        ui.public_key = self.test_public_key
        ui.store_request('123', '456', {'req': 789})

        b64_encrypted_request = storage.lpop('requests')

        request = self.unwrap_request(b64_encrypted_request)

        self.assertIsNotNone(request, 'Unwrapped request was None')

        self.assertIn('id', request)
        self.assertIn('type', request)
        self.assertIn('request_content', request)
        self.assertEqual('123', request['id'])
        self.assertEqual('456', request['type'])
        self.assertEqual({'req': 789}, request['request_content'])
