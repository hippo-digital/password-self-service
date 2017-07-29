import unittest
import json
from Crypto.PublicKey import RSA
from Crypto import Random
from storage import storage
import base64
import view


class tests(unittest.TestCase):
    def setUp(self):
        random_generator = Random.new().read
        self.test_private_key = RSA.generate(2048, random_generator)
        self.test_public_key = self.test_private_key.publickey()
        storage(db = 3)
        view.redis_db = 3
        self.app = view.app.test_client()

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

        public_key = key.publickey()
        enc_data = public_key.encrypt('abcdefgh'.encode('utf-8'), random_generator)

        dec_data = key.decrypt(enc_data)

        None


    def test__store_request__whenCalledWithValidData__storesInRedis(self):
        view.public_key = self.test_public_key
        view.store_request('123', '456', {'req': 789})

        b64_encrypted_request = storage.lpop('requests')

        self.assertIsNotNone(b64_encrypted_request, 'Request was not stored in Redis')

    def test__store_request__whenCalledWithValidData__storesInRedisAndIsRetrievableUsingPrivateKey(self):
        self.clear_requests()

        view.public_key = self.test_public_key
        view.store_request('123', '456', {'req': 789})

        b64_encrypted_request = storage.lpop('requests')

        request = self.unwrap_request(b64_encrypted_request)

        self.assertIsNotNone(request, 'Unwrapped request was None')

        self.assertIn('id', request)
        self.assertIn('type', request)
        self.assertIn('request_content', request)
        self.assertEqual('123', request['id'])
        self.assertEqual('456', request['type'])
        self.assertEqual({'req': 789}, request['request_content'])

    def test__requests__whenCalledWithNoRequestsStored__returnsEmptySetAsJSON(self):
        self.clear_requests()

        requests_request = self.app.get('/requests')
        requests_body = requests_request.data.decode('utf-8')
        requests = json.loads(requests_body)

        self.assertEqual(0, len(requests))

    def test__requests__whenCalledWithThreeRequestsStored__returnsRequestsSetAsJSON(self):
        self.clear_requests()

        view.public_key = self.test_public_key

        for i in range(0, 3):
            view.store_request('%s' % i, '%s' % (i + 100), {'req': i + 200})

        requests_request = self.app.get('/requests')
        requests_body = requests_request.data.decode('utf-8')
        requests = json.loads(requests_body)

        self.assertEqual(3, len(requests))




