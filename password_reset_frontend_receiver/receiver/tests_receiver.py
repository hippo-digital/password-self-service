import unittest
import json
from Crypto.PublicKey import RSA
from Crypto import Random
from storage import storage
import base64
import receiver


class tests(unittest.TestCase):
    def setUp(self):
        random_generator = Random.new().read
        self.test_private_key = RSA.generate(2048, random_generator)
        self.test_public_key = self.test_private_key.publickey()
        storage(db = 3)
        receiver.redis_db = 3
        self.app = receiver.app.test_client()

    def unwrap_request(self, b64_encrypted_request):
        encrypted_request = base64.b64decode(b64_encrypted_request)

        request_data = self.test_private_key.decrypt(encrypted_request)
        return json.loads(request_data.decode('utf-8'))

    def clear_requests(self):
        req = ''

        while req != None:
            req = storage.lpop('requests')

    def test__requests__whenCalledWithNoRequestsStored__returnsEmptySetAsJSON(self):
        self.clear_requests()

        requests_request = self.app.get('/requests')
        requests_body = requests_request.data.decode('utf-8')
        requests = json.loads(requests_body)

        self.assertEqual(0, len(requests))

    def test__requests__whenCalledWithThreeRequestsStored__returnsRequestsSetAsJSON(self):
        self.clear_requests()

        for i in range(0, 3):
            storage.rpush('requests', 'abc')

        requests_request = self.app.get('/requests')
        requests_body = requests_request.data.decode('utf-8')
        requests = json.loads(requests_body)

        self.assertEqual(3, len(requests))




