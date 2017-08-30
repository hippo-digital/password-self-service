import unittest
import json
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import mock
import poller


class tests_poller(unittest.TestCase):
    # This method will be used by the mock to replace requests.get
    def mocked_send_sms(self, *args, **kwargs):
        class SendSMSSuccess:
            class messages():
                def create(self, to=None, from_=None, body=None):
                    None

        return SendSMSSuccess()

    def mocked_pyad(self, *args, **kwargs):
        class MockedPyAD:
            def __init__(self):
                self.results = []

            def get_results(self):
                return self.results

            def execute_query(self, attributes=None, where_clause=None, base_dn=None):
                return None

        return MockedPyAD()

    def setUp(self):
        self.test_request_raw = 'Dpeac2xvdXVTuXocPkLKayuej/IRQY3i32RqhQMm3M1fBEB5scnj9xMz+5AzV1JO+MOQeB+8M65KNaNIIeNA3G3R5QgZzra/CgTT6s1nseNav8dsLND6f9nfC2TsBANooboNRxb5grjdKxujqLjX4WUnYgMTHf6b3/jwF+ftUoMJwDqFO2UhJE+pkAjmzSacwtkYSmeGoKNJKj+BmiIdFCjOJqpoP2IS4aUbGP9BLzuHiM5DoN12SmIViuoCbUROXQ3a/+I3yh5wNGbDGZmVwfr3f+1LQL6R9AzQ3vveoH16FQR7uLW1t1hJS07/pEMTKMuSrjUP2IBbsSNhWL3dtA=='

    def unwrap_request(self, b64_encrypted_request):
        encrypted_request = base64.b64decode(b64_encrypted_request)

        request_data = self.test_private_key.decrypt(encrypted_request)
        return json.loads(request_data.decode('utf-8'))

    def test_crypto(self):
        random_generator = Random.new().read
        key = RSA.generate(2048, random_generator)
        to_encrypt = 'abcdefgh'.encode('utf-8')

        public_key = key.publickey()
        enc_data = public_key.encrypt(to_encrypt, random_generator)

        dec_data = key.decrypt(enc_data)

        self.assertEqual(dec_data, to_encrypt)

    def test_unwrap(self):
        import poller

        p = poller.poller()
        req = p.unwrap_request(self.test_request_raw)

        self.assertIn('id', req)
        self.assertIn('type', req)
        self.assertIn('request_content', req)
        self.assertIn('username', req['request_content'])
        self.assertEqual('brett', req['request_content']['username'])

    def test__send_code__whenCalledWithValidParameters__calls_send_sms(self):
        from ad_connector import search_object, set_password
        p = poller.poller()

        with mock.patch('ad_connector.search_object.search_object', autospec=True, entries=[user_obj()], bound=True, return_value=wibble()) as ldap_conn:
        # with mock.patch('pyad.adquery.ADQuery', side_effect=self.mocked_pyad):
            with mock.patch('requests.post') as post_request:
                with mock.patch('poller.poller.send_sms') as mocked_sms:
                    p.send_code('wibble', '123')
                    mocked_sms.assert_called()
                    called_args = mocked_sms.call_args_list[0][0]

                    self.assertEqual('123456', called_args[0])
                    self.assertEqual(10, len(called_args[1]))

    def test__poll__whenCalled__callsRequestsURL(self):
        p = poller.poller()

        with mock.patch ('requests.get') as get_request:
            p.poll()

            address = get_request.call_args[0][0]

            get_request.assert_called()
            self.assertIn('/requests', address)

    def test__mock__pyad(self):
        with mock.patch('ad_connector.search_object.search_object', autospec=True, entries=[user_obj()], bound=True, return_value=wibble()) as ldap_conn:
        # with mock.patch('pyad.adquery.ADQuery', side_effect=self.mocked_pyad):
            from ad_connector import search_object

            so = search_object.search_object()
            so.search('test_cn', 'test_domain', 'test_server')
            None

class user_obj:
    def __init__(self):
        self.entry_dn = ''
        self.entry_attributes_as_dict = {'sn': ['Smith'], 'givenName': ['Sandra'], 'mail': ['sandra.smith@example.org'], 'mobile': ['123456']}

class wibble:
    def search(self, a, b, c):
        return [{'sn': 'Smith', 'givenName': 'Sandra', 'mail': 'sandra.smith@example.org', 'mobile': '123456'}]
