import unittest
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from storage import storage
import base64
import ui
import mock


class tests(unittest.TestCase):
    def setUp(self):
        random_generator = Random.new().read
        # self.test_random_private_key = RSA.generate(2048, random_generator)
        # self.test_random_public_key = self.test_random_private_key.publickey()
        storage(db = 3)
        ui.redis_db = 3
        self.app = ui.app.test_client()

        self.b64_private_key = """MIIEogIBAAKCAQEApaaE3Bu5pBEbFQ67rXzvrwwya7VKfPyF6gxw4s/FSmuO2olq
        vmHpxOLvOvY5YsAjARM1oI0PZ4dv4OsTpHsCTw/v5tbcaYw4VZnAwmZKsna8NuP7
        yKgHOR1J2Iql07NLpIR436Imp9TvlFB2pWRpS3cmg0rJcO7r3BkajrnAv9qppqnX
        w9ZCYS1J8UEoOUN42/8pKyRboTZ7PPCwb3eGIOdi8hSH65zJhv+n+2zoLSwMLGt0
        w4v5Ami21tB5izyxl4MYY1hO93UT1UBXcceAoNAVu8TWDBLKUhVk+cL3TMk8eYCM
        8LQCLMqveCdGEJ4J8rHop/lFVqA2OLItvb/zjQIDAQABAoIBAGcKI86+uEUkFtKM
        bZXHB1i9n4d8J6+DbNFfl8CeOTzHlv69R9bRFRbRiroEe0G//oYmqs8Jr7FYf/FK
        iNdhZNhFM5dFw6kr/cbRcyP5eTF1xjHmsrHoQ0X1v/+gjvIWr1DQzlddh+oR/E0n
        mAXdZdn5bc1xcch79d7dBrYNOaacnxIeazEEBpfyq0fV0IUlyOYik1X9UTQlmO1g
        lLEQAcf6ydovXgXcgHaBLeKiBJnTv1M7tFVnKf3fjYeoglxbYKPQSw7neGVJVpjG
        CbTLlmmwkODCLlPaPi4munuDQxKkSMgJ5cKZQU61H15EWTH8DK+VD5jhlm2TzxoE
        W1ceegkCgYEA2onrtkCttnmI8FPwhRviQcUUqnW+PGyalcosg7vP1DjhtDPoYOJC
        Ka0XuYUPJ67QMfZqD+nSQG6tu0r6uTQFWlaGi09UDuJOt7QvbAeYiYU5ibHsg12r
        FSU/N5eao3m5zlfXspRACUbBhozJfjYLpwvAWdLobsdCYQc/TaQdOjsCgYEAwgu3
        GhfeG9/Y4PCXDlQ817aZwNsZMANyNGDo6SJMu924R4+BnlTVTa5DlpKABN5PoygV
        RAnExvN/1Mexd4Pt+YCbZeKUQwRL837RlD8oummNHH1FyN2metV3lnrNBCw8lc4L
        /HtuTvtFa3agsD1oO4SUS92PpJ2+42Lvvu8PZNcCgYBU4p2b/SN8bVizgOc7zMjl
        oxeT3og2EDk7VXxU7u6bED0bMc5hU4E/juxYM0bfsxdLUNuBsuDoBhWVWlpo9bve
        ix1Xn0iXP3A0CtkgrRKi2AyxX1ru68M4Q296uHhoZy+05onx44O8Fq+1A5qAW53L
        FNVyDmoaHWu7JIWCMuznYQKBgGNhlqSBhtrl2XDTJ7pKAGNGfRad4BeMHEihPYhx
        bbVmCAR2hh8uOZSwZKNQYsqbhVP9qm6PRj3S5ix3HfglFJONf4k980sjfza1Q+dW
        NajLeF8X9c67XpFYlQf32tqBQYJD5jWojcVbwaEZP5Ej0idxbnYwgmn/9I0G1d0H
        GO4/AoGAbJpDhD7Rjn3tMQDVyqdKU7+7KhkGMwMMh1nzOYeUC75sDfBXpVKveXVy
        hZuRK6SD9lV4MFl+1H1igBqHVUj5t2zTqNDAxoh13HqpxxxH4GIn0SWbZBNbLfcO
        KjiITfQGNThfsTh2/1HPl6A61E4Iw2G+xGXuy0O/IvYvwBNwveE="""
        self.test_private_key = RSA.importKey(base64.b64decode(self.b64_private_key))

        self.b64_public_key = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApaaE3Bu5pBEbFQ67rXzv
        rwwya7VKfPyF6gxw4s/FSmuO2olqvmHpxOLvOvY5YsAjARM1oI0PZ4dv4OsTpHsC
        Tw/v5tbcaYw4VZnAwmZKsna8NuP7yKgHOR1J2Iql07NLpIR436Imp9TvlFB2pWRp
        S3cmg0rJcO7r3BkajrnAv9qppqnXw9ZCYS1J8UEoOUN42/8pKyRboTZ7PPCwb3eG
        IOdi8hSH65zJhv+n+2zoLSwMLGt0w4v5Ami21tB5izyxl4MYY1hO93UT1UBXcceA
        oNAVu8TWDBLKUhVk+cL3TMk8eYCM8LQCLMqveCdGEJ4J8rHop/lFVqA2OLItvb/z
        jQIDAQAB"""
        self.test_public_key = RSA.importKey(base64.b64decode(self.b64_public_key))

        self.test_evidence = 'gM9LIB7VBHBiVYqpr3l54st76Rwk5R_-sr4xdHpNiPH6RE2K6lrg3eeqa9VdpwXf0tr9UsO27HqVmuLbFQek6mUqwT-2UFgtAnzAwcCy9pBklJSjTwrIM-sdGkXDA6_1qUw5LcWCMsSU__vQb831Dbn10UIWJx4nyhbUukmp6gasiZlzI3al3zusi9zQp4oLDdxVPrdcT6ncgk0C3KQnr33AD0Kbib6akrbWtcwh6_lBD9fvZfA2btGarIkP0RtY9b2pTrGFy5ZKG42z5O2Tr_gtyLPsrSF4kCmH6INtvKicKtRdpPUiz9iXAHA0hceUNlFzyAhwc3eSCgNkG5JXXg==.JgrR-t1myDwn-Na9kZey1D9r2cXdDw_TeiFp-2t9TV_70HCYO-FhXHBVnFVPdOYbM2QkUeGk7yyATmszOgNGK3jSScpBZJy7E01cq_ZGa0DQR0YMlpasHAlQX5iHpSNijENbKMtZ9dpsoRiWZfBteieei_n_v6s94o0mk-SHNzOMSTQNrp01Omz8Anh7Ae9Z'

    def unwrap_request(self, message):
        secret_key_encrypted = base64.urlsafe_b64decode(message.split('.')[0])
        payload_encrypted = base64.urlsafe_b64decode(message.split('.')[1])

        public_cipher = PKCS1_OAEP.new(self.test_private_key)
        sc = public_cipher.decrypt(secret_key_encrypted)

        iv = payload_encrypted[:AES.block_size]
        cipher = AES.new(sc, AES.MODE_CFB, iv)

        pl_unpadded = cipher.decrypt(payload_encrypted[AES.block_size:])
        pl = self._unpad(pl_unpadded).decode('utf-8')
        unwrapped = json.loads(pl)

        return unwrapped

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

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

    def test_cryptoPublicToPrivate_usingTestKeyPair(self):
        random_generator = Random.new().read
        to_encrypt = 'abcdefgh'.encode('utf-8')
        enc_data = self.test_public_key.encrypt(to_encrypt, random_generator)

        dec_data = self.test_private_key.decrypt(enc_data)

        self.assertEqual(dec_data, to_encrypt)

    def test__package_and_encrypt__withTypicalCodeRequest__successfullyDecrypts(self):
        to_encrypt = {'id': '123', 'type': 'code', 'request_content': {'username': 'wibble'}}
        encrypted_data = ui.package_and_encrypt(to_encrypt)

        unwrapped = self.unwrap_request(encrypted_data)

        self.assertEqual(to_encrypt, unwrapped)

    def test__package_and_encrypt__withTypicalResetRequest__successfullyDecrypts(self):
        to_encrypt = {'id': '123', 'type': 'code', 'request_content': {'username': 'wibble', 'evidence': self.test_evidence, 'password': 'Password1'}}
        encrypted_data = ui.package_and_encrypt(to_encrypt)

        unwrapped = self.unwrap_request(encrypted_data)

        self.assertEqual(to_encrypt, unwrapped)

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

    def test__code__whenUsernameIsSupplied__storesRequestForCode(self):
        self.clear_requests()
        ui.public_key = self.test_public_key
        ui.backend_wait_time_seconds = 3

        code_response = self.app.post('/code', data={'username': 'wibble', 'id': 'abcd1234'})

        b64_encrypted_request = storage.lpop('requests')

        if b64_encrypted_request == None:
            self.fail('No request was stored')
            return

        request = self.unwrap_request(b64_encrypted_request)

        self.assertIsNotNone(request, 'Unwrapped request was None')

        self.assertIn('id', request)
        self.assertIn('type', request)
        self.assertIn('request_content', request)
        self.assertEqual('code', request['type'])
        self.assertEqual({'username': 'wibble'}, request['request_content'])

    def test__reset__whenCodeAndPasswordIsSupplied__storesRequestForReset(self):
        self.clear_requests()
        #ui.public_key = self.test_private_key
        reset_request_form = {'id': 'nY0WZvm2n9go',
            'evidence': self.test_evidence,
            'username': 'wibble',
            'password': 'Password1',
            'password-confirm': 'Password1'}

        storage.hset('reset_responses', 'aaa123123', json.dumps({'status': 'OK'}))

        with mock.patch('storage.storage.hget', return_value='{"status": "OK"}'):
            reset_response = self.app.post('/reset', data=reset_request_form)

            b64_encrypted_request = storage.lpop('requests')

            if b64_encrypted_request == None:
                self.fail('No request was stored')
                return

            request = self.unwrap_request(b64_encrypted_request)

            self.assertIsNotNone(request, 'Unwrapped request was None')

            self.assertIn('id', request)
            self.assertIn('type', request)
            self.assertIn('request_content', request)
            self.assertIn('username', request['request_content'])
            self.assertIn('evidence', request['request_content'])
            self.assertIn('password', request['request_content'])

            self.assertEqual('nY0WZvm2n9go', request['id'])
            self.assertEqual('reset', request['type'])
            self.assertEqual('wibble', request['request_content']['username'])
            self.assertEqual(self.test_evidence, request['request_content']['evidence'])
            self.assertEqual('Password1', request['request_content']['password'])

    def test__password__whenCalledWithValidRequest__returnsPageRequestingNewPassword(self):
        path = '/password/fRzzadwEHx0uSzBEAoh8KFKo7CTIfJMgA5dpvK2D4ZIpdCMUSlVX6k4Q9kkyXHTX-KNbjnI_us31McOzPFHG3OhWY6-DKpn2dNPQg5UqaQoWngZ6cut-E1wHjmzVrDq35G6zV-MhE4kSG17-mKJ42vW2kwavP2cJw989e926wSfpx0OCR0UKozxov34uw5CzNXBmCfSYVJ33OKAphdzcVkCyIxKR3ljNMFYGZcEGc2PBGsj0hrP49BGis033XvxHes38zZnx5W5H2hVIqcl2FQ4HMGe4uzT8R7jR4TJ0iF_rVlOPsUBrupkrl-_A_8karVvJ3F39mTSAJVzxwE2X4w=='
        password_response = self.app.post(path, data={'username': 'wibble', 'id': '123456'})
        body = password_response.data.decode('utf-8')

        self.assertEqual(200, password_response.status_code)
        self.assertIn('value="wibble"', body)
        self.assertIn('value="123456"', body)
        self.assertIn('<form action="/reset"', body)

    def test__reset__whenCalledWithValidRequestAndPasswordEvidence__storesPasswordResetRequest(self):
        path = '/reset'
        form = {'id': 'nY0WZvm2n9go',
            'evidence': self.test_evidence,
            'username': 'brett',
            'password': 'Password1',
            'password-confirm': 'Password1'}

        with mock.patch('storage.storage.hget', return_value='{"status": "OK"}'):
            reset_response = self.app.post(path, data=form)
            body = reset_response.data.decode('utf-8')

            self.assertEqual(200, reset_response.status_code)
            self.assertIn('Your password is reset', body)

