import requests
import time
import json
import string
import random
import yaml
import os
import logging
import hashlib
import base64
import sys

from ad_connector import search_object, set_password
from twilio.rest import Client
from Crypto import Random
from Crypto.PublicKey import RSA



class poller():
    def __init__(self):
        self.log = logging.getLogger('password_reset_backend')
        self.log.setLevel(logging.DEBUG)
        fh = logging.FileHandler('c:\\temp\\password_reset_backend.log')
        fh.setLevel(logging.DEBUG)
        self.log.addHandler(fh)
        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
        fh.setFormatter(formatter)
        self.log.info("Poller started")

        self.log.info('Loading config')
        self.config = self.loadconfig('config.yml')
        self.log.info('Configuration: %s' % self.config)

        self.salt = ''.join(random.choice(string.printable) for _ in range(100))
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
        self.private_key = RSA.importKey(base64.b64decode(self.b64_private_key))

    def poll(self):
        reqs = {}
        try:
            req = requests.get('%s/requests' % self.config['frontend']['address'])

            if req.status_code == 200:
                result_raw = req.content.decode('utf-8')
                reqs = json.loads(result_raw)
        except Exception as ex:
            self.log.info(ex)


        for req in reqs:
            None

        if reqs != [] and reqs != None:
            if 'codes' in reqs:
                for code in reqs['codes']:
                    try:
                        code_request = json.loads(code)
                    except Exception as ex:
                        self.log.error('Method=poll, Message=Failed to parse JSON input, Input=%s, Exception=%s', (code, ex))
                        break

                    try:
                        self.send_code(code_request['username'], code_request['id'])
                    except Exception as ex:
                        self.log.error('Method=poll, Message=Failed to send code, Input=%s, Exception=%s', (code_request, ex))
                        break

            if 'resets' in reqs:
                for reset_raw in reqs['resets']:
                    try:
                        reset = json.loads(reset_raw)
                    except Exception as ex:
                        self.log.error('Method=poll, Message=Failed to parse JSON input, Input=%s, Exception=%s', (reset_raw, ex))
                        break

                    try:
                        self.reset_password(reset)
                    except Exception as ex:
                        self.log.error('Method=poll, Message=Failed reset password, Input=%s, Exception=%s', (reset, ex))
                        break

    def unwrap_request(self, b64_encrypted_request):
        encrypted_request = base64.b64decode(b64_encrypted_request)
        decrypted_request = self.private_key.decrypt(encrypted_request)
        ret = json.loads(decrypted_request.decode('utf-8'))
        return ret

    def send_code(self, username, id):
        self.log.info('Method=send_code, Username=%s, ID=%s' % (username, id))

        q = search_object.search_object()
        users = None

        try:
            users = q.search(username, self.config['directory']['dn'], self.config['directory']['fqdn'])
        except Exception as ex:
            self.log.error('Method=send_code, Message=Error searching for user,username=%s' % username, ex)

        if len(users) == 0:
            self.log.info('Method=send_code, Message=User could not be found in the directory, Username=%s' % username)
            requests.post('%s/coderesponse/%s/Failed' % (self.config['frontend']['address'], id), data='User account could not be found')
        elif len(users) == 1 and 'mobile' in users[0]:
            user = users[0]
            mobile_number = user['mobile']

            code = "%s%s %03d %03d" % (random.choice(string.ascii_uppercase),
                                       random.choice(string.ascii_uppercase),
                                       random.randint(0, 999),
                                       random.randint(0, 999))
            raw_code = code.replace(' ', '')

            try:
                self.send_sms(mobile_number, code)
            except Exception as ex:
                self.log.error('Method=send_code, Message=Error sending code, username=%s, Code=%s' % (username, code), ex)

            try:
                code_hash = self.generate_code_hash(username, raw_code, id)
                requests.post('%s/coderesponse/%s/OK' % (self.config['frontend']['address'], id), data=code_hash)
            except Exception as ex:
                self.log.error('Method=send_code, Message=Error setting status on frontend, username=%s, Code=%s' % (username, code), ex)
        else:
            self.log.error('Method=send_code, Message=Too many objects returned, Data=%s' % users)

    def send_sms(self, mobile_number, code):
        self.log.info('Method=send_sms, Message=Setting up API')

        twilio_sid = self.config['sms']['twilio_sid']
        twilio_authcode = self.config['sms']['twilio_authcode']
        from_text = self.config['sms']['organisation_shortname']
        body = self.config['sms']['message'] % code

        client = Client(twilio_sid, twilio_authcode)

        try:
            client.messages.create(
                to = mobile_number,
                from_ = from_text,
                body = body
            )
            self.log.info('Method=send_sms, Message=Successfully sent SMS, mobile_number=%s' % mobile_number)
        except Exception as ex:
            self.log.error('Method=send_sms, Message=Failed to send SMS, mobile_number=%s, twilio_sid=%s, twilio_authcode=%s, from_text=%s, body=%s' % (mobile_number, twilio_sid, twilio_authcode, from_text, body))
            # raise(ex)

    def reset_password(self, reset_request):
        if 'username' in reset_request and 'code' in reset_request and 'code_hash' in reset_request and 'id' in reset_request and 'password' in reset_request:
            self.log.info('Method=reset_request, Username=%s, Code=%s, CodeHash=%s, ID=%s' % (
                reset_request['username'],
                reset_request['code'],
                reset_request['code_hash'],
                reset_request['id']))

            expected_hash = self.generate_code_hash(reset_request['username'], reset_request['code'], reset_request['id'])

            if expected_hash != reset_request['code_hash']:
                requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], reset_request['id']), data='The reset code supplied was incorrect')
            else:
                self.reset_ad_password(reset_request['username'], reset_request['password'])
                requests.post('%s/resetresponse/%s/OK' % (self.config['frontend']['address'], reset_request['id']), data='')
        else:
            raise(Exception())

    def reset_ad_password(self, username, new_password):
        self.log.info('Method=reset_ad_password, Username=%s' % username)
        q = search_object.search_object()

        try:
            users = q.search(username, self.config['directory']['dn'], self.config['directory']['fqdn'])
        except Exception as ex:
            print(ex)

        if len(users) != 1:
            raise Exception('Incorrect')

        user = users[0]

        pwd = set_password.set_password()
        pwd.set(user['distinguishedName'], new_password, self.config['directory']['dn'], self.config['directory']['fqdn'])

    def loadconfig(self, config_file_path):
        script_path = os.path.dirname(os.path.realpath(__file__))
        with open('%s/%s' % (script_path, config_file_path)) as cfgstream:
            cfg = yaml.load(cfgstream)
            return cfg

    def generate_code_hash(self, username, code, id):
        to_hash = '%s.%s.%s.%s' % (username.upper(), code.upper(), id, self.salt)
        hash = hashlib.sha512(to_hash.encode('utf-8')).digest()
        b64_hash = base64.b64encode(hash).decode('utf-8')
        return b64_hash


if __name__ == '__main__':
    p = poller()

    while True:
        p.poll()
        time.sleep(1)

