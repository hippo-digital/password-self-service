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
from Crypto.Cipher import AES, PKCS1_OAEP


class poller():
    def __init__(self):
        self.session_service_template = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RequestSet vers="1.0" svcid="session" reqid="1">
<Request><![CDATA[<SessionRequest vers="1.0" reqid="0">
<GetSession reset="true">
<SessionID>{{ ticket }}</SessionID>
</GetSession>
</SessionRequest>]]>
</Request>
</RequestSet>"""
        self.log = logging.getLogger('password_reset_backend')

        self.config = self.loadconfig('config.yml')

        self.domain_dn = self.config['directory']['dn']
        self.domain_fqdn = self.config['directory']['fqdn']
        self.auth_service_validate_ticket_uri = '%s/amserver/sessionservice' % self.config['auth_service']['address']

        self.log.info('Configuration: %s' % self.config)

        self.salt = ''.join(random.choice(string.printable) for _ in range(100))
        self.private_key = RSA.importKey(base64.b64decode(self.config['private_key']))


    def poll(self):
        reqs = {}
        try:
            req = requests.get('%s/requests' % self.config['frontend']['address'])

            if req.status_code == 200:
                result_raw = req.content.decode('utf-8')
                reqs = json.loads(result_raw)
        except Exception as ex:
            self.log.info('Failed to retrieve requests: %s' % ex)


        for req in reqs:
            try:
                unwrapped_request = self.unwrap_request(req)
            except Exception as ex:
                self.log.error('Failed to unwrap request %s with error %s' % (req, ex))

            if type(unwrapped_request) is dict:
                if 'type' in unwrapped_request and 'id' in unwrapped_request and 'request_content' in unwrapped_request:
                    id = unwrapped_request['id']
                    content = unwrapped_request['request_content']
                    request_type = unwrapped_request['type']

                    self.log.info('Request Type: %s,  ID: %s, Content: %s' % (request_type, id, content))

                    if request_type == 'code':
                        if 'username' in content:
                            username = content['username']

                            self.send_code(username=username, id=id)

                    if request_type == 'reset':
                        try:
                            self.reset_password(unwrapped_request)
                        except Exception as ex:
                            self.log.error('Method=poll, Message=Failed reset password, Input=%s, Exception=%s',
                                           (unwrapped_request, ex))
                            break

    def unwrap_request(self, message):
        secret_key_encrypted = base64.urlsafe_b64decode(message.split('.')[0])
        payload_encrypted = base64.urlsafe_b64decode(message.split('.')[1])

        public_cipher = PKCS1_OAEP.new(self.private_key)
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

    def send_code(self, username, id):
        self.log.info('Method=send_code, Username=%s, ID=%s' % (username, id))

        q = search_object.search_object()
        users = None

        try:
            self.log.info('Searching for user, Username=%s, DN=%s, FQDN=%s' % (username, self.domain_dn, self.domain_fqdn))
            users = q.search(username, self.domain_dn, self.domain_fqdn)
        except Exception as ex:
            self.log.error('Method=send_code, Message=Error searching for user,username=%s' % username, ex)
            self.log.exception(ex)

        if len(users) == 0:
            self.log.info('Method=send_code, Message=User could not be found in the directory, Username=%s' % username)
            requests.post('%s/coderesponse/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'User account could not be found'}))
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
                requests.post('%s/coderesponse/%s/OK' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'OK', 'code_hash': code_hash}))
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
        if 'id' in reset_request \
                and 'request_content' in reset_request \
                and 'username' in reset_request['request_content'] \
                and 'evidence' in reset_request['request_content'] \
                and 'password' in reset_request['request_content']:

            id = reset_request['id']
            username = reset_request['request_content']['username']
            password = reset_request['request_content']['password']
            evidence_raw = reset_request['request_content']['evidence']

            evidence = self.unwrap_request(evidence_raw)

            verified = False

            if 'code_hash' in evidence:
                code = evidence['code']
                code_hash = evidence['code_hash']

                verified = self.check_code(id, username, code, code_hash)

                if not verified:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps({'status': 'Failed', 'message': 'The reset code supplied was incorrect'}))
            elif 'ticket' in evidence:

                ticket = evidence['ticket']

                verified = self.verify_ticket(username, ticket)

                if not verified:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps({'status': 'Failed', 'message': 'There was a problem validating your Smartcard'}))

            if verified:
                self.reset_ad_password(username, password)
                requests.post('%s/resetresponse/%s/OK' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'OK'}))
        else:
            raise(Exception())

    def check_code(self, id, username, code, code_hash):
        self.log.info('Method=reset_request, Username=%s, Code=%s, CodeHash=%s, ID=%s' % (
            username,
            code,
            code_hash,
            id))

        expected_hash = self.generate_code_hash(username, code, id)

        if expected_hash == code_hash:
            return True

        return False

    def verify_ticket(self, username, ticket):
        request_body = self.session_service_template.replace('{{ ticket }}', ticket)

        try:
            response = requests.post(self.auth_service_validate_ticket_uri, data=request_body)
        except Exception as ex:
            self.log.exception(ex)
            self.log.error('Failed to request authvalidate')
            return False

        response_body = response.content.decode('utf-8')
        self.log.info('Message=Response received from Spine, Response=%s' % response_body)

        user_details = self.get_user(username)
        registered_uuid = user_details['pager']

        ticket_validated = '<Property name="SessionHandle" value="shandle:%s"></Property>' % ticket in response_body
        username_validated = '<Property name="UserId" value="%s">' % registered_uuid in response_body

        return ticket_validated and username_validated

    def get_user(self, username):
        q = search_object.search_object()
        users = None

        try:
            self.log.info('Searching for user, Username=%s, DN=%s, FQDN=%s' % (username, self.domain_dn, self.domain_fqdn))
            users = q.search(username, self.domain_dn, self.domain_fqdn)
        except Exception as ex:
            self.log.error('Method=send_code, Message=Error searching for user,username=%s' % username, ex)
            self.log.exception(ex)

        if len(users) == 1:
            return users[0]


    def reset_ad_password(self, username, new_password):
        self.log.info('Method=reset_ad_password, Username=%s' % username)

        try:
            q = search_object.search_object()
        except Exception as ex:
            self.log.error('Failed search for user in AD', ex)

        try:
            users = q.search(username, self.config['directory']['dn'], self.config['directory']['fqdn'])
        except Exception as ex:
            self.log.error('Failed search for user in AD', ex)

        if len(users) != 1:
            self.log.error('Could not find specified user in AD')
            raise Exception('Incorrect')

        user = users[0]

        try:
            pwd = set_password.set_password()
            pwd.set(user['distinguishedName'], new_password, self.config['directory']['dn'], self.config['directory']['fqdn'])
        except Exception as ex:
            self.log.error('Failed to set password in AD', ex)

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


# if __name__ == '__main__':
#     p = poller()
#
#     while True:
#         try:
#             p.poll()
#         except Exception as ex:
#             print(ex)
#
#         time.sleep(1)

