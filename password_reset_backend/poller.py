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
import re

from ad_connector import search_object, set_password
from twilio.rest import Client
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE


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

        self.domain_dn_list = self.config['directory']['dn_list']
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
            self.log.exception('Method=poll, Message=Failed to retrieve requests')


        for req in reqs:
            try:
                unwrapped_request = self.unwrap_request(req)
            except Exception as ex:
                self.log.exception('Method=poll, Message=Failed to unwrap request, Request=%s' % req)

            if type(unwrapped_request) is dict:
                if 'type' in unwrapped_request and 'id' in unwrapped_request and 'request_content' in unwrapped_request:
                    id = unwrapped_request['id']
                    content = unwrapped_request['request_content']
                    request_type = unwrapped_request['type']

                    self.log.info('Method=poll, Message=Request received, RequestType=%s, ID=%s' % (request_type, id))

                    if request_type == 'code':
                        if 'username' in content:
                            username = content['username']

                            try:
                                self.send_code(username=username, id=id)
                            except Exception as ex:
                                self.log.exception('Method=poll, Message=Failed send code, Username=%s, RequestType=%s, ID=%s' % (username, request_type, id))
                                break

                    if request_type == 'checkauthcode':
                        if 'username' in content and 'code' in content and 'code_hash' in content:
                            username = content['username']
                            code = content['code']
                            code_hash = content['code_hash']

                        verified = self.check_code(id, username, code, code_hash)
                        if not verified:
                            requests.post('%s/checkcoderesponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed', 'message': 'The reset code supplied was incorrect'}))
                        else:
                            requests.post('%s/checkcoderesponse/%s/OK' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'OK'}))

                    if request_type == 'checknameexist':
                        if 'username' in content and 'uid' in content:
                            username = content['username']
                            uid = content['uid']

                        user = self.get_user(username)

                        if user is None:
                            self.log.info(
                                'Method=send_code, Message=User could not be found in the directory, Username=%s' % username)
                            requests.post('%s/checknameresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed', 'message': 'User account could not be found'}))
                        else:
                            user_id = user['pager'].split(":+", 1)[0]
                            user_id = user_id.split(":")[1]

                            if (uid == user_id):
                                requests.post('%s/checknameresponse/%s/OK' % (self.config['frontend']['address'], id),
                                              data=json.dumps({'status': 'OK'}))
                            else:
                                requests.post('%s/checknameresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                              data=json.dumps(
                                                  {'status': 'Failed', 'message': 'Username and Smartcard does not match.'}))

                    if request_type == 'resetwithsmartcard':
                        id = unwrapped_request['id']
                        username = content['username']
                        password = content['password']

                        try:
                            self.reset_ad_password(username, password)
                            requests.post('%s/resetresponse/%s/OK' % (self.config['frontend']['address'], id),
                                          data=json.dumps({'status': 'OK'}))
                        except ComplexityNotMetException:
                            requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps({'status': 'Failed',
                                                           'message': 'Password does not meet complexity requirements'}))
                        except ComplexityNotMetException:
                            requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed',
                                               'message': 'Password does not meet complexity requirements'}))
                        except UserDoesNotExistException:
                            requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed',
                                               'message': 'The user does not exist in the directory'}))
                        except CannotConnectToDirectoryException:
                            requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed', 'message': 'Could not connect to the directory'}))
                        except AccessIsDeniedException:
                            requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed',
                                               'message': 'The account could not be reset due to a permissions issue'}))
                        except Exception:
                            requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                          data=json.dumps(
                                              {'status': 'Failed',
                                               'message': 'The account could not be reset due to an undetermined issue'}))

                    if request_type == 'reset':
                        try:
                            self.reset_password(unwrapped_request)
                        except Exception as ex:
                            self.log.exception('Method=poll, Message=Failed reset password, RequestType=%s, ID=%s' % (request_type, id))
                            break

                    if request_type == 'get_user_details':
                        try:
                            self.get_user_details(unwrapped_request)
                        except Exception as ex:
                            self.log.exception('Method=poll, Message=Failed get user details, RequestType=%s, ID=%s' % (request_type, id))
                            break

                    if request_type == 'set_user_details':
                        try:
                            self.set_user_details(unwrapped_request)
                        except Exception as ex:
                            self.log.exception('Method=poll, Message=Failed get user details, RequestType=%s, ID=%s' % (request_type, id))
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
        self.log.info('Method=send_code, Message=Processing send_code request, Username=%s, ID=%s' % (username, id))

        q = search_object.search_object()
        users = None

        try:
            self.log.info('Method=send_code, Message=Searching for user, Username=%s, DN=%s' % (username, self.domain_dn_list))
            users = q.search(username, self.domain_dn_list)
        except Exception as ex:
            self.log.error('Method=send_code, Message=Error searching for user, Username=%s' % username)
            self.log.exception(ex)

        if len(users) == 0:
            self.log.info('Method=send_code, Message=User could not be found in the directory, Username=%s' % username)
            requests.post('%s/coderesponse/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'User account could not be found'}))
        elif len(users) == 1 and 'mobile' in users[0]:
            user = users[0]
            pager = user['pager'].split(':')
            mobile_number = None

            if len(pager) == 3 and pager[0] == 'pwd':
                mobile_number = pager[2]

            if mobile_number is None or len(mobile_number) < 11:
                raise Exception('No mobile phone number or invalid number for user: %s' % mobile_number)

            code = "%s%s %03d %03d" % (random.choice(string.ascii_uppercase),
                                       random.choice(string.ascii_uppercase),
                                       random.randint(0, 999),
                                       random.randint(0, 999))
            raw_code = code.replace(' ', '')

            try:
                self.send_sms(mobile_number, code)
            except Exception as ex:
                self.log.error('Method=send_code, Message=Error sending code, Username=%s, Code=%s' % (username, code))

            try:
                code_hash = self.generate_code_hash(username, raw_code, id)
                requests.post('%s/coderesponse/%s/OK' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'OK', 'code_hash': code_hash}))
            except Exception as ex:
                self.log.exception('Method=send_code, Message=Error setting status on frontend, Username=%s, Code=%s' % (username, code))
        else:
            self.log.error('Method=send_code, Message=Too many user objects returned on search, UserObjects=%s' % users)

    def send_sms(self, mobile_number, code):
        self.log.info('Method=send_sms, Message=Setting up API for send, MobileNumber=%s, Code=%s' % (mobile_number, code))

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
            self.log.info('Method=send_sms, Message=Successfully sent SMS, MobileNumber=%s' % mobile_number)
        except Exception as ex:
            self.log.exception('Method=send_sms, Message=Failed to send SMS, MobileNumber=%s, TwilioSID=%s, TwilioAuthcode=%s, FromText=%s, Body=%s' % (mobile_number, twilio_sid, twilio_authcode, from_text, body))

    def set_user_details(self, reset_request):
        if 'id' in reset_request \
                and 'request_content' in reset_request \
                and 'dn' in reset_request['request_content'] \
                and 'username' in reset_request['request_content'] \
                and 'mobile' in reset_request['request_content'] \
                and 'uid' in reset_request['request_content'] \
                and 'evidence' in reset_request['request_content']:
            id = reset_request['id']
            dn = reset_request['request_content']['dn']
            username = reset_request['request_content']['username']
            mobile = reset_request['request_content']['mobile']
            uid = reset_request['request_content']['uid']
            evidence_raw = reset_request['request_content']['evidence']

            evidence = self.unwrap_request(evidence_raw)
            password = evidence['password']

            server = Server(self.domain_fqdn, get_info=ALL, port=636, use_ssl=True)
            conn = Connection(server, user=dn, password=password)

            if not conn.bind():
                if conn.result['description'] == 'invalidCredentials':
                    self.log.warning('Method=set_user_details, Message=Incorrect password supplied, Request=%s' % reset_request)
                    requests.post('%s/setuserdetails/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'The supplied password was incorrect'}))
                else:
                    self.log.warning('Method=set_user_details, Message=Other error occurred, Result=%s, Request=%s' % (conn.result, reset_request))
                    requests.post('%s/setuserdetails/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'An unspecified error occurred'}))
                return

            if len(uid) != 0 and (len(uid) != 12 or not uid.isnumeric()):
                self.log.warning('Method=set_user_details, Message=UID field was invalid, Request=%s' % reset_request)
                requests.post('%s/setuserdetails/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'The UID field was invalid'}))

            if len(mobile) != 0 and (len(mobile) != 13 or not mobile.startswith('+447') or not mobile[1:].isnumeric()):
                self.log.warning('Method=set_user_details, Message=Mobile number field was invalid, Request=%s' % reset_request)
                requests.post('%s/setuserdetails/%s/Failed' % (self.config['frontend']['address'], id),
                              data=json.dumps({'status': 'Failed', 'message': 'The mobile number field was invalid'}))

            pager_field = 'pwd:%s:%s' % (uid, mobile)

            conn.modify(dn, {'pager': [(MODIFY_REPLACE, [pager_field])]})

            if conn.result['description'] == 'success':
                self.log.info('Method=set_user_details, Message=Successfully set attributes, Attributes=%s, Request=%s' % ({'mobile': mobile, 'pager': uid}, reset_request))
                requests.post('%s/setuserdetails/%s/OK' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'OK'}))
            else:
                self.log.warning('Method=set_user_details, Message=Other error occurred, Result=%s, Request=%s' % (conn.result, reset_request))
                requests.post('%s/setuserdetails/%s/Failed' % (self.config['frontend']['address'], id),
                              data=json.dumps({'status': 'Failed', 'message': 'An unspecified error occurred'}))

            conn.unbind()
            return
        else:
            self.log.error('Method=set_user_details, Message=Called with incomplete set of fields, Request=%s' % reset_request)
            return

    def get_user_details(self, reset_request):
        if 'id' in reset_request \
                and 'request_content' in reset_request \
                and 'username' in reset_request['request_content'] \
                and 'evidence' in reset_request['request_content']:

            id = reset_request['id']
            username = reset_request['request_content']['username']
            evidence_raw = reset_request['request_content']['evidence']

            evidence = self.unwrap_request(evidence_raw)

            password = evidence['password']

            user = self.get_user(username)

            if user == None:
                self.log.warning('Method=get_user_details, Message=User account could not be found, Request=%s' % reset_request)
                requests.post('%s/getuserdetails/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'The specified user account could not be found'}))
                return

            server = Server(self.domain_fqdn, get_info=ALL, port=636, use_ssl=True)
            conn = Connection(server, user=user['distinguishedName'], password=password)

            if not conn.bind():
                if conn.result['description'] == 'invalidCredentials':
                    self.log.warning('Method=get_user_details, Message=Incorrect password supplied, Request=%s' % reset_request)
                    requests.post('%s/getuserdetails/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'The supplied password was incorrect'}))
                else:
                    self.log.warning('Method=get_user_details, Message=Other error occurred, Result=%s, Request=%s' % (conn.result, reset_request))
                    requests.post('%s/getuserdetails/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'Failed', 'message': 'An unspecified error occurred'}))
                return

            search_result = conn.search(conn.user, '(objectClass=user)', attributes=['pager', 'mobile'])

            if search_result:
                attributes = {'status': 'OK', 'dn': user['distinguishedName'], 'mobile': '', 'uid': ''}
                if len(conn.entries[0].entry_attributes_as_dict['pager']) == 1:
                    pager_field = conn.entries[0].entry_attributes_as_dict['pager'][0]

                    extracted = re.search('(^pwd:([0-9]{12}|):(\+447[0-9]{9}|)$)', pager_field)

                    if extracted != None and len(extracted.groups()) == 3:
                        attributes['uid'] = extracted.group(2)
                        attributes['mobile'] = extracted.group(3)
                    elif len(pager_field) == 12 and pager_field.isnumeric():
                        attributes['uid'] = pager_field

                if attributes['mobile'] == '' and len(conn.entries[0].entry_attributes_as_dict['mobile']) == 1:
                    attributes['mobile'] = conn.entries[0].entry_attributes_as_dict['mobile'][0]

                self.log.info('Method=get_user_details, Message=Retrieved and returning attributes, Attributes=%s, Request=%s' % (attributes, reset_request))
                requests.post('%s/getuserdetails/%s/OK' % (self.config['frontend']['address'], id), data=json.dumps(attributes))
                conn.unbind()
        else:
            self.log.error('Method=get_user_details, Message=Called with incomplete set of fields, Request=%s' % reset_request)
            return

    def reset_password(self, reset_request):
        if 'id' in reset_request \
                and 'request_content' in reset_request \
                and 'username' in reset_request['request_content'] \
                and 'evidence' in reset_request['request_content'] \
                and 'password' in reset_request['request_content']:

            id = reset_request['id']
            username = reset_request['request_content']['username']
            evidence_raw = reset_request['request_content']['evidence']
            unlock_only = reset_request['request_content']['unlock_only'] == 'true'

            if unlock_only:
                password = None
            else:
                password = reset_request['request_content']['password']

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

                try:
                    verified = self.verify_ticket(username, ticket)
                except UserDoesNotExistException as ex:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps(
                                      {'status': 'Failed',
                                       'message': 'The user does not exist in the directory'}))
                    return
                except CannotConnectToSpineAuthenticationException as ex:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps(
                                      {'status': 'Failed',
                                       'message': 'Failed to connect to Spine authentication service'}))
                    return

                if not verified:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps({'status': 'Failed', 'message': 'There was a problem validating your Smartcard'}))

            if verified:
                try:
                    self.reset_ad_password(username, password)
                    requests.post('%s/resetresponse/%s/OK' % (self.config['frontend']['address'], id), data=json.dumps({'status': 'OK'}))
                except ComplexityNotMetException:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps({'status': 'Failed',
                                                   'message': 'Password does not meet complexity requirements'}))
                except ComplexityNotMetException:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps(
                                      {'status': 'Failed',
                                       'message': 'Password does not meet complexity requirements'}))
                except UserDoesNotExistException:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps(
                                      {'status': 'Failed',
                                       'message': 'The user does not exist in the directory'}))
                except CannotConnectToDirectoryException:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id),
                                  data=json.dumps(
                                      {'status': 'Failed', 'message': 'Could not connect to the directory'}))
                except AccessIsDeniedException:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps(
                        {'status': 'Failed', 'message': 'The account could not be reset due to a permissions issue'}))
                except Exception:
                    requests.post('%s/resetresponse/%s/Failed' % (self.config['frontend']['address'], id), data=json.dumps(
                        {'status': 'Failed', 'message': 'The account could not be reset due to an undetermined issue'}))
            else:
                raise(Exception())

    def check_code(self, id, username, code, code_hash):
        self.log.info('Method=check_code, Message=Checking Reset Code, Username=%s, Code=%s, CodeHash=%s, ID=%s' % (
            username,
            code,
            code_hash,
            id))

        cleaned_code = code.replace(' ', '').strip().upper()

        expected_hash = self.generate_code_hash(username, cleaned_code, id)

        if expected_hash == code_hash:
            return True

        return False

    def verify_ticket(self, username, ticket):
        request_body = self.session_service_template.replace('{{ ticket }}', ticket)

        try:
            response = requests.post(self.auth_service_validate_ticket_uri, data=request_body, verify=False)
        except Exception as ex:
            self.log.exception('Method=verify_ticket, Message=Failed to request authvalidate, Request=%s' % request_body)
            raise CannotConnectToSpineAuthenticationException()

        response_body = response.content.decode('utf-8')

        user_details = self.get_user(username)
        if user_details == None:
            self.log.warning('Method=verify_ticket, Message=Username not found in directory, Username=%s' % username)
            raise UserDoesNotExistException()

        registered_uuid = user_details['pager']

        ticket_validated = '<Property name="SessionHandle" value="shandle:%s"></Property>' % ticket in response_body
        username_validated = '<Property name="UserId" value="%s">' % registered_uuid in response_body

        if not ticket_validated:
            self.log.warning('Method=verify_ticket, Message=Ticket not validated for user, Username=%s, SpineResponse=%s' % (username, response_body))

        if not username_validated:
            self.log.warning('Method=verify_ticket, Message=Username not validated for user, Username=%s, RegisteredUID=%s, SpineResponse=%s' % (username, registered_uuid, response_body))

        return ticket_validated and username_validated

    def get_user(self, username):
        q = search_object.search_object()
        users = None

        try:
            self.log.info('Method=get_user, Message=Searching for user, Username=%s, DN=%s' % (username, self.domain_dn_list))
            users = q.search(username, self.domain_dn_list)
        except Exception as ex:
            self.log.exception('Method=get_user, Message=Error searching for user, Username=%s' % username)

        if len(users) == 1:
            return users[0]

        return None

    def reset_ad_password(self, username, new_password=None):
        self.log.info('Method=reset_ad_password, Message=Resetting password, Username=%s' % username)
        from pyad import pyadexceptions

        import pywintypes

        try:
            q = search_object.search_object()
        except Exception as ex:
            self.log.exception('Method=reset_ad_password, Message=Failed search for user in AD')

        try:
            users = q.search(username, self.domain_dn_list)
        except pywintypes.com_error as ex:
            if 'referral was returned' in ex.excepinfo[2]:
                raise(CannotConnectToDirectoryException)
            else:
                raise(ex)
        except Exception as ex:
            self.log.exception('Method=reset_ad_password, Message=Failed search for user in AD, Username=%s' % username)

        if len(users) != 1:
            self.log.error('Method=reset_ad_password, Message=Could not find specified user in AD, Users=%s' % users)
            raise(UserDoesNotExistException)

        user = users[0]

        try:
            pwd = set_password.set_password()
            pwd.set(user['distinguishedName'], user['distinguishedName'], self.config['directory']['fqdn'], password=new_password)
        except pyadexceptions.win32Exception as ex:
            if ex.error_info['error_code'] == '0x80070005':
                raise(AccessIsDeniedException)
            elif ex.error_info['error_code'] == '0x800708c5':
                raise (ComplexityNotMetException)
            else:
                raise(ex)
        except Exception as ex:
            self.log.exception('Method=reset_ad_password, Message=Failed to set password in AD, Username=%s')
            raise(ex)

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

class ComplexityNotMetException(Exception):
    None

class UserDoesNotExistException(Exception):
    None

class CannotConnectToDirectoryException(Exception):
    None

class AccessIsDeniedException(Exception):
    None

class CannotConnectToSpineAuthenticationException(Exception):
    None


