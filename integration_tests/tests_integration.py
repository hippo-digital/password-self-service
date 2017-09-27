import unittest
import requests
import json
import re
import dateutil.parser
from datetime import datetime, timedelta
from dateutil import tz
import time

class tests(unittest.TestCase):
    def setUp(self):
        self.frontend_address = 'http://127.0.0.1:5001'

    def get_code(self):
        sms_uri = 'https://rest.textmagic.com/api/v2/replies?limit=1'
        reset_method_uri = '%s/reset_method' % self.frontend_address
        code_uri = '%s/code' % self.frontend_address
        username = 'test_user_1'

        code_requested = datetime.now(tz=tz.tzutc())
        message_timestamp = code_requested

        reset_method_response = requests.post(reset_method_uri, data={'username': username, 'reset_method': 'code'}, verify=False)
        reset_method_body = reset_method_response.content.decode('utf-8')

        id_field_definition = re.search('(<input name=\"id\".*)', reset_method_body).groups(0)[0]
        id = re.findall('(?:value=\")([a-z,A-Z,0-9,/+=]*)', id_field_definition)[0]

        code_response = requests.post(code_uri, data={'username': username, 'id': id}, verify=False)
        code_body = code_response.content.decode('utf-8')

        code_hash_field_definition = re.search('(<input name=\"code_hash\".*)', code_body).groups(0)[0]
        code_hash = re.findall('(?:value=\")([a-z,A-Z,0-9,/+=]*)', code_hash_field_definition)[0]

        while (message_timestamp <= code_requested):
            messages_response = requests.get(sms_uri, headers={'X-TM-Username': 'brettjackson', 'X-TM-Key': 'WMHU5KTbqAUBYwTmYH0zvyyfOKSdMp'})
            messages_raw = messages_response.content.decode('utf-8')
            messages = json.loads(messages_raw)
            message = messages['resources'][0]
            message_text = message['text']
            message_timestamp_raw = message['messageTime']

            message_timestamp = dateutil.parser.parse(message_timestamp_raw)

            time.sleep(1)

        matches = re.findall('(?:Your reset code is )(.*)', message_text)

        if len(matches) == 1:
            code = matches[0]
            code = code.replace(' ', '')
            return {'code': code,
                    'code_hash': code_hash,
                    'id': id,
                    'username': username}
        else:
            return None

    def get_password_page(self, code_details):
        code_uri = '%s/code' % self.frontend_address

        password_response = requests.post(code_uri, data=code_details)
        password_body = password_response.content.decode('utf-8')

        return {'body': password_body, 'form_fields': {}}

    def reset_password(self, password, username=None):
        form_fields = self.get_code()

        password_details = self.get_password_page(form_fields)
        password_body = password_details['body']

        evidence_field_definition = re.search('(<input name=\"evidence\".*)', password_body).groups(0)[0]
        form_fields['evidence'] = re.findall('(?:value=\")([^"]*)', evidence_field_definition)[0]

        reset_uri = '%s/reset' % self.frontend_address

        form_fields['password'] = password
        form_fields['password-confirm'] = form_fields['password']

        if username != None:
            form_fields['username'] = username

        reset_response = requests.post(reset_uri, data=form_fields, verify=False)

        return reset_response.content.decode('utf-8')

    def test_whenValidUsernameIsSubmitted_aResetCodeIsSentViaSMS(self):
        code_details = self.get_code()
        code = code_details['code']

        if code == None:
            self.fail('No codes or more than one code found in text message')
        else:
            self.assertTrue(True, 'Code successfully received')

    def test_whenValidUsernameAndCodeIsSubmitted_theResetPasswordScreenIsPresented(self):
        code_details = self.get_code()

        password_details = self.get_password_page(code_details)
        password_body = password_details['body']

        self.assertIn('<input name="password"', password_body)
        self.assertIn('<input name="password-confirm"', password_body)

    def test_whenFlowCompletedWithResetViaSMS_successfullySetsNewPasswordOnADAccount(self):
        reset_response = self.reset_password('Wibble123!')

        self.assertIn('You can now log in using the password you set.', reset_response, 'Expected successful response from reset call not received.')

    def test_whenPasswordChangeSubmittedWithWeakPassword_complexityErrorMessageReturned(self):
        reset_response = self.reset_password('weak')

        self.assertIn('Password does not meet complexity requirements', reset_response, 'Expected failure response from reset call not received.')

    def test_whenPasswordChangeSubmittedWithInvalidUser_userInvalidErrorMessageReturned(self):
        reset_response = self.reset_password('Wibble123!', username='does_not_exist')

        self.assertIn('The user does not exist in the directory', reset_response, 'Expected failure response from reset call not received.')


    def test_get_platform(self):
        import sys
        x = sys.platform

        None


