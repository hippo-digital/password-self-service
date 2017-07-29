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
        self.frontend_address = 'http://127.0.0.1:5000'

    def get_code(self):
        sms_uri = 'https://rest.textmagic.com/api/v2/replies?limit=1'
        code_uri = '%s/code' % self.frontend_address

        code_requested = datetime.now(tz=tz.tzutc())
        message_timestamp = code_requested

        response = requests.post(code_uri, data={'username': 'aaa'})
        body = response.content.decode('utf-8')

        id_field_definition = re.search('(<input name=\"id\".*)', body).groups(0)[0]
        code_hash_field_definition = re.search('(<input name=\"code_hash\".*)', body).groups(0)[0]

        id = re.findall('(?:value=\")([a-z,A-Z,0-9,/+=]*)', id_field_definition)[0]
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
                    'id': id}
        else:
            return None

    def reset_password(self, code, code_hash, id):
        reset_uri = '%s/reset' % self.frontend_address

        data = {'username': 'aaa',
                'code': code,
                'code_hash': code_hash,
                'id': id,
                'username': 'aaa',
                'password': 'Wibble123!',
                'password-confirm': 'Wibble123!'}

        reset_response = requests.post(reset_uri, data=data)

        return 'You can now log in using the password you set.' in reset_response.content.decode('utf-8')

    def test_whenUsernameIsSubmitted_aResettCodeIsSentViaSMS(self):
        code = self.get_code()['code']

        if code == None:
            self.fail('No codes or more than one code found in text message')
        else:
            self.assertTrue(True, 'Code successfully received')

    def test_whenFlowCompletedWithResetViaSMS_successfullySetsNewPasswordOnADAccount(self):
        code_response = self.get_code()

        reset_response = self.reset_password(code_response['code'],
                                             code_response['code_hash'],
                                             code_response['id'])

        self.assertTrue(reset_response, 'Expected successful response from reset call not received.')

        None

