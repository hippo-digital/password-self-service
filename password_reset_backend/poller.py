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

from ad_connector import search_object, set_password
from twilio.rest import Client


def poll():
    reqs = {}
    try:
        req = requests.get('%s/requests' % config['frontend']['address'])

        if req.status_code == 200:
            result_raw = req.content.decode('utf-8')
            reqs = json.loads(result_raw)
    except Exception as ex:
        log.info(ex)

    if reqs != {} and reqs != None:
        if 'codes' in reqs:
            for code in reqs['codes']:
                try:
                    code_request = json.loads(code)
                except Exception as ex:
                    log.error('Method=poll, Message=Failed to parse JSON input, Input=%s, Exception=%s', (code, ex))
                    break

                try:
                    send_code(code_request['username'], code_request['id'])
                except Exception as ex:
                    log.error('Method=poll, Message=Failed to send code, Input=%s, Exception=%s', (code_request, ex))
                    break

        if 'resets' in reqs:
            for reset_raw in reqs['resets']:
                try:
                    reset = json.loads(reset_raw)
                except Exception as ex:
                    log.error('Method=poll, Message=Failed to parse JSON input, Input=%s, Exception=%s', (reset_raw, ex))
                    break

                try:
                    reset_password(reset)
                except Exception as ex:
                    log.error('Method=poll, Message=Failed reset password, Input=%s, Exception=%s', (reset, ex))
                    break

def send_code(username, id):
    q = search_object.search_object()
    users = None

    try:
        users = q.search(username, config['directory']['dn'], config['directory']['fqdn'])
    except Exception as ex:
        log.error('Method=send_code, Message=Error searching for user,username=%s' % username, ex)

    if len(users) == 0:
        log.info('Method=send_code, Message=User could not be found in the directory, Username=%s' % username)
        requests.post('%s/coderesponse/%s/Failed' % (config['frontend']['address'], id), data='User account could not be found')
    elif len(users) == 1 and 'mobile' in users[0]:
        user = users[0]
        mobile_number = user['mobile']

        code = "%s%s %03d %03d" % (random.choice(string.ascii_uppercase),
                                   random.choice(string.ascii_uppercase),
                                   random.randint(0, 999),
                                   random.randint(0, 999))
        raw_code = code.replace(' ', '')

        try:
            send_sms(mobile_number, code)
        except Exception as ex:
            log.error('Method=send_code, Message=Error sending code, username=%s, Code=%s' % (username, code), ex)

        try:
            code_hash = generate_code_hash(username, raw_code, id)
            requests.post('%s/coderesponse/%s/OK' % (config['frontend']['address'], id), data=code_hash)
        except Exception as ex:
            log.error('Method=send_code, Message=Error setting status on frontend, username=%s, Code=%s' % (username, code), ex)
    else:
        log.error('Method=send_code, Message=Too many objects returned, Data=%s' % users)

def send_sms(mobile_number, code):
    log.info('Method=send_sms, Message=Setting up API')

    twilio_sid = config['sms']['twilio_sid']
    twilio_authcode = config['sms']['twilio_authcode']
    from_text = config['sms']['organisation_shortname']
    body = config['sms']['message'] % code

    client = Client(twilio_sid, twilio_authcode)

    try:
        client.messages.create(
            to = mobile_number,
            from_ = from_text,
            body = body
        )
        log.info('Method=send_sms, Message=Successfully sent SMS, mobile_number=%s' % mobile_number)
    except Exception as ex:
        log.error('Method=send_sms, Message=Failed to send SMS, mobile_number=%s, twilio_sid=%s, twilio_authcode=%s, from_text=%s, body=%s' % (mobile_number, twilio_sid, twilio_authcode, from_text, body))
        # raise(ex)

def reset_password(reset_request):
    if 'username' in reset_request and 'code' in reset_request and 'code_hash' in reset_request and 'id' in reset_request and 'password' in reset_request:
        expected_hash = generate_code_hash(reset_request['username'], reset_request['code'], reset_request['id'])

        if expected_hash != reset_request['code_hash']:
            requests.post('%s/resetresponse/%s/Failed' % (config['frontend']['address'], reset_request['id']), data='The reset code supplied was incorrect')
        else:
            reset_ad_password(reset_request['username'], reset_request['password'])
            requests.post('%s/resetresponse/%s/OK' % (config['frontend']['address'], reset_request['id']), data='')
    else:
        raise(Exception())

def reset_ad_password(username, new_password):
    q = search_object.search_object()

    try:
        users = q.search(username, config['directory']['dn'], config['directory']['fqdn'])
    except Exception as ex:
        print(ex)

    if len(users) != 1:
        raise Exception('Incorrect')

    user = users[0]

    pwd = set_password.set_password()
    pwd.set(user['distinguishedName'], new_password, config['directory']['dn'], config['directory']['fqdn'])

def loadconfig(config_file_path):
    # SCRIPTPATH = os.path.dirname(os.path.realpath(__file__))
    with open(config_file_path) as cfgstream:
        config = yaml.load(cfgstream)
        return config

def generate_code_hash(username, code, id):
    to_hash = '%s.%s.%s.%s' % (username.upper(), code.upper(), id, salt)
    hash = hashlib.sha512(to_hash.encode('utf-8')).digest()
    b64_hash = base64.b64encode(hash).decode('utf-8')
    return b64_hash


log = logging.getLogger('password_reset_backend')
log.setLevel(logging.DEBUG)
fh = logging.FileHandler('password_reset_backend.log')
fh.setLevel(logging.DEBUG)
log.addHandler(fh)
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
fh.setFormatter(formatter)
log.info("Poller started")

config = loadconfig('config.yml')
salt = ''.join(random.choice(string.printable) for _ in range(100))

while True:
    time.sleep(1)
    poll()

