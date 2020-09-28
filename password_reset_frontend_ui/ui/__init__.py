from flask import Flask, request, render_template, redirect, url_for
import requests
import logging, os
import string
import random
from storage import storage
import json
import time
import Crypto
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import yaml
from jinja2 import Template
import re
from pyasn1.type import univ, tag
from pyasn1.codec.ber import encoder, decoder

app = Flask(__name__)

auth_activate_template = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
<gpOBJECT>
<gpPARAM name="auth_method">3</gpPARAM>
<gpPARAM name="app_url">NHST</gpPARAM>
<gpPARAM name="log_session_id">{{ session_id }}</gpPARAM>
<gpPARAM name="device_id">{{ device_id }},ClientIP={{ ip }}</gpPARAM>
<gpPARAM name="service">ACTIVATION</gpPARAM>
</gpOBJECT>"""

auth_validate_template = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
<gpOBJECT>
<gpPARAM name="auth_method">3</gpPARAM>
<gpPARAM name="app_url">NHST</gpPARAM>
<gpPARAM name="log_session_id">{{ session_id }}</gpPARAM>
<gpPARAM name="device_id">{{ device_id }},ClientIP={{ ip }}</gpPARAM>
<gpPARAM name="service">AUTHENTICATION</gpPARAM>
<gpPARAM name="challenge">{{ challenge }}</gpPARAM>
<gpPARAM name="signature">{{ signature }}</gpPARAM>
<gpPARAM name="uid">{{ uid }}</gpPARAM>
<gpPARAM name="card_type">p11</gpPARAM>
<gpPARAM name="response" encoding="base64">{{ response }}</gpPARAM>
<gpPARAM name="mobility">0</gpPARAM>
</gpOBJECT>"""

smime_header = """MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/x-pkcs7-mime; name="smime.p7m"
Content-Transfer-Encoding: base64

"""

auth_logout_template = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
<gpOBJECT>
<gpPARAM name="service">LOGOUT</gpPARAM>
<gpPARAM name="sso_ticket">{{ ticket }}</gpPARAM>
<gpPARAM name="log_session_id">{{ session_id }}</gpPARAM>
<gpPARAM name="device_id">{{ device_id }},ClientIP={{ ip }}</gpPARAM>
<gpPARAM name="uid">{{ uid }}</gpPARAM>
</gpOBJECT>"""


def envelope(challenge, cert, signature):
    user_certificate = decoder.decode(cert)

    version_section = univ.Integer(1)

    digest_section = univ.Set()
    digest_section[0] = univ.Sequence()
    digest_section[0][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
    digest_section[0][1] = univ.Null()

    challenge_section = univ.Sequence()
    challenge_section[0] = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
    challenge_section[1] = univ.OctetString(value=base64.b64decode(challenge),
                                            tagSet=tag.TagSet((), tag.Tag(0, 0, 4), tag.Tag(128, 32, 0)))

    cert_section = univ.Sequence(tagSet=tag.TagSet((), tag.Tag(0, 32, 16), tag.Tag(128, 32, 0)))
    cert_section[0] = user_certificate[0][0]
    cert_section[1] = user_certificate[0][1]
    cert_section[2] = user_certificate[0][2]

    response_section = univ.Set()
    response_section[0] = univ.Sequence()
    response_section[0][0] = univ.Integer(1)
    response_section[0][1] = univ.Sequence()
    response_section[0][1][0] = user_certificate[0][0][3]
    response_section[0][1][1] = user_certificate[0][0][1]
    response_section[0][2] = univ.Sequence()
    response_section[0][2][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
    response_section[0][2][1] = univ.Null()
    response_section[0][3] = univ.Sequence()
    response_section[0][3][0] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
    response_section[0][3][1] = univ.Null()
    response_section[0][4] = univ.OctetString(signature)

    outer = univ.Sequence()
    outer[0] = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
    outer[1] = univ.Sequence(tagSet=tag.TagSet((), tag.Tag(0, 32, 16), tag.Tag(128, 32, 0)))
    outer[1][0] = version_section
    outer[1][1] = digest_section
    outer[1][2] = challenge_section
    outer[1][3] = cert_section
    outer[1][4] = response_section

    encoded = encoder.encode(outer)

    b64 = base64.b64encode(encoded).decode('utf-8')

    return encoded

def _extract_parameter(body, parameter_name):
    return re.findall('(?:%s\">)([a-z,A-Z,0-9,/+=]*)' % parameter_name, body)[0]

@app.before_request
def log_request():
    transaction_id = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(6)])
    request.environ['transaction_id'] = transaction_id

    log.info('Method=BeforeRequest Transaction=%s RequestMethod=%s URL=%s ClientIP=%s WebMethod=%s Proto=%s UserAgent=%s Arguments=%s Data=%s'
             % (transaction_id,
                request.method,
                request.url,
                request.headers.environ['REMOTE_ADDR'] if 'REMOTE_ADDR' in request.headers.environ else 'NULL',
                request.headers.environ['REQUEST_METHOD'],
                request.headers.environ['SERVER_PROTOCOL'],
                request.headers.environ['HTTP_USER_AGENT'] if 'HTTP_USER_AGENT' in request.headers.environ else 'NULL',
                request.args,
                request.data.decode('utf-8')))

def _parse_validate_response(auth_validate_response, session):
    session['roles'] = []

    session['sso_ticket'] = re.findall('(?:sso_ticket\">)([^<]*)', auth_validate_response)[0]
    session['cn'] = re.findall('(?:cn\">)([^<]*)', auth_validate_response)[0]
    session['sso_logout_url'] = re.findall('(?:sso_logout_url\">)([^<]*)', auth_validate_response)[0]

    #for l in auth_validate_response.split('\n'):
        #if 'name="nhsjobrole' in l:
            #session['roles'].append(_extract_role(l))

@app.route('/')
@app.route('/start')
def start():
    help_link = config['help_link']
    return fields_render('start', fields={'help_link': help_link})

@app.route('/username')
def username():
    return basic_render('username')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' not in request.form:
        return basic_render('register')
    elif 'id' in request.form \
            and 'username' in request.form \
            and 'dn' in request.form \
            and 'mobile' in request.form \
            and 'uid' in request.form \
            and 'evidence' in request.form:
        id = request.form['id']
        username = request.form['username']
        dn = request.form['dn']
        mobile = request.form['mobile']
        uid = request.form['uid']
        evidence = request.form['evidence']

        store_request(id, 'set_user_details', {'id': id,
                                               'username': username,
                                               'evidence': evidence,
                                               'dn': dn,
                                               'mobile': mobile,
                                               'uid': uid})

        res = await_and_get_backend_response(id, 'set_user_details_responses')

        if 'status' in res:
            if res['status'] == 'OK':
                return basic_render('register_complete')
            else:
                return fields_render('failed', fields={'message': res['message']})
        else:
            return fields_render('failed', fields={'message': 'No response from server, please contact a system administrator'})

    elif 'username' in request.form \
            and 'password' in request.form:
        id = get_new_id()
        username = request.form['username']
        password = request.form['password']

        evidence = package_and_encrypt({'password': password})

        store_request(id, 'get_user_details', {'username': username, 'evidence': evidence})

        res = await_and_get_backend_response(id, 'get_user_details_responses')

        if 'status' in res:
            if res['status'] == 'OK':
                return fields_render('update_details', fields={'id': id,
                                                               'username': username,
                                                               'evidence': evidence,
                                                               'dn': res['dn'],
                                                               'mobile': res['mobile'],
                                                               'uid': res['uid']})
            else:
                return fields_render('failed', fields={'message': res['message']})
        else:
            return fields_render('failed', fields={'message': 'No response from server, please contact a system administrator'})

@app.route('/reset_method', methods=['POST'])
def reset_method():
    username = request.form['username']

    if 'resetMethod' in request.form:
        if request.form['resetMethod'] == 'spineauth':
            return redirect('/spineactivate', code=307)
        elif request.form['resetMethod'] == 'code':
            return redirect('/code', code=307)
        else:
            return 'Error'
    else:
        id = get_new_id()

        return fields_render('reset_method', {'username': username, 'id': id})

@app.route('/spineauth', methods=['POST'])
def spineauth():
    if 'id' in request.form and 'username' in request.form:
        id = request.form['id']
        username = request.form['username']

        if 'ticket' in request.form:
            ticket = request.form['ticket']

            if ticket == 'null':
                return fields_render('failed', fields={'message': 'Could not reset your password at this time.'})

            evidence = package_and_encrypt({'ticket': ticket})
            return redirect('/password/%s' % (evidence), 307)

        return fields_render('spineauth', {'id': id, 'username': username})
    else:
        return 500

@app.route('/spineactivate', methods=['POST'])
def spineactivate():
    username = request.form['username']
    id = request.form['id']
    uid = request.form['uid']

    if 'signature' in request.form and 'cert' in request.form and 'uid' in request.form and 'activatesignature' in request.form and 'challenge' in request.form:
        return redirect('/spineverify', code=307)
    else:
        store_request(id, 'checknameexist', {'username': username, 'uid': uid})
        result = await_and_get_backend_response(id, 'check_name_response')

        if result['status'] == 'timeout':
            return fields_render('failed', fields={'message': 'Failed to get response from server in a timely manner.  Please contact IT support.'})
        elif result['status'] == 'invalid':
            return fields_render('failed', fields={'message': 'A problem occurred that requires further investigation.  Please contact IT support.'})
        elif result['status'] == 'Failed':
            if 'message' in result:
                return fields_render('failed', fields={'message': result['message']})
            else:
                return fields_render('failed', fields={'message': 'An unexplained error occurred.  Please contact IT support.'})
        elif result['status'] != 'OK':
            return fields_render('failed', fields={'message': 'An expected error occurred.  Please contact IT support.'})
        else: # OK
            global auth_activate_template
            auth_activate_fill = Template(auth_activate_template)
            auth_activate_body = auth_activate_fill.render(device_id='0npf1w2t',
                                                               ip='127.0.0.1',
                                                               session_id='AR3G7C6JO8')
#'http://jenkins-legacy.uksouth.cloudapp.azure.com:5000'  'http://127.0.0.1:5003'    'http://10.0.2.2:5003'   'http://51.141.94.100:5000'
            auth_activate = requests.post('%s/login/authactivate' % 'http://10.0.2.2:5003',
                                          verify=False,
                                          data=auth_activate_body,
                                          headers={'User-Agent': 'Mozilla/4.0(compatible;IE;GACv10. 0. 0. 1)'})

            body = auth_activate.content.decode('utf-8')

            challenge = _extract_parameter(body, 'challenge')
            activateSignature = _extract_parameter(body, 'signature')

            return fields_render('code', {'challenge': challenge, 'activatesignature': activateSignature})

@app.route('/spineverify', methods=['POST'])
def spineverify():
    signature = request.form['signature']
    uid = request.form['uid']
    cert = request.form['cert']
    activateSignature = request.form['activatesignature']
    challenge = request.form['challenge']

    #signature = base64.b64decode(signature)
    uid = uid.strip()
    cert = base64.b64decode(cert)
    challenge = base64.b64decode(challenge).decode('utf8')
    activateSignature = base64.b64decode(activateSignature).decode('utf8')

    #cms_envelope = base64.b64encode(envelope(challenge, cert, signature)).decode('utf-8')
    cms_envelope = signature

    global smime_header
    auth_validate_request_signature_raw = '%s%s' % (smime_header, cms_envelope)
    auth_validate_request_signature_encoded = base64.b64encode(auth_validate_request_signature_raw.encode('utf-8'))

    global auth_validate_template
    auth_validate_fill = Template(auth_validate_template)
    auth_validate_body = auth_validate_fill.render(uid=uid,
                                                       device_id='0npf1w2t',
                                                       ip='127.0.0.1',
                                                       session_id='AR3G7C6JO8',
                                                       challenge=challenge,
                                                       signature=activateSignature,
                                                       response=auth_validate_request_signature_encoded.decode('utf8'))
#'http://127.0.0.1:5003'  'http://jenkins-legacy.uksouth.cloudapp.azure.com:5000'   'http://10.0.2.2:5003'
    auth_validate_response = requests.post('%s/login/authvalidate' % 'http://10.0.2.2:5003',
                                           verify=False,
                                           headers={'User-Agent': 'Mozilla/4.0(compatible;IE;GACv10. 0. 0. 1)'},
                                           data=auth_validate_body)

    print (auth_validate_body)

    body = auth_validate_response.content.decode('utf-8')

    print (body)

    if ('Invalid input request' in body):
        return fields_render('failed', fields={'message': 'bad request'})
    elif ('Failed To Validate' in body):
        return fields_render('failed', fields={'message': 'validation failed'})
    elif 'sso_ticket' not in body or 'sso_logout_url' not in body:
        return fields_render('failed', fields={'message': 'validation failed'})
    else:
        sso_ticket = re.findall('(?:sso_ticket\">)([^<]*)', body)[0]
        sso_logout_url = re.findall('(?:sso_logout_url\">)([^<]*)', body)[0]
        return fields_render('code', {'sso_ticket': sso_ticket, 'sso_logout_url': sso_logout_url})

@app.route('/resetwithsmartcard', methods=['POST'])
def resetwithsmartcard():
    username = request.form['username']
    id = request.form['id']
    uid = request.form['uid']
    password = request.form['password']
    password_confirm = request.form['password']
    sso_ticket = request.form['sso_ticket']
    sso_logout_url = request.form['sso_logout_url']

    global auth_logout_template
    logout_body_template = Template(auth_logout_template)
    logout_body = logout_body_template.render(ticket=sso_ticket,
                                              uid=uid,
                                              device_id='0npf1w2t',
                                              ip='127.0.0.1',
                                              session_id='AR3G7C6JO8')

    auth_logout = requests.get(sso_logout_url,
                 verify=False,
                 headers={'User-Agent': 'Mozilla/4.0(compatible;IE;GACv10. 0. 0. 1)'},
                 data=logout_body)

    body = auth_logout.content.decode('utf-8')

    print (body)

    if password != password_confirm:
        return 'Passwords do not match'

    store_request(id, 'resetwithsmartcard', {'username': username, 'password': password})

    res = {}
    timeout_counter = 0

    while res == {} and timeout_counter < backend_wait_time_seconds:
        timeout_counter += 1
        time.sleep(1)
        response_raw = storage.hget('reset_responses', id)

        if response_raw != None:
            res = json.loads(response_raw)

    if 'status' in res:
        if res['status'] == 'OK':
            return basic_render('complete')
        else:
            return fields_render('failed', fields={'message': res['message']})
    else:
        return fields_render('failed', fields={'message': 'No response from server, please contact a system administrator'})

@app.route('/code', methods=['POST'])
def code():
    username = request.form['username']
    id = request.form['id']

    if 'code' in request.form and 'code_hash' in request.form:
        cleaned_code = request.form['code'].replace(' ', '').strip().upper()
        evidence = package_and_encrypt({'code': cleaned_code, 'code_hash': request.form['code_hash']})

        store_request(id, 'checkauthcode', {'username': username, 'code': cleaned_code, 'code_hash': request.form['code_hash']})
        result = await_and_get_backend_response(id, 'check_code_response')

        if result['status'] == 'timeout':
            return fields_render('failed', fields={'message': 'Failed to get response from server in a timely manner.  Please contact IT support.'})
        elif result['status'] == 'invalid':
            return fields_render('failed', fields={'message': 'A problem occurred that requires further investigation.  Please contact IT support.'})
        elif result['status'] == 'Failed':
            if 'message' in result:
                return fields_render('failed', fields={'message': result['message']})
            else:
                return fields_render('failed', fields={'message': 'An unexplained error occurred.  Please contact IT support.'})
        elif result['status'] != 'OK':
            return fields_render('failed', fields={'message': 'An expected error occurred.  Please contact IT support.'})
        else: # OK
            return redirect('/password/%s' % evidence, 307)
    else:
        store_request(id, 'code', {'username': username})

        result = await_and_get_backend_response(id, 'code_responses')

        if result['status'] == 'timeout':
            return fields_render('failed', fields={'message': 'Failed to get response from server in a timely manner.  Please contact IT support.'})
        elif result['status'] == 'invalid':
            return fields_render('failed', fields={'message': 'A problem occurred that requires further investigation.  Please contact IT support.'})
        elif result['status'] == 'Failed':
            if 'message' in result:
                return fields_render('failed', fields={'message': result['message']})
            else:
                return fields_render('failed', fields={'message': 'An unexplained error occurred.  Please contact IT support.'})
        elif result['status'] != 'OK':
            return fields_render('failed', fields={'message': 'An expected error occurred.  Please contact IT support.'})
        else: # OK
            return fields_render('code', {'username': username, 'id': id, 'code_hash': result['code_hash']})

def await_and_get_backend_response(id, storage_key):
    res = {}
    timeout_counter = 0

    while res == {} and timeout_counter < backend_wait_time_seconds:
        timeout_counter += 1
        time.sleep(1)
        response_raw = storage.hget(storage_key, id)

        if response_raw != None:
            try:
                res = json.loads(response_raw)
            except Exception as ex:
                return {'status': 'invalid'}

        if 'status' in res:
            return res

    return {'status': 'timeout'}

@app.route('/password/<evidence>', methods=['POST'])
def password(evidence, id=None, username=None):
    if id == None:
        id = request.form['id']
        username = request.form['username']

    return fields_render('password', {'username': username, 'evidence': evidence, 'id': id})

@app.route('/reset', methods=['POST'])
def reset():
    username = request.form['username']
    evidence = request.form['evidence']
    id = request.form['id']
    password = request.form['password']
    password_confirm = request.form['password-confirm']

    unlock_only = str(not ('unlock' in request.form and request.form['unlock'] == 'on')).lower()

    if password != password_confirm:
        return 'Passwords do not match'

    store_request(id, 'reset', {'username': username, 'evidence': evidence, 'password': password, 'unlock_only': unlock_only})

    res = {}
    timeout_counter = 0

    while res == {} and timeout_counter < backend_wait_time_seconds:
        timeout_counter += 1
        time.sleep(1)
        response_raw = storage.hget('reset_responses', id)

        if response_raw != None:
            res = json.loads(response_raw)

    if 'status' in res:
        if res['status'] == 'OK':
            return basic_render('complete')
        else:
            return fields_render('failed', fields={'message': res['message']})
    else:
        return fields_render('failed', fields={'message': 'No response from server, please contact a system administrator'})

def basic_render(step):
    body = render_template('%s.html' % step)
    return render_template('index.html', body=body)

def fields_render(step, fields):
    body = render_template('%s.html' % step, fields=fields)
    return render_template('index.html', body=body)

def get_new_id():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])

def store_request(id, type, data):
    to_encrypt = {'id': id, 'type': type, 'request_content': data}
    b64_encrypted_data = package_and_encrypt(to_encrypt)

    storage.rpush('requests', b64_encrypted_data)

def package_and_encrypt(dict):
    Crypto.Random.atfork()
    block_size = 32

    to_encrypt_string = json.dumps(dict)
    payload = _pad(to_encrypt_string, block_size).encode('utf-8')

    secret_key_raw = os.urandom(block_size)

    cipher = PKCS1_OAEP.new(public_key)
    secret_key_encrypted = cipher.encrypt(secret_key_raw)

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(secret_key_raw, AES.MODE_CFB, iv)
    payload_encrypted = iv + cipher.encrypt(payload)

    message = '%s.%s' % (base64.urlsafe_b64encode(secret_key_encrypted).decode('utf-8'), base64.urlsafe_b64encode(payload_encrypted).decode('utf-8'))

    return message

def _pad(s, block_size):
    return s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

def loadconfig(config_file_path):
    script_path = os.path.dirname(os.path.realpath(__file__))
    with open('%s/%s' % (script_path, config_file_path)) as cfgstream:
        cfg = yaml.load(cfgstream)
        return cfg

config = loadconfig('config.yml')

public_key = RSA.importKey(base64.b64decode(config['public_key']))
redis_db = 0
backend_wait_time_seconds = 30

log = logging.getLogger('password_reset_frontend')

storage(db = redis_db, address=os.getenv('REDIS_HOST', 'localhost'))


