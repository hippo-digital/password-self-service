from flask import Flask, request, render_template, redirect, url_for
import requests
import logging, os
import string
import random
from storage import storage
import json
import time
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import yaml


app = Flask(__name__)

#app.add_url_rule('/favicon.ico', redirect_to=url_for('static', filename='favicon.ico'))


@app.before_request
def log_request():
    transaction_id = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(6)])
    request.environ['transaction_id'] = transaction_id

    log.info('Method=BeforeRequest Transaction=%s RequestMethod=%s URL=%s ClientIP=%s Method=%s Proto=%s UserAgent=%s Arguments=%s Form=%s Data=%s'
             % (transaction_id,
                request.method,
                request.url,
                request.headers.environ['REMOTE_ADDR'] if 'REMOTE_ADDR' in request.headers.environ else 'NULL',
                request.headers.environ['REQUEST_METHOD'],
                request.headers.environ['SERVER_PROTOCOL'],
                request.headers.environ['HTTP_USER_AGENT'] if 'HTTP_USER_AGENT' in request.headers.environ else 'NULL',
                request.args,
                request.form,
                request.data.decode('utf-8')))


@app.route('/')
def start():
    return basic_render('start')

@app.route('/username')
def username():
    return basic_render('username')

@app.route('/reset_method', methods=['POST'])
def reset_method():
    username = request.form['username']

    if 'resetMethod' in request.form:
        if request.form['resetMethod'] == 'spineauth':
            return redirect('/spineauth', code=307)
        elif request.form['resetMethod'] == 'code':
            return redirect('/code', code=307)
        else:
            return 'Error'
    else:
        id = get_new_id()

        return fields_render('reset_method', {'username': username, 'id': id})
    # return basic_render('reset_method')

@app.route('/spineauth', methods=['POST'])
@app.route('/spineauth/<ticket>', methods=['POST'])
def spineauth(ticket=None):
    if ticket == None:
        return basic_render('spineauth')
    else:
        store_request(id, 'smartcard_validate', {'ticket': ticket})

        return ticket

@app.route('/code', methods=['POST'])
def code():
    username = request.form['username']
    id = request.form['id']

    if 'code' in request.form and 'code_hash' in request.form:
        evidence = package_and_encrypt({'code': request.form['code'], 'code_hash': request.form['code_hash']})
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
def password(evidence):
    username = request.form['username']
    id = request.form['id']

    return fields_render('password', {'username': username, 'evidence': evidence, 'id': id})

@app.route('/reset', methods=['POST'])
def reset():
    username = request.form['username']
    evidence = request.form['evidence']
    id = request.form['id']
    password = request.form['password']
    password_confirm = request.form['password-confirm']

    if password != password_confirm:
        return 'Passwords do not match'

    store_request(id, 'reset', {'username': username, 'evidence': evidence, 'password': password})

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

storage(db = redis_db)


