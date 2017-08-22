from flask import Flask, request, render_template, redirect
import requests
import logging, os
import string
import random
from storage import storage
import json
import time
from Crypto import Random
from Crypto.PublicKey import RSA
import base64


app = Flask(__name__)

b64_public_key = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApaaE3Bu5pBEbFQ67rXzv
rwwya7VKfPyF6gxw4s/FSmuO2olqvmHpxOLvOvY5YsAjARM1oI0PZ4dv4OsTpHsC
Tw/v5tbcaYw4VZnAwmZKsna8NuP7yKgHOR1J2Iql07NLpIR436Imp9TvlFB2pWRp
S3cmg0rJcO7r3BkajrnAv9qppqnXw9ZCYS1J8UEoOUN42/8pKyRboTZ7PPCwb3eG
IOdi8hSH65zJhv+n+2zoLSwMLGt0w4v5Ami21tB5izyxl4MYY1hO93UT1UBXcceA
oNAVu8TWDBLKUhVk+cL3TMk8eYCM8LQCLMqveCdGEJ4J8rHop/lFVqA2OLItvb/z
jQIDAQAB"""
public_key = RSA.importKey(base64.b64decode(b64_public_key))
redis_db = 0
backend_wait_time_seconds = 30

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

        code_hash = None
        timeout_counter = 0

        while code_hash == None and timeout_counter < backend_wait_time_seconds:
            timeout_counter += 1
            time.sleep(1)
            response_raw = storage.hget('code_responses', id)

            if response_raw != None:
                code_hash = response_raw

                return fields_render('code', {'username': username, 'id': id, 'code_hash': code_hash})

        return fields_render('failed', fields={'message': 'Failed to get response from server'})

@app.route('/password/<evidence>', methods=['POST'])
def password(evidence):
    username = request.form['username']
    id = request.form['id']

    return fields_render('password', {'username': username, 'evidence': evidence, 'id': id})

@app.route('/reset', methods=['POST'])
def reset():
    username = request.form['username']
    code = request.form['code']
    code_hash = request.form['code_hash']
    id = request.form['id']
    password = request.form['password']
    password_confirm = request.form['password-confirm']

    if password != password_confirm:
        return 'Passwords do not match'

    store_request(id, 'reset', {'username': username, 'code': code, 'code_hash': code_hash, 'password': password})

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
    to_encrypt = json.dumps(dict)
    random_generator = Random.new().read
    encrypted_data = public_key.encrypt(to_encrypt.encode('utf-8'), random_generator)
    b64_encrypted_data = base64.b64encode(encrypted_data[0])

    return b64_encrypted_data.decode('utf-8')

log = logging.getLogger('password_reset_frontend')

storage(db = redis_db)


