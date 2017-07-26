from flask import Flask, request, render_template
import requests
import logging, os
import string
import random
from storage import storage
import json
import time


app = Flask(__name__)


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

@app.route('/code', methods=['POST'])
def code():
    username=request.form['username']

    id = get_new_id()
    storage.rpush('code_requests', json.dumps({'username': username, 'id': id}))


    code = None
    timeout_counter = 0

    while code == None and timeout_counter < 30:
        timeout_counter += 1
        time.sleep(1)
        response_raw = storage.hget('code_responses', id)

        if response_raw != None:
            code = response_raw

            return fields_render('code', {'username': username, 'id': id, 'code_hash': code})


    return fields_render('failed', fields={'message': 'Failed to get response from server'})

@app.route('/password', methods=['POST'])
def password():
    username = request.form['username']
    code = request.form['code']
    code_hash = request.form['code_hash']
    id = request.form['id']

    return fields_render('password', {'username': username, 'code': code, 'code_hash': code_hash, 'id': id})

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


    storage.rpush('reset_requests', json.dumps({'id': id, 'username': username, 'code': code, 'code_hash': code_hash, 'password': password}))

    res = {}
    timeout_counter = 0

    while res == {} and timeout_counter < 30:
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

log = logging.getLogger('password_reset_frontend')

storage()


