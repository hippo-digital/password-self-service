from flask import Flask, request
import logging, os
import string
import random
from storage import storage
import json

app = Flask(__name__)
redis_db = 0


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

@app.route('/requests')
def requests():
    req = ''
    outstanding_requests = []

    while req != None:
        req = storage.lpop('requests')

        if req != None:
            outstanding_requests.append(req)

    return json.dumps(outstanding_requests)

@app.route('/checknameresponse/<id>/<status>', methods=['POST'])
def checknameresponse(id, status):
    body = request.data.decode('utf-8')
    return parse_and_store_response(id, status, body, 'check_name_response')

@app.route('/checkcoderesponse/<id>/<status>', methods=['POST'])
def checkcoderesponse(id, status):
    body = request.data.decode('utf-8')
    return parse_and_store_response(id, status, body, 'check_code_response')

@app.route('/coderesponse/<id>/<status>', methods=['POST'])
def coderesponse(id, status):
    body = request.data.decode('utf-8')
    return parse_and_store_response(id, status, body, 'code_responses')

@app.route('/resetresponse/<id>/<status>', methods=['POST'])
def resetresponse(id, status):
    body = request.data.decode('utf-8')
    return parse_and_store_response(id, status, body, 'reset_responses')

@app.route('/getuserdetails/<id>/<status>', methods=['POST'])
def getuserdetails(id, status):
    body = request.data.decode('utf-8')
    return parse_and_store_response(id, status, body, 'get_user_details_responses')

@app.route('/setuserdetails/<id>/<status>', methods=['POST'])
def setuserdetails(id, status):
    body = request.data.decode('utf-8')
    return parse_and_store_response(id, status, body, 'set_user_details_responses')

@app.route('/sendmessage', methods=['POST'])
def send_message():
    body = request.data.decode('utf-8')
    return 200

def parse_and_store_response(id, status, body, storage_key):
    if len(id) != 12:
        return 500

    if len(request.data) < 512:
        invalid_data_response = json.dumps({'status': 'Failed', 'message': 'An invalid response was received from the server'})

        try:
            body_data = json.loads(body)
        except Exception as ex:
            storage.hset(storage_key, id, invalid_data_response)
            return 500

        if 'status' in body_data and (body_data['status'] == 'OK' or body_data['status'] == 'Failed'):
            storage.hset(storage_key, id, body)
        else:
            storage.hset(storage_key, id, invalid_data_response)
            return 500

    return 'OK'

log = logging.getLogger('password_reset_frontend')

storage(db = redis_db)

