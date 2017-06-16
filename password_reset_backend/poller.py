import requests
import time
import json
import string
import random
from storage import storage
from ad_connector import search_object, set_password


def poll():
    reqs = {}
    req = requests.get('http://10.211.55.2:5000/requests')
    if req.status_code == 200:
        result_raw = req.content.decode('utf-8')
        reqs = json.loads(result_raw)

        if 'codes' in reqs:
            for code in reqs['codes']:
                send_code(code)

        if 'resets' in reqs:
            for reset in reqs['resets']:
                reset_password(json.loads(reset))

def send_code(username):
    code = "%s%s %03d %03d" % (random.choice(string.ascii_letters), random.choice(string.ascii_letters), random.randint(0, 999), random.randint(0, 999))
    code = code.upper()
    raw_code = code.replace(' ', '')
    mobile_number = storage.hgetasstring('mobilenumbers', username)
    storage.set('code_%s' % username, raw_code)
    storage.expire('code_%s' % username, 900)
    send_reset_sms(mobile_number, code)
    return "OK"

def send_reset_sms(mobile_number, code):
    from twilio.rest import Client
    # put your own credentials here
    ACCOUNT_SID = "ACf5e81dd572ad916b9dbd6d1883e755ae"
    AUTH_TOKEN = "b3ae4c2f616c9f9529aba41ce219cfd6"
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    try:
        client.messages.create(
            to=mobile_number,
            from_="RothICT",
            body="A reset code has been requested for your account.\n\nIf this was in error contact the service desk on 0113 235 3315.\n\nYour reset code is %s" % code
        )
    except Exception as ex:
        None

def reset_password(reset_request):
    if 'username' in reset_request and 'code' in reset_request and 'id' in reset_request and 'password' in reset_request:

        code = storage.get('code_%s' % reset_request['username'])
        sanitised_code = reset_request['code'].replace(' ', '').upper()

        if code != sanitised_code:
            requests.post('http://10.211.55.2:5000/resetresponse/%s/Failed' % reset_request['id'], data='The reset code supplied was incorrect')
        else:
            reset_ad_password(reset_request['username'], reset_request['password'])
            requests.post('http://10.211.55.2:5000/resetresponse/%s/OK' % reset_request['id'], data='')

def reset_ad_password(username, new_password):
    q = search_object.search_object()

    try:
        users = q.search(username, 'CN=Users,DC=hd,DC=local', 'hd-dc-01.hd.local')
    except Exception as ex:
        print(ex)

    if len(users) != 1:
        raise Exception('Incorrect')

    user = users[0]

    pwd = set_password.set_password()
    pwd.set(user, new_password, 'CN=Users,DC=hd,DC=local', 'hd-dc-01.hd.local')

storage('127.0.0.1', 6379, 2)

while True:
    time.sleep(1)
    poll()

