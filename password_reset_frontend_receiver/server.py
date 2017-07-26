from view import app
import logging

app.secret_key = 'Secret123!'
app.config['SESSION_TYPE'] = 'filesystem'

log = logging.getLogger('password_reset_frontend')
log.setLevel(logging.DEBUG)
fh = logging.FileHandler('password_reset_frontend.log')
fh.setLevel(logging.DEBUG)
log.addHandler(fh)
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
fh.setFormatter(formatter)
log.info("Server started")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5002, threaded=True)


