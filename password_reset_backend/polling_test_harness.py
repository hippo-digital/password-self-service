import poller
import time
import logging
import os

log = logging.getLogger('password_reset_backend')
log.setLevel(logging.DEBUG)

if os.getenv('LOG_STDOUT', 'false').lower().strip() == 'true':
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    log.addHandler(ch)
else:
    fh = logging.FileHandler('c:\\temp\\password_reset_backend.log')
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    fh.setFormatter(formatter)
    log.addHandler(fh)

if __name__ == '__main__':
    p = poller.poller()

    while True:
        try:
            p.poll()
        except Exception as ex:
            print(ex)

        time.sleep(1)
