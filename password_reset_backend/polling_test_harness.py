import poller
import time
import logging

log = logging.getLogger('password_reset_backend')
log.setLevel(logging.DEBUG)
fh = logging.FileHandler('c:\\temp\\password_reset_backend.log')
fh.setLevel(logging.DEBUG)
log.addHandler(fh)
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
fh.setFormatter(formatter)

if __name__ == '__main__':
    p = poller.poller()

    while True:
        try:
            p.poll()
        except Exception as ex:
            print(ex)

        time.sleep(1)