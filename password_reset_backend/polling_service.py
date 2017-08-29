import sys
import logging
import random
import string
from datetime import time

import win32serviceutil
import win32service
import win32event
import socket
import servicemanager

# easy_install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win-amd64-py3.4.exe

class polling_service(win32serviceutil.ServiceFramework):
    _svc_name_ = "pwdbackend"
    _svc_display_name_ = "Hippo Digital Password Reset Back-end"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.stop_requested = False

    def main(self):
        self.log.info(' ** Hello PyWin32 World ** ')

        while True:
            if self.stop_requested:
                break

            time.sleep(1)
            self.poll()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.log.info('Stopping service ...')
        self.stop_requested = True

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(poller)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(poller)

