#!/bin/bash

RES=0

cd /var/lib/jenkins/shared-workspace/password_reset_frontend_receiver/
virtualenv .
source bin/activate
pip3 install flask redis pycrypto
python3 -m unittest receiver/tests_receiver.py
RES=$(( $? + $RES ))
echo $RES

cd /var/lib/jenkins/shared-workspace/password_reset_frontend_ui/
virtualenv .
source bin/activate
pip3 install flask pycrypto redis requests
python3 -m unittest ui/tests_ui.py
RES=$(( $? + $RES ))
echo $RES


exit $RES


