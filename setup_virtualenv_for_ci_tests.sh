#!/bin/bash

RES=0

START_PATH=${PWD}

cd $START_PATH/password_reset_frontend_receiver/
virtualenv .
source bin/activate
pip3 install flask redis pycrypto


cd $START_PATH/password_reset_frontend_ui/
virtualenv .
source bin/activate
pip3 install flask pycrypto redis requests


