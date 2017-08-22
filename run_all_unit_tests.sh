#!/bin/bash

RES=0

START_PATH=${PWD}

cd $START_PATH/password_reset_frontend_receiver/
python3 -m unittest receiver/tests_receiver.py
RES=$(( $? + $RES ))
echo $RES

cd $START_PATH/password_reset_frontend_ui/
python3 -m unittest ui/tests_ui.py
RES=$(( $? + $RES ))
echo $RES


exit $RES


