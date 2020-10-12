#!/bin/bash

export DOCKER_HOST=$DOCKER_HOST

RES=0
docker-compose build &>/dev/null


docker run pss-rec -m unittest receiver/tests_receiver.py
RES=$(( $? + $RES ))
echo $RES


docker run pss-ui -m unittest ui/tests_ui.py
RES=$(( $? + $RES ))
echo $RES


docker run pss-backend -m unittest tests_poller.py
RES=$(( $? + $RES ))
echo $RES


exit $RES


