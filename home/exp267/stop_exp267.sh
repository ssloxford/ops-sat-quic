#!/bin/sh
HOME_DIR=$PWD

exp_id="arm_exp267"
bridge_id=$exp_id"_bridge"
client_id=$exp_id"_client"
server_id=$exp_id"_server"
# put any code here to stop your experiment properly

BRIDGE_PID=$(ps u | tr -s " " | grep -iw "$bridge_id" | grep -vE 'grep|start|su' | cut -d' ' -f2)
CLIENT_PID=$(ps u | tr -s " " | grep -iw "$client_id" | grep -vE 'grep|start|su' | cut -d' ' -f2)
SERVER_PID=$(ps u | tr -s " " | grep -iw "$server_id" | grep -vE 'grep|start|su' | cut -d' ' -f2)

BRIDGE_RUNNING=$(echo $BRIDGE_PID | wc -w)
CLIENT_RUNNING=$(echo $CLIENT_PID | wc -w)
SERVER_RUNNING=$(echo $SERVER_PID | wc -w)

if [ $BRIDGE_RUNNING -ge 1 ]
then
    kill $BRIDGE_PID
    echo Killed bridge
fi

if [ $CLIENT_RUNNING -ge 1 ]
then
    kill $CLIENT_PID
    echo Killed client
fi

if [ $SERVER_RUNNING -ge 1 ]
then
    kill $SERVER_PID
    echo Killed server
fi
