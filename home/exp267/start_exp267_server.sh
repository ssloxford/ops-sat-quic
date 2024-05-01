#!/bin/sh
exp_id="arm_exp267"
bridge_id=$exp_id"_bridge"
server_id=$exp_id"_server"
NUM_PROCESSES=$(ps u | tr -s " " | grep -iw "$server_id" | grep -vE 'grep|start|su' | wc -l)
BRIDGE_PROCESSES=$(ps u | tr -s " " | grep -iw "$bridge_id" | grep -vE 'grep|start|su' | wc -l)
timestamp_trigger=$(date +"%Y%m%d_%H%M%S")
logfile=$server_id-$timestamp_trigger.log
logpath=$HOME_DIR/toGround/$logfile
HOME_DIR=$PWD

echo "Starting at $(date +"%H:%M:%S")"

# The bridge must be running in the server config, not the client config
if [ $BRIDGE_PROCESSES -ge 1 ]
then
    echo "$bridge_id is already running. No need to restart it."
else
    echo "Starting bridge $bridge_id"
    $HOME_DIR/bin/$bridge_id -p11120 -u &
    BRIDGE_PID=$(ps u | tr -s " " | grep -iw "$bridge_id" | grep -vE 'grep|start|su' | cut -d' ' -f2)
    echo "Bridge PID $BRIDGE_PID"
fi

if [ $NUM_PROCESSES -ge 1 ]
then
    # Exit app, because it is already running
    echo "$server_id is already running..."
else
    # Run app
    echo "PID $$" 
    echo "Non-NMF experiment"
    echo "Starting $server_id"
    $HOME_DIR/bin/$server_id -p11120 -t | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$logfile
    echo "$server_id ended - exiting now"
fi

echo "Ending at $(date +"%H:%M:%S")"

exit 0
