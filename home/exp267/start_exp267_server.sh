#!/bin/sh
exp_id="exp267"
bridge_id=$exp_id"_bridge"
server_id=$exp_id"_server"
NUM_PROCESSES=$(ps | tr -s " " | cut -d' ' -f5 | grep -iw "$server_id" | grep -vE 'grep|start|su' | wc -l)
BRIDGE_PID=$(ps | tr -s " " | grep -iw "$bridge_id" | cut -d' ' -f2)
BRIDGE_PROCESSES=$(echo $BRIDGE_PID | wc -w)
timestamp_trigger=$(date +"%Y%m%d_%H%M")
logfile=$exp_id_$timestamp_trigger.log
logpath=$HOME_DIR/toGround/$logfile
HOME_DIR=$PWD

if [ $BRIDGE_PROCESSES -ge 1 ]
then
    echo "$bridge_id is already running. No need to restart it."
else
    echo "Starting bridge $bridge_id"
    $HOME_DIR/$bridge_id -p11120 -t -u & 
    echo $BRIDGE_PID > $HOME_DIR/bridge_pid
    echo "Bridge PID $(cat $HOME_DIR/bridge_pid)"
fi

if [ $NUM_PROCESSES -ge 1 ]
then
    # Exit app, because it is already running
    echo "$server_id is already running..."
else
    # Run app
    echo "$$" > $HOME_DIR/exp_pid
    echo "PID $(cat $HOME_DIR/exp_pid)"
    echo "Non-NMF experiment"
    echo "Starting $exp_id"
    $HOME_DIR/$server_id -p11120 $args | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$logfile
    echo >> $HOME_DIR/toGround/$logfile # Add a new line between trials
        
    echo "$exp_id ended - exiting now"
fi

exit 0
