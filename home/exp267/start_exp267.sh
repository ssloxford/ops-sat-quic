#!/bin/sh
exp_id="exp267"
bridge_id=$exp_id"_bridge"
NUM_PROCESSES=$(ps aux | tr -s " " | cut -d' ' -f5 | grep -i "$exp_id" | grep -vE 'grep|start|su' | wc -l)
timestamp_trigger=$(date +"%Y%m%d_%H%M")
logfile=$exp_id_$timestamp_trigger.log
bridgelogfile="bridge_"$logfile
HOME_DIR=$PWD

BRIDGE_RUNNING=$(ps aux | tr -s " " | cut -d' ' -f5 | grep -i "$bridge_id" | grep -vE 'grep|start|su' | wc -l)

if [ $BRIDGE_RUNNING -eq 0]
then
    echo "$$" > $HOME_DIR/bridge_pid
    echo "PID $(cat $HOME_DIR/bridge_pid)"
    echo "Starting bridge $bridge_id"
    $HOME_DIR/$bridge_id | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$bridgelogfile
    echo "$bridge_id ended - exiting now"
fi

if [ $NUM_PROCESSES -ge 1 ]
then
    # Exit app, because it is already running
    echo "$exp_id is already running..."
else
    # Run app
    echo "$$" > $HOME_DIR/exp_pid
    echo "PID $(cat $HOME_DIR/exp_pid)"
    echo "Non-NMF experiment"
    echo "Starting $exp_id"
    $HOME_DIR/$exp_id | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$logfile
    echo "$exp_id ended - exiting now"
fi

exit 0
