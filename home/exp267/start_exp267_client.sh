#!/bin/sh
exp_id="exp267"
bridge_id=$exp_id"_bridge"
client_id=$exp_id"_client"
NUM_PROCESSES=$(ps | tr -s " " | cut -d' ' -f5 | grep -iw "$client_id" | grep -vE 'grep|start|su' | wc -l)
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
    $HOME_DIR/$bridge_id -p11120 -t & 
    echo $BRIDGE_PID > $HOME_DIR/bridge_pid
    echo "Bridge PID $(cat $HOME_DIR/bridge_pid)"
fi

if [ $NUM_PROCESSES -ge 1 ]
then
    # Exit app, because it is already running
    echo "$client_id is already running..."
else
    # Run app
    echo "$$" > $HOME_DIR/exp_pid
    echo "PID $(cat $HOME_DIR/exp_pid)"
    echo "Non-NMF experiment"
    echo "Starting $exp_id"
    for sc in 1 2 4 8
    do
        echo "Streams: $sc" >> $HOME_DIR/toGround/$logfile
        for ((kb = 1; kb <= 1024;kb *= 2));
        do
            # Allocated how many bytes per stream and builds a string with the arguments
            let "bytes=$kb * 1024 / $sc"
            args=""
            for ((i = 0; i < sc; i++)); do 
                args="$args -s$bytes"
            done
            echo "Running experiment with arguments: $args."
            echo "Streams: $sc; Data: $kb KB" >> $HOME_DIR/toGround/$logfile
            $HOME_DIR/$client_id -p11120 -t $args | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$logfile
            echo >> $HOME_DIR/toGround/$logfile # Add a new line between trials
        done
    done
    echo "$exp_id ended - exiting now"
fi

exit 0
