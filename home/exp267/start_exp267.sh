#!/bin/sh
exp_id="arm_exp267"
bridge_id=$exp_id"_bridge"
client_id=$exp_id"_client"
NUM_PROCESSES=$(ps | tr -s " " | cut -d' ' -f5 | grep -iw "$client_id" | grep -vE 'grep|start|su' | wc -l)
BRIDGE_PID=$(ps | tr -s " " | grep -iw "$bridge_id" | cut -d' ' -f2)
BRIDGE_PROCESSES=$(echo $BRIDGE_PID | wc -w)
timestamp_trigger=$(date +"%Y%m%d_%H%M%S")
logfile=$exp_id_$timestamp_trigger.log
logpath=$HOME_DIR/toGround/$logfile
HOME_DIR=$PWD

echo "Starting at $(date +"%H:%M:%S")"

if [ $BRIDGE_PROCESSES -ge 1 ]
then
    echo "$bridge_id is already running. No need to restart it."
else
    echo "Starting bridge $bridge_id"
    $HOME_DIR/bin/$bridge_id -p11120 -t & 
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
    # Run for 1, 2, 4, and 8 streams
    for ((sc = 1; sc <= 8; sc *= 2));
    do
        # Test the congestion control algos on 
        if [ $sc -eq 8 ]
        then
            cc_algos="c b r"
        else
            cc_algos="c"
        fi
        for cc in $cc_algos
        do
            echo "Streams: $sc" >> $HOME_DIR/toGround/$logfile
            # Run with total payload sizes from 8KB to 8MB
            for ((kb = 8; kb <= 8*1024; kb *= 2));
            do
                # Calculates bytes per stream
                let "bytes=$kb * 1024 / $sc"
                args="-t -p11120 -c$cc"
                # Generate the arguments string with the payload distributed evenly across the streams
                for ((i = 0; i < sc; i++)); do 
                    args="$args -s$bytes"
                done
                if [ $sc -eq 1 ]
                then
                    # Also measure inflight time when running single stream
                    args="-t $args"
                fi
                echo "Running experiment with arguments: $args."
                echo "Streams: $sc; Data: $kb KB; Congestion control: $cc" >> $HOME_DIR/toGround/$logfile
                $HOME_DIR/bin/$client_id $args | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$logfile
                # Add a new line between trials
                echo >> $HOME_DIR/toGround/$logfile
            done
        done
    done
    echo "$exp_id ended - exiting now"
fi

echo "Ending at $(date +"%H:%M:%S")"

exit 0
