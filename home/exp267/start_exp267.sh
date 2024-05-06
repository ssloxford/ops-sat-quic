#!/bin/sh
exp_id="arm_exp267"
bridge_id=$exp_id"_bridge"
client_id=$exp_id"_client"
NUM_PROCESSES=$(ps u | tr -s " " | grep -iw "$client_id" | grep -vE 'grep|start|su' | wc -l)
BRIDGE_PROCESSES=$(ps u | tr -s " " | grep -iw "$bridge_id" | grep -vE 'grep|start|su' | wc -l)
timestamp_trigger=$(date +"%Y%m%d_%H%M%S")
logfile=$client_id-$timestamp_trigger.log
logpath=$HOME_DIR/toGround/$logfile
HOME_DIR=$PWD

echo "Starting at $(date +"%H:%M:%S")"

if [ $BRIDGE_PROCESSES -ge 1 ]
then
    echo "$bridge_id is already running. No need to restart it."
else
    echo "Starting bridge $bridge_id"
    $HOME_DIR/bin/$bridge_id -p11120 -t -q9999 &
    BRIDGE_PID=$(ps u | tr -s " " | grep -iw "$bridge_id" | grep -vE 'grep|start|su' | cut -d' ' -f2)
    echo "Bridge PID $BRIDGE_PID"
fi

if [ $NUM_PROCESSES -ge 1 ]
then
    # Exit app, because it is already running
    echo "$client_id is already running..."
else
    # Run app
    echo "PID $$"
    echo "Non-NMF experiment"
    echo "Starting $client_id"
    # Run with total payload sizes from 32kb to 512kb
    kb=32
    while [ "$kb" -le 512 ];
    do
        # Run for 1 and 4 streamas
        for sc in 1 4
        do
            echo "Streams: $sc" >> $HOME_DIR/toGround/$logfile
            if [ $sc -eq 4 ]
            then
                cc_algos="c b"
            else
                cc_algos="c"
            fi
            for cc in $cc_algos
            do
                # Calculates bytes per stream
                let "bytes=$kb * 1024 / $sc"
                args="-t -t -p11120 -c$cc"
                # Generate the arguments string with the payload distributed evenly across the streams
                i=1
                while [ "$i" -le "$sc" ]; do
                    args="$args -s$bytes"
                    i=$(( i + 1 ))
                done
                echo "Running experiment with arguments: $args."
                echo "Streams: $sc; Data: $kb KB; Congestion control: $cc" >> $HOME_DIR/toGround/$logfile
                $HOME_DIR/bin/$client_id $args | awk '{print strftime("[%d-%m-%Y %H:%M:%S.%f]"), $0}' >> $HOME_DIR/toGround/$logfile
                # Add a new line between trials
                echo >> $HOME_DIR/toGround/$logfile
            done
        done
        kb=$(( kb * 2 ))
    done
    echo "$client_id ended - exiting now"
fi

echo "Ending at $(date +"%H:%M:%S")"

exit 0
