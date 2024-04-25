#!/bin/sh
HOME_DIR=$PWD
# put any code here to stop your experiment properly

kill `cat $HOME_DIR/exp_pid`
kill `cat $HOME_DIR/bridge_pid`
rm $HOME_DIR/exp_pid
rm $HOME_DIR/bridge_pid
