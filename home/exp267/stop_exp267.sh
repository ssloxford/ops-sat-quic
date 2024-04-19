#!/bin/sh

# put any code here to stop your experiment properly

kill `cat ~/exp_pid`
kill `cat ~/bridge_pid`
rm ~/exp_pid
