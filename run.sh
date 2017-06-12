#!/bin/bash
ps -p `cat gunicorn.pid` &>  /dev/null
if [ $? = 1 ]
then
echo "Starting gunicorn."
./gunicorn_start.sh
else
echo "Gunicorn is Running."
fi
