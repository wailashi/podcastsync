#!/bin/bash
PORT=40024
NAME="podcastsync"
PIDFILE="gunicorn.pid"

echo "Starting PodcastSync"

source venv/bin/activate

exec gunicorn gposerver:app -b 127.0.0.1:$PORT \
	--name podcastsync \
	--pid $PIDFILE
