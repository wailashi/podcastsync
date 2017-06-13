#!/bin/bash
PORT=40024
NAME="podcastsync"
PIDFILE="gunicorn.pid"

echo "Starting PodcastSync"

source venv/bin/activate

exec gunicorn gposerver:app -b 0.0.0.0:$PORT \
	--name podcastsync \
	--workers=2 \
	--pid $PIDFILE \
	--log-leve=debug
