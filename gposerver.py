import logging
import sys
from logging.handlers import RotatingFileHandler
import enum
from flask import Flask, jsonify, Response, request, session, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import case
from sqlalchemy.sql.functions import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
import json
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'as393,d392.j#19#$'
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(255))
    devices = db.relationship('Device', backref='user', lazy='dynamic')

    def __init__(self, username, password):
        self.username = username
        self.password_hash = generate_password_hash(password)

    def __repr__(self):
        return '<User: {}>'.format(self.username)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, unique=True)
    caption = db.Column(db.String)
    device_type = db.Column(db.String(10))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, device_id, caption, device_type):
        self.device_id = device_id
        self.device_type = device_type
        self.caption = caption

    def __repl__(self):
        return '<Device: {}>'.format(self.device_id)


class SubscriptionAction(enum.Enum):
    subscribe = 'subscribe'
    unsubscribe = 'unsubscribe'


class SubscriptionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.Integer)
    podcast = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    action = db.Column(db.Enum(SubscriptionAction))

    def __init__(self, podcast, user_id, device_id, action):
        self.podcast = podcast
        self.action = action
        self.user_id = user_id
        self.device_id = device_id
        self.timestamp = int(time.time())

    def __repr__(self):
        return '<SubscriptionEvent: {} {}>'.format(self.action, self.podcast)


class EpisodeAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.Integer)
    podcast = db.Column(db.String)
    episode = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    upload_time = db.Column(db.Integer)
    action = db.Column(db.String)
    started = db.Column(db.Integer)
    position = db.Column(db.Integer)
    total = db.Column(db.Integer)

    def __init__(self, podcast, episode, user_id, device_id, action, timestamp, started=None, position=None, total=None):
        self.podcast = podcast
        self.episode = episode
        self.action = action
        self.user_id = user_id
        self.device_id = device_id
        self.timestamp = timestamp
        self.upload_time = int(time.time())
        if action == 'play':
            self.position = position
            if started and total:
                self.started = started
                self.total = total

    def __repr__(self):
        return '<EpisodeAction {} {}>'.format(self.episode, self.action)


def add_subscription_event(username, device_id, podcast, action):
    user = User.query.filter_by(username=username).first().id
    device = Device.query.filter_by(device_id=device_id).first().id
    db.session.add(SubscriptionEvent(podcast, user, device, action))
    db.session.commit()


def add_episode_action(username, device_id, podcast, episode, action, timestamp, started=None, position=None, total=None):
    user = User.query.filter_by(username=username).first().id
    device = Device.query.filter_by(device_id=device_id).first().id
    db.session.add(EpisodeAction(podcast, episode, user, device, action, timestamp, started, position, total))
    db.session.commit()


def get_subscriptions(username, device_id):
    events = SubscriptionEvent.query.filter(User.username == username,
                                            Device.device_id == device_id).all()
    return events

import pprint
@auth.verify_password
def verify_password(username, password):
    if session.get('logged_in'):
        return True
    if not username:
        return False
    password_hash = User.query.filter(User.username == username).first_or_404().password_hash
    if password_hash:
        if check_password_hash(password_hash, password):
            session['logged_in'] = True
            session['user'] = username
            return True
    return False


@app.route('/')
def frontpage():
	return 'gposerver', 200


@app.route('/api/2/auth/<string:username>/login.json', methods=['POST'])
@auth.login_required
def authenticate(username):
    if auth.username() != username:
        return '', 401
    session['logged_in'] = True
    session['user'] = username
    response = make_response('', 200)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Cache-Control'] = 'no-store, must-revalidate, no-cache, max-age=0'
    response.headers['Set-Cookie'] = 'sessionid=8xsr5iiwmms91l106x29f84gi2yiu0da; expires=Sat, 09-Jun-2018 23:03:39 GMT; HttpOnly; Max-Age=31535999; Path=/'
    response.headers['Set-Cookie'] = 'csrftoken=WY88pikZ8UtytSsmP338rdioJfN9WozJ; expires=Fri, 08-Jun-2018 23:03:40 GMT; Max-Age=31449600; secure; HttpOnly; Path=/'
    response.set_cookie('sessionid', value='testcookievalue', max_age=5000, httponly=True)
    return response


@app.route('/api/2/devices/<string:username>.json', methods=['GET'])
@auth.login_required
def list_devices(username):
    devices = Device.query.filter(User.username == username).all()
    response = [{'id': d.device_id,
                 'caption': d.caption,
                 'type': d.device_type,
                 'subscriptions': 0, }
                for d in devices]

    return jsonify(response), 200


@app.route('/api/2/devices/<string:username>/<string:device_id>.json', methods=['POST'])
@auth.login_required
def update_device_data(username, device_id):
    return '', 200


@app.route('/subscriptions/<string:username>/<string:device_id>.<string:response_format>', methods=['GET'])
@auth.login_required
def get_device_subscriptions(username, device_id, response_format):
    if response_format != 'json':
        return '', 400
    return '', 201


@app.route('/api/2/subscriptions/<string:username>/<string:device_id>.json', methods=['GET'])
@auth.login_required
def get_subscription_changes(username, device_id):
    since = request.args.get('since')
    podcasts = db.session.query(SubscriptionEvent.podcast,
                                func.sum(case([(SubscriptionEvent.action == 'subscribe', 1)], else_=0)),
                                func.sum(case([(SubscriptionEvent.action == 'unsubscribe', 1)], else_=0))) \
                               .select_from(SubscriptionEvent)\
                               .filter(SubscriptionEvent.timestamp >= int(since))\
                               .group_by(SubscriptionEvent.podcast).all()
    response = {'add': [], 'remove': []}
    for podcast, added, removed in podcasts:
        if added > removed:
            response['add'].append(podcast)
        if added < removed:
            response['remove'].append(podcast)
    response['timestamp'] = int(time.time())
    return jsonify(response), 200


@app.route('/api/2/subscriptions/<string:username>/<string:device_id>.json', methods=['POST'])
@auth.login_required
def upload_subscription_changes(username, device_id):
    payload = request.get_json(force=True)
    add = payload['add']
    remove = payload['remove']
    update_urls = [[url, url] for url in add]
    for podcast in add:
        if podcast:
            add_subscription_event(username, device_id, podcast, 'subscribe')
    for podcast in remove:
        if podcast:
            add_subscription_event(username, device_id, podcast, 'unsubscribe')
    timestamp = int(time.time())
    response = {'timestamp': timestamp, 'update_urls': update_urls}
    return jsonify(response), 200


@app.route('/api/2/episodes/<string:username>.json', methods=['GET'])
@auth.login_required
def get_episode_actions(username):
    podcast = request.args.get('podcast')
    device = request.args.get('device')
    since = request.args.get('since')
    aggregated = request.args.get('aggregated')

    query = EpisodeAction.query.filter(User.username == username)
    if podcast:
        query = query.filter_by(podcast=podcast)
    if device:
        query = query.filter_by(device=device)
    if since:
        query = query.filter(EpisodeAction.upload_time >= since)

    actions = [{
            'podcast': a.podcast,
            'episode': a.episode,
            'device': a.device_id,
            'action': a.action,
            'timestamp': a.timestamp,
            'started': a.started,
            'postition': a.position,
            'total': a.total}
            for a in query.all()]
    timestamp = int(time.time())
    return jsonify({'actions': actions, 'timestamp': timestamp}), 200


@app.route('/api/2/episodes/<string:username>.json', methods=['POST'])
@auth.login_required
def upload_episode_actions(username):
    payload = request.get_json(force=True)
    for c in payload:
        add_episode_action(username, c['device'], c['podcast'], c['episode'],
                c['action'], c.get('timestamp'), c.get('started'),
                c.get('position'), c.get('total'))
    timestamp = int(time.time())
    response = {'timestamp': timestamp, 'update_urls': []}
    return jsonify(response), 200


if __name__ == "__main__":
    logger = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
    logger.setLevel(logging.INFO)
    app.logger.addHandler(logger)
    app.run(port=40024)
