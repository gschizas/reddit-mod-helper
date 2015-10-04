import os
from uuid import uuid4
from collections import MutableMapping
from flask_sqlalchemy import SQLAlchemy
from flask.sessions import SessionInterface, SessionMixin
import ruamel.yaml as yaml

db = SQLAlchemy()


class Session(db.Model):
    __tablename__ = 'SESSION'

    id = db.Column('SESSION_ID', db.String(36), primary_key=True)
    key = db.Column('KEY', db.String(64), primary_key=True)
    value = db.Column('VALUE', db.UnicodeText)

    def __init__(self, sid, key):
        self.id = sid
        self.key = key

        # def __init__(self, id, key, value):
        #     self.__init__(id, key)
        #     self.value = value


class Submissions(db.Model):
    __tablename__ = 'SUBMISSIONS'

    id = db.Column('THING_ID', db.String(36), primary_key=True, unique=True)
    url = db.Column('URL', db.String(2048))
    title = db.Column('TITLE', db.String(1024))
    content = db.Column('CONTENT', db.UnicodeText())


class PostgresSession(MutableMapping, SessionMixin):
    # # These proxy classes are needed in order
    # # for this session implementation to work properly.
    # # That is because sometimes flask will chain method calls
    # # with session'setdefault' calls.
    # # Eg: session.setdefault('_flashes', []).append(1)
    # # With these proxies, the changes made by chained
    # # method calls will be persisted back to the sqlite
    # # database.
    # class CallableAttributeProxy(object):
    #     def __init__(self, session, key, obj, attr):
    #         self.session = session
    #         self.key = key
    #         self.obj = obj
    #         self.attr = attr
    #
    #     def __call__(self, *args, **kwargs):
    #         rv = self.attr(*args, **kwargs)
    #         self.session[self.key] = self.obj
    #         return rv
    #
    # class PersistedObjectProxy(object):
    #     def __init__(self, session, key, obj):
    #         self.session = session
    #         self.key = key
    #         self.obj = obj
    #
    #     def __getattr__(self, name):
    #         attr = getattr(self.obj, name)
    #         if callable(attr):
    #             return PostgresSession.CallableAttributeProxy(self.session, self.key, self.obj, attr)
    #         return attr

    def __init__(self, sid, *args, **kwargs):
        self.sid = sid
        self.modified = False

    def __getitem__(self, key):
        value_obj = Session.query.filter_by(id=self.sid, key=key).first()
        if value_obj is None:
            raise KeyError('Key "{}" not in this session'.format(key))
        value_text = value_obj.value
        return yaml.load(value_text)

    def __setitem__(self, key, value):
        value_text = yaml.dump(value)
        session = Session.query.filter_by(id=self.sid, key=key).first()
        if session is None:
            session = Session(self.sid, key)
        session.value = value_text

        db.session.add(session)
        db.session.commit()
        self.modified = True

    def __delitem__(self, key):
        session_to_delete = Session.query.filter_by(id=self.sid, key=key).first()
        if session_to_delete is None:
            raise KeyError('Key "{}" not in this session'.format(key))
        db.session.delete(session_to_delete)
        db.session.commit()
        self.modified = True

    def __iter__(self):
        for session_item in Session.query.filter_by(id=self.sid):
            yield session_item.key

    def __len__(self):
        return Session.query.filter_by(id=self.sid).count()


class PostgresSessionInterface(SessionInterface):
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid4())
        rv = PostgresSession(sid)
        return rv

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        if not session:
            # try:
            # os.unlink(session.path)
            # except OSError as e:
            # if e.errno != errno.ENOENT:
            # raise
            if session.modified:
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain)
            return
        cookie_exp = self.get_expiration_time(app, session)
        response.set_cookie(app.session_cookie_name, session.sid, expires=cookie_exp, httponly=True, domain=domain)
