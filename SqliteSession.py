import os
import sqlite3
from uuid import uuid4
from pickle import dumps, loads
from collections import MutableMapping

from flask.sessions import SessionInterface, SessionMixin


class SqliteSession(MutableMapping, SessionMixin):
    _create_sql = (
        'CREATE TABLE IF NOT EXISTS session '
        '('
        '  sid VARCHAR(36),'
        '  key TEXT PRIMARY KEY,'
        '  val BLOB'
        ')'
    )
    _get_sql = 'SELECT val FROM session WHERE sid = ? AND key = ?'
    _set_sql = 'REPLACE INTO session (sid, key, val) VALUES (?, ?, ?)'
    _del_sql = 'DELETE FROM session WHERE sid = ? AND key = ?'
    _ite_sql = 'SELECT key FROM session WHERE sid = ?'
    _len_sql = 'SELECT COUNT(*) FROM session WHERE sid = ?'

    def __init__(self, sid, *args, **kwargs):
        self.sid = sid
        self.modified = False
        self.conn = None
        if not os.path.exists(self._db_filename()):
            with self._get_conn() as conn:
                conn.execute(self._create_sql)
                self.new = True

    def __getitem__(self, key):
        key = dumps(key, 0)
        rv = None
        with self._get_conn() as conn:
            for row in conn.execute(self._get_sql, (self.sid, key,)):
                rv = loads(row[0])
                break
        if rv is None:
            raise KeyError('Key not in this session')
        return rv

    def __setitem__(self, key, value):
        key = dumps(key, 0)
        value = dumps(value, 2)
        with self._get_conn() as conn:
            conn.execute(self._set_sql, (self.sid, key, value))
        self.modified = True

    def __delitem__(self, key):
        key = dumps(key, 0)
        with self._get_conn() as conn:
            conn.execute(self._del_sql, (self.sid, key,))
        self.modified = True

    def __iter__(self):
        with self._get_conn() as conn:
            for row in conn.execute(self._ite_sql, (self.sid,)):
                yield loads(row[0])

    def __len__(self):
        with self._get_conn() as conn:
            for row in conn.execute(self._len_sql, (self.sid,)):
                return row[0]

    def _get_conn(self):
        if not self.conn:
            self.conn = sqlite3.Connection(self._db_filename())
        return self.conn

    def _db_filename(self):
        filename = os.path.join(os.getenv('OPENSHIFT_DATA_DIR'), 'session.db')
        return filename

    # These proxy classes are needed in order
    # for this session implementation to work properly. 
    # That is because sometimes flask will chain method calls
    # with session'setdefault' calls. 
    # Eg: session.setdefault('_flashes', []).append(1)
    # With these proxies, the changes made by chained
    # method calls will be persisted back to the sqlite
    # database.
    class CallableAttributeProxy(object):
        def __init__(self, session, key, obj, attr):
            self.session = session
            self.key = key
            self.obj = obj
            self.attr = attr

        def __call__(self, *args, **kwargs):
            rv = self.attr(*args, **kwargs)
            self.session[self.key] = self.obj
            return rv

    class PersistedObjectProxy(object):
        def __init__(self, session, key, obj):
            self.session = session
            self.key = key
            self.obj = obj

        def __getattr__(self, name):
            attr = getattr(self.obj, name)
            if callable(attr):
                return SqliteSession.CallableAttributeProxy(
                    self.session, self.key, self.obj, attr)
            return attr

    def setdefault(self, key, value=None):
        if key not in self:
            self[key] = value
            self.modified = True
        return SqliteSession.PersistedObjectProxy(
            self, key, self[key])


class SqliteSessionInterface(SessionInterface):
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid4())
        rv = SqliteSession(sid)
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
        response.set_cookie(app.session_cookie_name, session.sid,
                            expires=cookie_exp, httponly=True, domain=domain)