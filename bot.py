# coding: utf-8
import urllib.parse
import praw
import configparser
import datetime
import os
import http.server

from dateutil.parser import parse as dateparser


class ScriptCallbackWebServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path != '/authorize_callback' or 'code' not in query:
            self.send_response(404)
            return
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<html><head><title>Simple Bot Helper</title></head>".encode('utf-8'))
        self.wfile.write("<body><p>This is the authorise callback page.</p>".encode('utf-8'))
        self.wfile.write("<p>You accessed path: {}</p>".format(self.path).encode('utf-8'))
        self.wfile.write("<p>You can close your browser".encode('utf-8'))
        self.wfile.write("</body></html>".encode('utf-8'))
        self.server.callback_code = query['code'][0]
        self.server.now_serving = False


class RedditAgent(praw.Reddit):
    def __init__(self, user_agent=None, ini_section='DEFAULT', scope=None, *args, **kwargs):
        self.cfg = configparser.ConfigParser()
        self.section = ini_section
        self.ini_filename = 'bot.ini'
        ini_dirty = False
        if 'OPENSHIFT_DATA_DIR' in os.environ:
            self.ini_filename = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], self.ini_filename)

        if os.path.isfile(self.ini_filename):
            self.cfg.read(self.ini_filename)

            if user_agent is None and 'user_agent' in self.cfg[self.section]:
                user_agent = self.cfg[self.section]['user_agent']

            if scope is None and 'scope' in self.cfg[self.section]:
                scope = set(self.cfg[self.section]['scope'].split(','))

            if self.section in self.cfg.sections():
                oauth_client = self.cfg[self.section]['client']
                oauth_secret = self.cfg[self.section]['secret']
            else:
                ini_dirty = True
        else:
            ini_dirty = True

        if ini_dirty:
            oauth_client = input("Enter Client ID: ")
            oauth_secret = input("Enter Secret ID: ")
            if os.path.isfile(self.ini_filename):
                self.cfg.read(self.ini_filename)
            with open(self.ini_filename, 'w') as f:
                self.cfg.add_section(self.section)
                self.save_state()
                self.cfg[self.section]['client'] = oauth_client
                self.cfg[self.section]['secret'] = oauth_secret
                self.cfg.write(f)

        self.client = oauth_client
        self.secret = oauth_secret

        if user_agent is None:
            user_agent = 'Reddit Temporary Script by /u/gschizas version ' + datetime.date.today().isoformat()
        if scope is None:
            scope = {'identity',
                     'flair',
                     'read',
                     'modflair',
                     'modlog',
                     'modposts',
                     'mysubreddits',
                     'wikiread',
                     'edit',
                     'modcontributors'}

        super().__init__(user_agent=user_agent, *args, **kwargs)

        self.config.decode_html_entities = True
        self.access_token = self.cfg[self.section].get('access_token', '')
        self.refresh_token = self.cfg[self.section].get('refresh_token', '')
        redirect_url = "http://example.com/authorize_callback"
        self.set_oauth_app_info(self.client, self.secret, redirect_url)
        if self.access_token == '' or self.refresh_token == '':
            url = self.get_authorize_url('reddit_scratch', scope, True)
            if 'OPENSHIFT_APP_NAME' in os.environ:
                # we are running under openshift, so, don't open browser automatcially
                # as openshift's environment only has a text browser, and it's not
                # going to be logged in
                print("Open the following URL in your browser:", url)
                final_url = input('Enter final URL here')
                callback_url = urllib.parse.urlparse(final_url)
                callback_query = urllib.parse.parse_qs(callback_url.query)
                callback_code = callback_query['code'][0]
            else:
                import webbrowser
                webbrowser.open(url)
                callback_code = self.start_web_server(65281)

            access_information = self.get_access_information(callback_code)
            self.access_token = access_information['access_token']
            self.refresh_token = access_information['refresh_token']
            self.save_state()
        last_refresh_text = self.cfg[self.section].get('last_refresh')
        if last_refresh_text is None:
            self.refresh_token = None
        else:
            last_refresh = dateparser(last_refresh_text)
            minutes = (datetime.datetime.now() - last_refresh).total_seconds() / 60
            if minutes < 60:
                self.refresh_token = None
            else:
                access_information = self.refresh_access_information(self.refresh_token)
                self.access_token = access_information['access_token']
                self.refresh_token = access_information['refresh_token']
                self.save_state()
        self.set_access_credentials(scope, self.access_token, self.refresh_token, True)

    def start_web_server(self, port):
        """
        :rtype : string
        """
        server = http.server.HTTPServer(('', port), ScriptCallbackWebServer)
        print('Started httpserver on port:', port)
        server.now_serving = True
        server.callback_code = None
        # Wait for incoming http requests
        # until a proper result is found
        while server.now_serving:
            server.handle_request()
        server.server_close()
        return server.callback_code

    def save_state(self):
        self.cfg.read(self.ini_filename)
        if self.section not in self.cfg.sections():
            self.cfg.add_section(self.section)
        self.cfg[self.section]['access_token'] = self.access_token
        self.cfg[self.section]['refresh_token'] = self.refresh_token
        self.cfg[self.section]['last_refresh'] = datetime.datetime.now().isoformat()
        with open(self.ini_filename, 'w') as f:
            self.cfg.write(f)
