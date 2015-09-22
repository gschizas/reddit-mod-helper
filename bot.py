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
    def __init__(self, user_agent=None, *args, **kwargs):
        if user_agent is None:
            user_agent = 'Reddit Temporary Script by /u/gschizas version ' + datetime.date.today().isoformat()
        scope = {'identity', 'flair', 'read', 'modflair', 'modlog', 'modposts', 'mysubreddits', 'wikiread', 'edit', 'modcontributors'}

        oauth_client = os.environ['OAUTH_CLIENT']
        oauth_secret = os.environ['OAUTH_SECRET']

        super().__init__(user_agent=user_agent, *args, **kwargs)
        self.config.decode_html_entities = True
        self.cfg = configparser.ConfigParser()
        ini_filename = 'bot.ini'
        if 'OPENSHIFT_DATA_DIR' in os.environ:
            ini_filename = os.path.join(os.environ, ini_filename)
        with open(ini_filename) as f:
            self.cfg.read_file(f)
        self.client = oauth_client
        self.secret = oauth_secret
        self.access_token = open(os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'access_token')).read()
        self.refresh_token = open(os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'refresh_token')).read()
        redirect_url = 'https://' + os.environ['OPENSHIFT_APP_DNS'] + '/authorize_callback'
        self.set_oauth_app_info(self.client, self.secret, redirect_url)
        if self.access_token == '' or self.refresh_token == '':
            url = self.get_authorize_url('reddit_scratch', scope, True)
            print("Open the following URL in your browser:", url)
            if 'OPENSHIFT_APP_NAME' in os.environ:
                final_url = input('Enter final URL here')
                callback_url = urllib.parse.urlparse(final_url)
                callback_query = urllib.parse.parse_qs(callback_url.query)
                callback_code = callback_query['code'][0]
            else:
                webbrowser.open(url)
                callback_code = self.start_web_server(65281)

            access_information = self.get_access_information(callback_code)
            self.access_token = access_information['access_token']
            self.refresh_token = access_information['refresh_token']
            self.save_state()
        last_refresh = dateparser(self.cfg[self.section]['last_refresh'])
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
        self.cfg[self.section]['access_token'] = self.access_token
        self.cfg[self.section]['refresh_token'] = self.refresh_token
        self.cfg[self.section]['last_refresh'] = datetime.datetime.now().isoformat()
        with open('bot.ini', 'w') as f:
            self.cfg.write(f)
