#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import configparser
import datetime
import io
import logging
import urllib.parse
import re
import os
import PIL
import PIL.Image
import praw
import requests
import tinycss
from flask.ext.babel import Babel, format_datetime
from bs4 import BeautifulSoup
from flask import Flask, abort, render_template, make_response, request, redirect, url_for, session, flash, \
    after_this_request, jsonify, g
from flask_wtf import Form
from wtforms import StringField
# from SqliteSession import SqliteSessionInterface

import model

app = Flask(__name__)
app.secret_key = 'SwK1xDj4gWIeDrTPqfMcXA8LJ1/BDlRDjLkaNAYcm5/ZO1gtdP31bDFrsVkN5EHE'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('OPENSHIFT_POSTGRESQL_DB_URL')
app.config['SECRET_KEY'] = app.secret_key
app.config['CSRF_ENABLED'] = False
app.session_interface = model.PostgresSessionInterface()
babel = Babel(app)

model.db.init_app(app)
with app.app_context():
    model.db.create_all()

# app = Flask(__name__)
# app.secret_key = "darkbaboon99"

first_run = True
logging.basicConfig(level=logging.DEBUG)


@app.context_processor
def inject_sysinfo():
    return dict(sysinfo=dict(build="0.5"))


@app.context_processor
def inject_user():
    return dict(user=session['me'] if 'me' in session else None)


@app.template_filter('maxlength')
def max_length(iterable):
    validators_max_length = [v.max for v in iterable.validators if 'wtforms.validators.Length' in str(type(v))]
    if len(validators_max_length) > 0:
        return max(validators_max_length)


@app.template_filter('datetime')
def format_datetime_filter(value, date_format='medium'):
    if type(value) in [int, float]:
        value = datetime.datetime.fromtimestamp(value)
    if date_format == 'full':
        date_format = "EEEE, d MMMM y 'at' HH:mm"
    elif date_format == 'medium':
        date_format = "EE dd/MM/y HH:mm"
    return format_datetime(value, date_format)


@babel.localeselector
def get_locale():
    # if a user is logged in, use the locale from the user settings
    user = getattr(g, 'user', None)
    if user is not None:
        return user.locale
    # otherwise try to guess the language from the user accept
    # header the browser transmits.  We support de/fr/en in this
    # example.  The best match wins.
    return request.accept_languages.best_match(['el', 'de', 'fr', 'en'])


@babel.timezoneselector
def get_timezone():
    user = getattr(g, 'user', None)
    if user is not None:
        return user.timezone


@app.route('/_dropdown/<table_name>', methods=('GET', 'POST'))
def dropdown(table_name):
    pass


class ConfigureForm(Form):
    client_id = StringField(u'Client ID')
    secret = StringField(u'Secret')


@app.route('/configure', methods=('GET', 'POST'))
def configure():
    form = ConfigureForm(request.form)
    if form.is_submitted():
        cfg = configparser.ConfigParser()
        ini_filename = get_ini_filename()
        if os.path.isfile(ini_filename):
            with open(ini_filename) as f:
                cfg.read(f)
        if 'oauth' not in cfg.sections():
            cfg.add_section('oauth')
        cfg.set('oauth', 'client', form.client_id.data)
        cfg.set('oauth', 'secret', form.secret.data)
        with open(ini_filename, 'w') as f:
            cfg.write(f)
        flash('ini file created')
        return redirect(url_for('index'))
    else:
        return render_template('configure.html', form=form)


def reddit_agent(anonymous=False):
    r = praw.Reddit(user_agent='Reddit Mod Helper by /u/gschizas version 0.5')
    r.config.decode_html_entities = True
    r.config.log_requests = 2
    logging.info(os.getcwd())
    if 'OAUTH_CLIENT' in os.environ:
        oauth_client = os.environ['OAUTH_CLIENT']
        oauth_secret = os.environ['OAUTH_SECRET']
    else:
        cfg = configparser.ConfigParser()
        # if file.exists()
        ini_filename = get_ini_filename()
        if os.path.isfile(ini_filename):
            with open(ini_filename) as f:
                cfg.read_file(f)
            oauth_client = cfg['oauth']['client']
            oauth_secret = cfg['oauth']['secret']
        else:
            @after_this_request
            def do_redirect(response):
                response = redirect(url_for('configure'))
                return response

            abort(404)  # return r

    logging.debug(request.headers)
    http_host = request.headers['X-Original-Host'] if 'X-Original-Host' in request.headers else request.host
    if request.headers.get('X-Forwarded-Proto') == 'https':
        protocol = 'https'
    elif request.headers.get('X-Original-Https') == 'on':
        protocol = 'https'
    else:
        protocol = 'http'
    redirect_url = urllib.parse.urljoin(protocol + '://' + http_host + '/', url_for('authorize_callback'))
    logging.info(redirect_url)
    r.set_oauth_app_info(oauth_client, oauth_secret, redirect_url)

    if anonymous:
        return r

    if 'access_info' in session:
        access_information = session['access_info']
        if 'last_used' in session:
            last_used = session['last_used']
            minutes = (datetime.datetime.now() - last_used).total_seconds() / 60
        else:
            minutes = 365 * 24 * 60

        if minutes > 60:
            new_access_info = r.refresh_access_information(access_information['refresh_token'])
            session['access_info'] = new_access_info
        else:
            r.set_access_credentials(**access_information)
        session['me'] = get_me_serializable(r)
    else:
        @after_this_request
        def do_redirect(response):
            return make_response(redirect(make_authorize_url(r)))

        abort(404)
    return r


def get_ini_filename():
    return os.path.join(os.getenv('OPENSHIFT_DATA_DIR'), 'bot.ini')


def get_empty_submissions(subreddit):
    r = reddit_agent()
    sr = r.get_subreddit(subreddit)
    submissions = list(sr.get_new(limit=200))
    link_flairs = submissions[0].get_flair_choices()
    empty_submissions = [
        s for s in submissions
        if s.link_flair_css_class is None]
    subreddit = subreddit.lower()
    if subreddit == 'greece':
        flair_order = ['politics', 'society', 'culture', 'economy', 'sports', 'technology', 'entertainment', 'tourism',
                       'questions', 'funny', 'meta']
        flair_choices = [f for f in
                         sorted(link_flairs['choices'], key=lambda f: flair_order.index(f['flair_css_class']))]
    elif subreddit == 'iama':
        flair_choices = [f for f in sorted(link_flairs['choices'], key=lambda f: f['flair_css_class'])
                         if not f['flair_css_class'].endswith('-live')]
    else:
        flair_choices = [f for f in sorted(link_flairs['choices'], key=lambda f: f['flair_css_class'])]
    return r, empty_submissions, flair_choices


@app.route('/flair/<subreddit>')
def flair(subreddit):
    r, empty_submissions, flair_choices = get_empty_submissions(subreddit)
    html_body = render_template('flair.html',
                                subreddit=subreddit,
                                submissions=empty_submissions,
                                flairs=flair_choices)
    response = make_response(html_body)

    response.headers.add('Last-Modified', datetime.datetime.now())
    response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0')
    response.headers.add('Pragma', 'no-cache')

    return response


@app.route('/flair/<subreddit>', methods=('POST',))
def change_flair(subreddit):
    r, empty_submissions, flair_choices = get_empty_submissions(subreddit)
    processed = 0
    for field_name, field_value in request.form.items():
        if field_name.startswith('flair_'):
            thing_id = field_name[6:]
            flair_id = field_value
            if flair_id != '':
                found_submissions = [s for s in empty_submissions if s.id == thing_id]
                if len(found_submissions) == 0:
                    pass
                elif len(found_submissions) > 1:
                    pass
                else:
                    submission = found_submissions[0]
                    selected_flair = [f for f in flair_choices if f['flair_template_id'] == flair_id][0]
                    submission.set_flair(flair_text=selected_flair['flair_text'],
                                         flair_css_class=selected_flair['flair_css_class'])
                    processed += 1
    flash("Changed flair in {} submissions".format(processed), 'info')
    return make_response(redirect(url_for('index', subreddit=subreddit)))


def get_mod_queue(subreddit):
    r = reddit_agent()
    sr = r.get_subreddit(subreddit)
    mq = list(sr.get_mod_queue(limit=None))
    return r, mq


@app.route('/modqueue/<subreddit>')
def modqueue(subreddit):
    r, mq = get_mod_queue(subreddit)
    mq_comments = [entry for entry in mq if type(entry) is praw.objects.Comment]
    return render_template('modqueue.html', subreddit=subreddit, entries=mq_comments)


@app.route('/modqueue/<subreddit>', methods=('POST',))
def modqueue_action(subreddit):
    r, mq = get_mod_queue(subreddit)
    # mq = session['mq']
    approved = 0
    removed = 0
    for field_name, field_value in request.form.items():
        if field_name.startswith('rb_'):
            thing_id = field_name[3:]
            if field_value == 'none':
                continue
            thing_search = [mq1 for mq1 in mq if mq1.id == thing_id]
            print(field_name, thing_id, field_value, len(thing_search))
            if len(thing_search) == 0:
                continue
            thing = thing_search[0]
            if field_value == 'approve':
                approved += 1
                response = thing.approve()
                print(response)
            elif field_value == 'remove':
                removed += 1
                response = thing.remove()
                print(response)
    flash_message = "Processed {} items in mod queue. Approved {}, removed {}".format(
        approved + removed, approved, removed)
    flash(flash_message, 'info')
    return make_response(redirect(url_for('index')))


def show_diff(seqm):
    """Unify operations between two compared strings
seqm is a difflib.SequenceMatcher instance whose a & b are strings"""
    output = []
    for opcode, a0, a1, b0, b1 in seqm.get_opcodes():
        if opcode == 'equal':
            output.append(seqm.a[a0:a1])
        elif opcode == 'insert':
            output.append("<ins>" + seqm.b[b0:b1] + "</ins>")
        elif opcode == 'delete':
            output.append("<del>" + seqm.a[a0:a1] + "</del>")
        elif opcode == 'replace':
            output.append("<ins>" + seqm.b[b0:b1] + "</ins>")
            output.append("<del>" + seqm.a[a0:a1] + "</del>")
        else:
            raise RuntimeError("unexpected opcode")
    return ''.join(output)


def _cached_get(submission):
    cached_page = model.Submission.query.filter_by(id=submission.id).first()
    if cached_page is None:
        resp = requests.get(submission.url)
        resp_ok = resp.ok
        resp_status = resp.status_code
        resp_text = resp.text
        if resp_ok:
            cached_page = model.Submission()
            cached_page.id = submission.id
            cached_page.url = submission.url
            cached_page.title = submission.title
            cached_page.content = resp_text
            model.db.session.add(cached_page)
            model.db.session.commit()
    else:
        resp_ok = True
        resp_status = 304
        resp_text = cached_page.content
    return resp_ok, resp_status, resp_text


@app.route('/editorialization/<subreddit>')
def editorialization(subreddit):
    import difflib
    from jinja2.filters import escape
    r = reddit_agent()
    sr = r.get_subreddit(subreddit)
    submissions = [s for s in sr.get_unmoderated(limit=20) if not s.is_self]
    for submission in submissions:
        real_page_ok, real_page_status, real_page_text = _cached_get(submission)
        if real_page_ok:
            page_soup = BeautifulSoup(real_page_text, "lxml")
            title_tag = page_soup.find("title")
            if title_tag:
                submission.real_title = title_tag.text
            else:
                submission.real_title = "Could not find title"
        else:
            submission.real_title = "ERROR:" + str(real_page_status)
        diff = difflib.SequenceMatcher(None, submission.title, submission.real_title)
        submission.difference = show_diff(diff)
    return render_template('editorialization.html', subreddit=subreddit, submissions=submissions)


def parse_link(raw_link):
    link_parts = raw_link.split(',')
    if link_parts[0] == 'm':  # message
        return 'https://www.reddit.com/message/messages/' + link_parts[1]
    elif link_parts[0] == 'l':  # link
        if len(link_parts) == 3:  # comment
            return 'https://www.reddit.com/comments/{0[1]}/_/{0[2]}'.format(link_parts)
        elif len(link_parts) == 2:  # post
            return 'https://www.reddit.com/comments/{0[1]}'.format(link_parts)
    # default
    return ''


@app.route('/usernotes/<subreddit>')
def usernotes(subreddit):
    import json
    import zlib
    import datetime
    if subreddit + ':usernotes' not in session:
        r = reddit_agent()
        sr = r.get_subreddit(subreddit)
        usernotes_page = sr.get_wiki_page('usernotes')
        usernotes_compressed = json.loads(usernotes_page.content_md)
        session[subreddit + ':usernotes'] = usernotes_compressed
    else:
        usernotes_compressed = session[subreddit + ':usernotes']
    usernotes = json.loads(zlib.decompress(base64.b64decode(usernotes_compressed['blob'])).decode())
    warnings = usernotes_compressed['constants']['warnings']
    moderators = usernotes_compressed['constants']['users']
    users = {}
    for user, notes in usernotes.items():
        note_info = [{
                         'link': parse_link(n['l']),
                         'text': n['n'],
                         'when': datetime.datetime.fromtimestamp(n['t']),
                         'mode': warnings[n['m']] if n['m'] < len(warnings) else 'unknown %d' % n['m'],
                         'who': moderators[n['w']] if n['w'] < len(moderators) else 'unknown %d' % n['w']
                     } for n in notes['ns']]
        users[user] = note_info
    return render_template('usernotes.html', subreddit=subreddit, users=users)


def read_automoderator_config(sr: praw.objects.Subreddit):
    last_end = -100
    line = 1

    def make_comment_tag(matchobj):
        nonlocal last_end, line
        if last_end + 1 == matchobj.start():
            line += 1
        else:
            line = 1
        # print(matchobj.start(), matchobj.end())
        last_end = matchobj.end()
        return matchobj.group(1) + '_comment_line{}: "'.format(line) + matchobj.group(2).replace('"', '\uFF02') + '"'

    automod_page = sr.get_wiki_page('automoderator')
    automod_content = automod_page.content_md.replace('\r\n', '\n').replace('&lt;', '<')
    automod_rules = list(
        yaml.load_all(
            re.sub(
                r'^(\s*)\#\s*(.*)',
                make_comment_tag,
                automod_content,
                flags=re.MULTILINE)))
    for rule in automod_rules:
        comments = []
        for key, value in rule.items():
            if key.startswith('_comment_line'):
                comments.append(value)
        rule['_comments'] = comments
    automod_rules = [
        {k: v for k, v in rule.items() if not k.startswith('_comment_line')}
        for rule in automod_rules]

    return automod_rules


def moderated_subreddits():
    r = reddit_agent()
    result = list(r.get_my_moderation())
    return result
    # if 'moderated_subreddits' not in session:
    #     for rr in result:
    #         if rr.header_img:
    #             rr.header_img = rr.header_img.replace('http://', 'https://')
    #     session['moderated_subreddits'] = result
    # return session['moderated_subreddits']


def clean_stylesheet(css, images):
    names = set()
    for r in re.finditer(r'%%(?P<name>[^%]+)%%', css):
        names.add(r.groupdict()['name'])
    result = css
    for name in names:
        image_url = [img for img in images if img['name'] == name][0]['url']
        result = result.replace('%%' + name + '%%', image_url)
    return result


def get_stylesheet(subreddit):
    # if os.path.isfile('europe.css') and os.stat('europe.css').st_mtime > time.time() - 60 * 5:  # five minutes ago
    # with open('europe.css') as f:
    # stylesheet_css = f.read()
    # else:  # file is too old or doesn't exist
    stylesheet_data = subreddit.get_stylesheet()
    stylesheet_css = clean_stylesheet(stylesheet_data['stylesheet'], stylesheet_data['images'])
    # with open('europe.css', 'w') as f:
    # f.write(stylesheet_css)
    return stylesheet_css


@app.route('/manage_flags/<subreddit>')
def list_flags(subreddit):
    r = reddit_agent()
    sr = r.get_subreddit(subreddit)
    user_flair_choices = sorted(sr.get_flair_choices()['choices'], key=lambda x: x['flair_css_class'])

    parser = tinycss.make_parser('page3')
    stylesheet_css = get_stylesheet(sr)
    stylesheet = parser.parse_stylesheet(stylesheet_css)

    stylesheet_flair_choices = {f['flair_css_class'].split('-')[1]: f['flair_text'] for f in user_flair_choices}

    # more_flair_choices = {f['flair_css_class'].split('-')[1]: f['flair_text']
    # for f in r.get_subreddit('vexillology').get_flair_choices()['choices']}

    flair_rules = [rule for rule in stylesheet.rules if rule.selector.as_css() == '.flair']
    declarations_url = []
    declarations_width = []
    declarations_height = []
    for rule in flair_rules:
        declarations_url.extend([decl for decl in rule.declarations if decl.name == 'background-image'])
        declarations_width.extend([decl for decl in rule.declarations if decl.name == 'width'])
        declarations_height.extend([decl for decl in rule.declarations if decl.name == 'height'])

    image_file = declarations_url[0].value[0].value
    width = declarations_width[0].value[0].value
    height = declarations_height[0].value[0].value

    image_data = requests.get(image_file).content
    image = PIL.Image.open(io.BytesIO(image_data))

    flag_rules = [rule for rule in stylesheet.rules if
                  rule.selector.as_css().startswith('.flair-') and len(rule.selector.as_css()) == 11]

    flair_rules = {
        fr['flair_css_class'].split('-')[1]: {
            'template_id': fr['flair_template_id'],
            'position': fr['flair_position'],
            'css_class': fr['flair_css_class'],
            'text': fr['flair_text'],
            'editable': fr['flair_text_editable']} for fr in user_flair_choices}

    for rule in flag_rules:
        flag_name = rule.selector.as_css().split('-')[1]
        x = rule.declarations[0].value[0].value
        y = rule.declarations[0].value[2].value
        flag_description = stylesheet_flair_choices.get(flag_name, '_Unknown_ ({})'.format(flag_name))
        # more_flair_choices.get(flag_name,
        # '_Unknown_ ({})'.format(flag_name)))
        flag_filename = '{}-{}.png'.format(flag_name, flag_description)
        image2 = image.crop((-x, -y, -x + width, -y + height))
        output = io.BytesIO()
        image2.save(output, format='PNG')
        contents = output.getvalue()
        output.close()
        image_base64 = base64.b64encode(contents).decode('ascii')
        if flag_name in flair_rules:
            flair_rules[flag_name]['image'] = image_base64
        else:
            flair_rules[flag_name] = {'image': image_base64,
                                      'template_id': '',
                                      'css_class': 'flair-' + flag_name,
                                      'text': '',
                                      'position': 'left',
                                      'editable': True}
    html_body = render_template('flag_manager.html',
                                subreddit=subreddit,
                                flairs=sorted(flair_rules.items()))
    response = make_response(html_body)

    response.headers.add('Last-Modified', datetime.datetime.now())
    response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0')
    response.headers.add('Pragma', 'no-cache')

    return response


@app.route('/manage_flags/<subreddit>', methods=('POST',))
def change_flags(subreddit):
    result = '\n'.join(['{}\t{}'.format(k, v) for k, v in request.form.items()])
    print(result)
    flash(result)
    return make_response(redirect(url_for('list_flags', subreddit=subreddit)))


def get_me_serializable(r):
    me = r.get_me()
    me_serializable = dict(comment_karma=me.comment_karma, created=me.created, created_utc=me.created_utc,
                           gold_creddits=me.gold_creddits, gold_expiration=me.gold_expiration,
                           has_fetched=me.has_fetched,
                           has_verified_email=me.has_verified_email, hide_from_robots=me.hide_from_robots, id=me.id,
                           inbox_count=me.inbox_count, is_gold=me.is_gold, is_mod=me.is_mod, json_dict=me.json_dict,
                           link_karma=me.link_karma, name=me.name, over_18=me.over_18)
    return me_serializable


@app.route('/modlog/<subreddit>')
def modlog(subreddit):
    r = reddit_agent()
    sr = r.get_subreddit(subreddit)
    mod_log = sr.get_mod_log(limit=50, action="removelink")
    return render_template('modlog.html', log_entries=mod_log)


@app.route('/debug')
def debug():
    print(request.headers)
    http_host = request.headers['X-Original-Host'] if 'X-Original-Host' in request.headers else request.host
    result = '<html><body><h1>' + http_host + '</h1><table>'
    result += ''.join(['<tr><td>{}</td><td>{}</td></tr>'.format(k, v) for k, v in request.headers.items()])
    result += '</table></body></html>'
    return result


def _slack_reply(text):
    return jsonify(dict(text=text))


@app.route('/votebot', methods=('GET', 'POST'))
def votebot():
    user_id = request.form['user_id']
    user_name = request.form['user_name']
    token = request.form['token']

    if user_id == 'USLACKBOT':
        abort(204)
    correct_token = os.environ['SLACK_VOTEBOT_TOKEN']
    if token != correct_token:
        abort(404)

    text = request.form['text']
    text_parts = text.split(maxsplit=2)
    command = text_parts[1].lower()

    yes_words = ['yes', 'yay', 'si', 'oui', 'ja', 'ναι', 'true', 'upvote', '+', '+1', '1']
    no_words = ['no', 'nay', 'non', 'nein', 'όχι', 'false', 'downvote', '-', '-1']
    abstain_words = ['abstain', 'meh', 'empty', '0']
    if command == 'help':
        return _slack_reply("""
        help: this help
        list: list all active ballots
        mine: list all ballots created by me
        create <title>: create a new ballot
        delete <id>: delete a ballot
        """ + ','.join(yes_words) + """ <id>: positive vote for ballot <id>
        """ + ','.join(no_words) + """ <id>: negative vote for ballot <id>
        """ + ','.join(abstain_words) + """ <id>: neutral vote for ballot <id>
        result <id>: current vote results
        """)
    elif command == 'create':
        ballot_title = text_parts[2]
        ballot = model.Ballots.query.filter_by(title=ballot_title).first()
        if ballot is not None:
            return _slack_reply("Vote on ballot '{}' already exists".format(ballot_title))
        ballot = model.Ballots()
        ballot.title = ballot_title
        ballot.opened_by = user_name
        ballot.status = model.Ballots.VOTE_OPEN
        model.db.session.add(ballot)
        model.db.session.commit()
        return _slack_reply(command + ":" + ballot_title)
    elif command == 'finish':
        ballot_id_text = text_parts[2]
        if not re.match("\d+", ballot_id_text):
            return _slack_reply("Invalid ballot Id:", ballot_id_text)
        else:
            ballot_id = int(ballot_id_text)
        return _slack_reply("{}:{}".format(command, ballot_id))
    elif command == 'list':
        result = '\n'.join(
            ['{}. "{}" by {}'.format(ballot.ballot_id, ballot.title, ballot.opened_by)
             for ballot in model.Ballots.query]
        )
        return _slack_reply(result)
    elif command in ['my', 'mine']:
        result = '\n'.join(
            ['{}. "{}" by you'.format(ballot.ballot_id, ballot.title)
             for ballot in model.Ballots.query.filter_by(opened_by=user_name)]
        )
        return _slack_reply(result)
    elif command in yes_words:
        ballot_id = text_parts[2]
        return _slack_reply("{} voted yes for ballot {}".format(user_name, ballot_id))
    elif command in no_words:
        ballot_id = text_parts[2]
        return _slack_reply("{} voted no for ballot {}".format(user_name, ballot_id))
    elif command in abstain_words:
        return _slack_reply("{} voted abstain for ballot {}".format(user_name))
    else:
        reply = "user_id: {}\nuser_name: {}\ntext: {}\ncommand: {}".format(user_id, user_name, text, command)
        return _slack_reply(reply)


@app.route('/authorize_callback')
def authorize_callback():
    state = request.args.get('state')
    code = request.args.get('code')
    r = reddit_agent(anonymous=True)
    try:
        access_information = r.get_access_information(code)
    except praw.errors.OAuthInvalidGrant as ex:
        print(ex)
        return make_response(redirect(make_authorize_url(r)))
    session['access_info'] = access_information
    session['last_used'] = datetime.datetime.now()
    # session['me'] = get_me_serializable(r)
    return make_response(redirect(url_for('index')))


def make_authorize_url(r):
    scope = {'identity', 'flair', 'read', 'modflair', 'modlog', 'modposts', 'mysubreddits', 'wikiread'}
    authorize_url = r.get_authorize_url('RedditModHelper', scope, True)
    return authorize_url


@app.route('/')
def index():
    subreddits = moderated_subreddits()
    return render_template('index.html', subreddits=subreddits)


def main():
    app.run(port=5007, host='0.0.0.0', debug=True)


if __name__ == '__main__':
    main()
