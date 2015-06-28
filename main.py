#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import configparser
import datetime
import io
import logging
import urllib.parse
import re

import PIL
import PIL.Image
import praw
import requests
import tinycss
import yaml
from flask import Flask, render_template, make_response, request, redirect, url_for, session, flash

from SqliteSession import SqliteSessionInterface

app = Flask(__name__)
app.secret_key = 'mNQNveTK5DmSyjTJJfQ4bYzd6vvBPUjj'
logging.basicConfig(level=logging.DEBUG)


@app.context_processor
def inject_sysinfo():
    return dict(sysinfo=dict(build="0.2"))


@app.context_processor
def inject_user():
    return dict(user=session['me']) if 'me' in session else None


@app.template_filter('maxlength')
def max_length(iterable):
    validators_max_length = [v.max for v in iterable.validators if 'wtforms.validators.Length' in str(type(v))]
    if len(validators_max_length) > 0:
        return max(validators_max_length)


@app.route('/_dropdown/<table_name>', methods=('GET', 'POST'))
def dropdown(table_name):
    pass


def reddit_agent():
    r = praw.Reddit(user_agent='Reddit Mod Helper by /u/gschizas version 0.3')
    r.config.decode_html_entities = True
    r.config.log_requests = 2
    cfg = configparser.ConfigParser()
    with open('bot.ini') as f:
        cfg.read_file(f)

    # print(request.headers)
    http_host = request.headers['X-Original-Host'] if 'X-Original-Host' in request.headers else request.host
    protocol = 'https' if request.headers.get('X-Original-Https') == 'on' else 'http'
    redirect_url = urllib.parse.urljoin(protocol + '://' + http_host + '/', url_for('authorize_callback'))
    print(redirect_url)
    r.set_oauth_app_info(cfg['oauth']['client'], cfg['oauth']['secret'], redirect_url)
    if 'access_info' in session:
        access_information = yaml.load(session['access_info'])
        if 'last_used' in session:
            last_used = session['last_used']
            minutes = (datetime.datetime.now() - last_used).total_seconds() / 60
        else:
            minutes = 365 * 24 * 60

        if minutes > 60:
            new_access_info = r.refresh_access_information(access_information['refresh_token'])
            session['access_info'] = yaml.dump(new_access_info)
        else:
            r.set_access_credentials(**access_information)
        session['me'] = get_me_serializable(r)
    return r


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
    #if 'moderated_subreddits' not in session:
    #    session['moderated_subreddits'] = list(r.get_my_moderation())
    #return session['moderated_subreddits']
    return list(r.get_my_moderation())


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


@app.route('/home')
def home():
    subreddits = moderated_subreddits()
    return render_template('home.html', subreddits=subreddits)


def get_me_serializable(r):
    me = r.get_me()
    me_serializable = dict(comment_karma=me.comment_karma, created=me.created, created_utc=me.created_utc,
                           gold_creddits=me.gold_creddits, gold_expiration=me.gold_expiration,
                           has_fetched=me.has_fetched,
                           has_verified_email=me.has_verified_email, hide_from_robots=me.hide_from_robots, id=me.id,
                           inbox_count=me.inbox_count, is_gold=me.is_gold, is_mod=me.is_mod, json_dict=me.json_dict,
                           link_karma=me.link_karma, name=me.name, over_18=me.over_18)
    return me_serializable


@app.route('/debug')
def debug():
    print(request.headers)
    http_host = request.headers['X-Original-Host'] if 'X-Original-Host' in request.headers else request.host
    result = '<html><body><h1>' + http_host + '</h1><table>'
    result += ''.join(['<tr><td>{}</td><td>{}</td></tr>'.format(k, v) for k, v in request.headers.items()])
    result += '</table></body></html>'
    return result


@app.route('/authorize_callback')
def authorize_callback():
    state = request.args.get('state')
    code = request.args.get('code')
    r = reddit_agent()
    try:
        access_information = r.get_access_information(code)
    except praw.errors.OAuthInvalidGrant as ex:
        print(ex)
        return make_response(redirect(make_authorize_url(r)))
    session['access_info'] = yaml.dump(access_information)
    session['last_used'] = datetime.datetime.now()
    session['me'] = get_me_serializable(r)
    return make_response(redirect(url_for('home')))


def make_authorize_url(r):
    scope = ['identity', 'flair', 'read', 'modflair', 'modlog', 'modposts', 'mysubreddits']
    authorize_url = r.get_authorize_url('RedditModHelper', scope, True)
    return authorize_url


@app.route('/')
def index():
    global first_run
    if first_run:
        session.clear()
        first_run = False
    if 'access_info' in session:
        return make_response(redirect(url_for('home')))
    else:
        r = reddit_agent()
        return make_response(redirect(make_authorize_url(r)))
        # return render_template('index.html')


def main():
    global first_run
    app.session_interface = SqliteSessionInterface()
    first_run = True
    app.run(port=5007, host='0.0.0.0', debug=True)


if __name__ == '__main__':
    main()
