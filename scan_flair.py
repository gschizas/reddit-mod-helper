#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import praw
import json
import re
import configparser
import logging
import logging.handlers
import sys

from hashlib import sha256

digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decode_base58(bc, length):
    n = 0
    for char in bc:
        n = n * 58 + digits58.index(char)
    return n.to_bytes(length, 'big')


def check_bc(bc):
    bcbytes = decode_base58(bc, 25)
    return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]


def check_hyperlink(flair_text):
    return re.findall('https?://', flair_text)


def run_praw_tasks():
    global logger
    from bot import RedditAgent
    cfg = configparser.ConfigParser()

    r = RedditAgent(ini_section='flairbot', user_agent='Flair helper by /u/gschizas version 0.2')

    search_space = json.loads(cfg.get('tasks', 'bitcoin_flair'))

    subreddits = {s[0] for s in search_space}

    offending_users = []
    sys.exit(99)
    for subreddit in subreddits:
        sr = r.get_subreddit(subreddit)
        flair_list = list(sr.get_flair_list(limit=None))
        flair_templates = sr.get_flair_choices()
        default_flair_text = {f['flair_css_class'][6:]: f['flair_text'] for f in flair_templates['choices']}
        extended_flair_list = [dict(
            f.items() | {'is_custom': default_flair_text.get(f['flair_css_class'], '***') != f['flair_text']}.items())
                               for f in flair_list]

        with open('flair_list-{}.json'.format(subreddit), mode='w', encoding='utf-8') as f:
            json.dump(extended_flair_list, f, ensure_ascii=False, sort_keys=True)

        for flair_item in flair_list:
            flair_text = flair_item.get('flair_text')
            if flair_text:
                bitcoin_addresses = re.findall('[13][a-km-zA-HJ-NP-Z0-9]{26,33}', flair_text)
                if len(bitcoin_addresses) > 0:
                    logging.warning(bitcoin_addresses)
                if any([check_bc(bc) for bc in bitcoin_addresses]):
                    offending_users.append([subreddit, flair_item['user']])
                if check_hyperlink(flair_text):
                    offending_users.append([subreddit, flair_item['user']])

    if len(offending_users) > 0:
        logging.warning(offending_users)
        existing_users = json.loads(cfg.get('tasks', 'bitcoin_flair'))
        full_users = offending_users + existing_users

        cfg.set('tasks', 'bitcoin_flair', json.dumps(list({(x[0], x[1]) for x in full_users})))

        cfg.write(sys.stdout)

        with open('flair-bot.ini', 'w') as f:
            cfg.write(f)

    r.clear_authentication()


def setup_logging():
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    log_file = os.path.join(os.environ['OPENSHIFT_PYTHON_LOG_DIR'], 'scan_flair.log')
    fh = logging.handlers.TimedRotatingFileHandler(log_file, when='W0')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def main():
    setup_logging()
    run_praw_tasks()


if __name__ == '__main__':
    main()
