#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import logging
import logging.handlers
import re
import json

import praw

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
    return re.findall('https?://', flair_text or '')

def setup_logging():
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    fh = logging.handlers.TimedRotatingFileHandler('remove_flair.log', when='midnight')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def run_praw_tasks():
    global logger
    cfg = configparser.ConfigParser()
    cfg.read('flair-bot.ini')
    # cfg.get('authentication', 'client_id')

    r = praw.Reddit(user_agent='Flair helper by /u/gschizas version 0.2')

    # config

    # access_token = cfg.get('access_info', 'access_token')
    # refresh_token = cfg.get('access_info', 'refresh_token')
    # access_info = {'access_token': access_token, 'refresh_token': refresh_token, 'scope': {'modflair'}}
    username = cfg.get('authentication', 'username')
    password = cfg.get('authentication', 'password')

    # client_id = cfg.get('authentication', 'client_id')
    # client_secret = cfg.get('authentication', 'client_secret')
    # redir_url = cfg.get('authentication', 'redir_url')

    # login

    # r.set_oauth_app_info(client_id, client_secret, redir_url)
    # r.set_access_credentials(**access_info)
    # r.refresh_access_information(access_information['refresh_token'])

    r.login(username=username, password=password)

    # action stuff
    search_space = json.loads(cfg.get('tasks', 'bitcoin_flair'))
    for subreddit_name, user_name in search_space:
        logger.info('Searching {} for {}'.format(subreddit_name, user_name))
        sr = r.get_subreddit(subreddit_name)
        rd = r.get_redditor(user_name)

        # print(sr)
        # print(rd)
        userflair = sr.get_flair(rd)
        logger.info(userflair)
        flair_text = userflair['flair_text']
        if flair_text:
            bitcoin_addresses = re.findall('[13][a-km-zA-HJ-NP-Z0-9]{26,33}', flair_text)
            logger.warning(bitcoin_addresses)
            if any([check_bc(bc) for bc in bitcoin_addresses]):
                logger.warning('BitCoin Addresses Found: {}'.format(bitcoin_addresses))
                result = sr.set_flair(rd, flair_text='')
                logger.warning(result)
        if check_hyperlink(flair_text):
            logger.warning('hyperlink found in here: {}'.format(flair_text))
            result = sr.set_flair(rd, flair_text='')
            logger.warning(result)

    r.clear_authentication()

def main():
    setup_logging()
    run_praw_tasks()

if __name__ == '__main__':
    main()
