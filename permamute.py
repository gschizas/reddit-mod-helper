#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bot import RedditAgent
import ruamel.yaml as yaml

r = RedditAgent(ini_section='muteuser')
sr = r.get_subreddit('europe')
muted_users = list(sr.get_muted(user_only=False))
muted_usernames = [user['name'].name for user in muted_users]
permamutes = yaml.load(sr.get_wiki_page('permamuted').content_md)

for permamute in permamutes:
    print(permamute, permamute in muted_usernames)
    if permamute not in muted_usernames:
        sr.add_mute(permamute)
