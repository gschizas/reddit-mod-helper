#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bot import RedditAgent
import datetime

r = RedditAgent(ini_section='muteuserbot')
sr1 = r.get_subreddit('europe')

checked_users = []
muted_users = list(sr1.get_muted())
modmail = list(sr1.get_mod_mail(limit=20))

for message in modmail:
    author = message.author
    if author in checked_users:
        continue
    if author in muted_users:
        print('{} is already muted'.format(author))
        checked_users.append(author)
        continue
    created = datetime.datetime.fromtimestamp(author.created_utc)
    dt = datetime.datetime.utcnow() - created
    if dt.total_seconds() > 1 * 60 * 60: # half an hour seems enough
        print('{} is old enough ({})'.format(author, created.isoformat()))
        checked_users.append(author)
        continue
    print('Muting {} for message {}'.format(author, message.subject))
    message.mute_modmail_author()
