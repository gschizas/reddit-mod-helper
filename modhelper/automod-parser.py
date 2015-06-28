# coding: utf-8
import os
import base64
base64.b64encode(os.urandom(16))
base64.b64encode(os.urandom(24))
def reddit_agent():
    cfg = configparser.ConfigParser()
    with open(r'C:\Users\GSchizas\Documents\Source\Python\reddit-helper\bot.ini') as f:
        cfg.read_file(f)
    username = cfg['authentication']['username']
    password = cfg['authentication']['password']
    r = praw.Reddit(user_agent='Mod helper by /u/gschizas version 0.1')
    r.login(username=username, password=password)
    return r
r = reddit_agent
r = reddit_agent()
import configparser
r = reddit_agent()
import praw
r = reddit_agent()
r.get_wiki_pages()
r.get_wiki_pages('europe')
list(r.get_wiki_pages('europe'))
a = list(r.get_wiki_pages('europe'))
a0 = a[0]
a0
a0.page
a0.content_md
import re
re.findall('\#.*$', a0.content_md)
re.findall('^\#.*$', a0.content_md)
print(content_md)
print(a0.content_md)
am = print(a0.content_md)
am = a0.content_md
am
print(am)
re.findall(r'\#.*$', am)
re.findall(r'\\#.*$', am)
re.findall(r'\#', am)
re.findall(r'\#.*', am)
am
am = am.replace('\r\n', '\n')
print(am)
print(repr(am))
re.findall(r'\#.*', am)
re.sub(r'\#(.*)', am)
re.sub(r'\#(.*)', '_comment: $1', am)
print(re.sub(r'\#(.*)', '_comment: $1', am))
print(re.sub(r'\#(.*)', '_comment: \\1', am))
print(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
get_ipython().magic('cd')
get_ipython().magic('cd')
get_ipython().magic('cd Desktop/')
with open('print(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
with open('automoderator.yaml', 'w') as f:
    f.write(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
    
with open('automoderator.yaml', 'w', encoding='utf8') as f:
    f.write(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
    
am_obj = yaml.loads(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
import yaml
am_obj = yaml.loads(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
am_obj = yaml.load_all(re.sub(r'\#\s*(.*)', '_comment: \\1', am))
am_obj
list(am_obj)
am_obj = yaml.load_all(re.sub(r'\#\s*(.*)', '_comment: "\\1"', am))
list(am_obj)
am_obj = yaml.load_all(re.sub(r'\#\s*(.*)', '_comment: \'\\1\'', am))
list(am_obj)
am_obj = list(yaml.load_all(re.sub(r'\#\s*(.*)', '_comment: \'\\1\'', am.replace('"', '\uff02'))))
am_obj = yaml.load_all(re.sub(r'\#\s*(.*)', make_comment_tag, am))
def make_comment_tag(matchobj):
    print(matchobj)
am_obj = yaml.load_all(re.sub(r'\#\s*(.*)', make_comment_tag, am))
def make_comment_tag(matchobj):
    return '_comment: ' + matchobj.group(1)
am_obj = yaml.load_all(re.sub(r'\#\s*(.*)', make_comment_tag, am))
list(am_obj)
def make_comment_tag(matchobj):
    return '_comment: "' + matchobj.group(1).replace('"', '\uFF02') + '"'
am_obj = list(yaml.load_all(re.sub(r'\#\s*(.*)', make_comment_tag, am)))
am
print(Am)
print(am)
with open('automoderator.yaml', 'w', encoding='utf8') as f:
    f.write(am)
    
am_obj = list(yaml.load_all(re.sub(r'^\s*\#\s*(.*)', make_comment_tag, am)))
am_obj
get_ipython().magic('save')
get_ipython().magic('save C:/Users/GSchizas/Documents/Source/Python/reddit-helper/automod-parser.py 1-75')
