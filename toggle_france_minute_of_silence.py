#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bot import RedditAgent

# test
subreddits = ['gschizas']
# prod
# subreddits = ['europe', 'greece']

r = RedditAgent()

href = 'http://www.consilium.europa.eu/en/press/press-releases/2015/11/14-joint-eu-statement-terrorist-attacks-paris/'
stylesheet_addon = '''.side a[href*="''' + href + '''"] {
    position:fixed;
    top:0; left:0;
    height:100%;
    width:100%;
    z-index:9999;
    background:#000;
    color:#FFF;
    font-size:50px;
    line-height:500%;
    text-align:center;
}
body {
    overflow: hidden;
}
.moderator .styleToggle {
    z-index: 99999;
    background-color: white;
    text-align: center;
}\n\n'''

for subreddit in subreddits:
    sr = r.get_subreddit(subreddit)
    # get stylesheet
    current_stylesheet = sr.get_stylesheet()['stylesheet']
    # check if stylesheet already has the changes
    if stylesheet_addon in current_stylesheet:
        new_stylesheet = current_stylesheet.replace(stylesheet_addon, '')
        print('Removing France solidarity stylesheet fragment on ' + subreddit)
    else:
        new_stylesheet = stylesheet_addon + current_stylesheet
        print('Adding France solidarity stylesheet fragment' + subreddit)
    # update stylesheet
    result = sr.set_stylesheet(new_stylesheet)
    print(result)

