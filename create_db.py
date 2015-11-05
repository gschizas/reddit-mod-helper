#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from flask import Flask

import model

app = Flask(__name__)
app.secret_key = 'SwK1xDj4gWIeDrTPqfMcXA8LJ1/BDlRDjLkaNAYcm5/ZO1gtdP31bDFrsVkN5EHE'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('OPENSHIFT_POSTGRESQL_DB_URL')
app.config['SECRET_KEY'] = app.secret_key
app.config['CSRF_ENABLED'] = False

model.db.init_app(app)
with app.app_context():
    model.db.create_all()
