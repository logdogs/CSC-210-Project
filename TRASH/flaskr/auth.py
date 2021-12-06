import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

import database

bp = Blueprint("auth", __name__, url_prefix="/auth")
db = database.db

@bp.route('/login')
def login():

    return

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        middle_name = request.form['middle_name']
        last_name = request.form['last_name']
        ssn = request.form['ssn']
        email = request.form['email']
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'
        elif not first_name:
            error = 'First name is required'
        elif not last_name:
            error = 'Last name is required'
        elif not ssn:
            error = 'SSN is required'
        elif not email:
            error = 'Email is required'
        
        if error is None:
            if not middle_name:
                db.createAccount(first_name, last_name, ssn, username, password, email, )
            else:
                db.createAccount(first_name, last_name, ssn, username, password, email, middle_name)
                
    return render_template('create.html')