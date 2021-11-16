from flask import Flask, redirect, render_template, url_for, Blueprint
from flask_sqlalchemy import SQLAlchemy

bp = Blueprint("auth", __name__, url_prefix="auth")

bp.route('/login')
def login():

    return

bp.route('/register')
def register():

    return