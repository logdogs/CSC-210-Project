# from typing_extensions import Required
from flask import Flask, redirect, render_template, url_for, Blueprint, current_app, g
import sqlalchemy as sql
from sqlalchemy.sql.schema import ForeignKey, Table
from sqlalchemy.sql.sqltypes import VARCHAR
from sqlalchemy.sql.sqltypes import DECIMAL
from sqlalchemy.sql.schema import Column

bp = Blueprint("database", __name__)

engine = sql.create_engine('sqlite:///banking.db', echo=True)
meta = sql.MetaData()
connection = engine.connect()

USERS = Table (
    'USERS', meta,
    Column('first_name', VARCHAR(50), nullable=False),
    Column('last_name', VARCHAR(50), nullable=False),
    Column('ssn', VARCHAR(9), unique=True, nullable=False),
    Column('username', VARCHAR(100), unique=True, nullable=False),
    Column('user_id', VARCHAR(9), primary_key=True)
)
HAS_MIDDLE_NAME = Table (
    'HAS_MIDDLE_NAME', meta,
    Column('user_id', VARCHAR(9), primary_key=True), # Foreign key into USERS
    Column('middle_name', VARCHAR(50))
)
PARENT_OF = Table (
    'PARENT_OF', meta,
    Column('parent_id', VARCHAR(9), unique=True, nullable=False), # Foreign key into USERS
    Column('child_id', VARCHAR(9), primary_key=True),
    Column('spending_cap', DECIMAL(precision=10, scale=2), nullable=False)
)
SAVINGS_ACCOUNT = Table (
    'SAVINGS_ACCOUNT', meta,
    Column('user_id', VARCHAR(9), unique=True), # Foreign key into USERS
    Column('savings_account_number', VARCHAR(9), primary_key=True),
    Column('balance', DECIMAL(precision=10, scale=2), nullable=False)
)
CHECKING_ACCOUNT = Table (
    'CHECKING_ACCOUNT', meta,
    Column('user_id', VARCHAR(9), unique=True), # Foreign key into USERS
    Column('checking_account_number', VARCHAR(9), primary_key=True),
    Column('balance', DECIMAL(precision=10, scale=2), nullable=False)
)
def get_db():
    meta.create_all(engine)

def createAccount(fn, ln, s, un, ui):
    insert_statement = USERS.insert().values(first_name=fn, last_name=ln, ssn=s, username=un, user_id=ui)
    result = connection.execute(insert_statement)
    return result

def getAccount(username):
    select_statement = USERS.select().where(USERS.user_name==username)
    result = connection.execute(select_statement)
    return result

def deleteAccount(username):
    delete_statement = USERS.delete().where(USERS.user_name==username)
    result = connection.execute(delete_statement)
    return result

def createChildAccount(fn, ln, s, un, ui, ps, cap):
    select_statement = USERS.select().where(USERS.ssn==ps)
    select_result = connection.execute(select_statement)
    insert_user_statement = USERS.insert().values(first_name=fn, last_name=ln, ssn=s, user_name=un, user_id=ui)
    insert_user_result = connection.execute(insert_user_statement)
    insert_parent_child_statement = USERS.insert().values(parent_id=select_result.user_id, child_id=ui, spending_cap=cap)
    insert_parent_child_result = connection.execute(insert_parent_child_statement)
    return (insert_user_result, insert_parent_child_result)