# from typing_extensions import Required
from flask import Flask, redirect, render_template, url_for, Blueprint, current_app, g
import sqlalchemy as sql
from sqlalchemy.sql.schema import ForeignKey, Table
from sqlalchemy.sql.sqltypes import INTEGER, VARCHAR
from sqlalchemy.sql.sqltypes import DECIMAL
from sqlalchemy.sql.schema import Column

bp = Blueprint("database", __name__)

class db:
    def __init__(self):
        self.engine = sql.create_engine('sqlite:///banking.db', echo=True)
        self.meta = sql.MetaData()
        self.connection = self.engine.connect()    
        self.USERS = Table (
        'USERS', self.meta,
        Column('first_name', VARCHAR(50), nullable=False),
        Column('middle_name', VARCHAR(50)),
        Column('last_name', VARCHAR(50), nullable=False),
        Column('ssn', VARCHAR(9), unique=True, nullable=False),
        Column('username', VARCHAR(100), unique=True, nullable=False),
        Column('password', VARCHAR(100), unique=True, nullable=False),
        Column('email', VARCHAR(100), unique=True, nullable=False),
        Column('user_id', INTEGER, autoincrement=True, primary_key=True)
        )
        self.HAS_MIDDLE_NAME = Table (
            'HAS_MIDDLE_NAME', self.meta,
            Column('user_id', VARCHAR(9), primary_key=True), # Foreign key into USERS
            Column('middle_name', VARCHAR(50))
        )
        self.PARENT_OF = Table (
            'PARENT_OF', self.meta,
            Column('parent_id', VARCHAR(9), unique=True, nullable=False), # Foreign key into USERS
            Column('child_id', VARCHAR(9), primary_key=True),
            Column('spending_cap', DECIMAL(precision=10, scale=2), nullable=False)
        )
        self.SAVINGS_ACCOUNT = Table (
            'SAVINGS_ACCOUNT', self.meta,
            Column('user_id', VARCHAR(9), unique=True), # Foreign key into USERS
            Column('savings_account_number', VARCHAR(9), primary_key=True),
            Column('balance', DECIMAL(precision=10, scale=2), nullable=False)
        )
        self.CHECKING_ACCOUNT = Table (
            'CHECKING_ACCOUNT', self.meta,
            Column('user_id', VARCHAR(9), unique=True), # Foreign key into USERS
            Column('checking_account_number', VARCHAR(9), primary_key=True),
            Column('balance', DECIMAL(precision=10, scale=2), nullable=False)
        )
        self.meta.create_all(self.engine)
        

    def get_db(self):
        self.init_db()

    @classmethod
    def createAccount(fn, ln, s, un, pw, e, mn=None):
        if mn==None:
            insert_statement = USERS.insert().values(first_name=fn, last_name=ln, ssn=s, username=un, password=pw, email=e)
            result = connection.execute(insert_statement)
        else:
            insert_statement = USERS.insert().values(first_name=fn, middle_name=mn, last_name=ln, ssn=s, username=un, password=pw, email=e)
            result = connection.execute(insert_statement)
        return result

    @classmethod
    def getAccount(username):
        select_statement = USERS.select().where(USERS.user_name==username)
        result = connection.execute(select_statement).fetchone()
        return result

    @classmethod
    def deleteAccount(username):
        delete_statement = USERS.delete().where(USERS.user_name==username)
        result = connection.execute(delete_statement).fetchone()
        return result

    @classmethod
    def createChildAccount(fn, ln, s, un, pw, e, pssn, cap, mn=None):
        select_statement = USERS.select().where(USERS.ssn==pssn)
        select_result = connection.execute(select_statement).fetchone()
        if mn==None:
            insert_user_statement = USERS.insert().values(first_name=fn, last_name=ln, ssn=s, user_name=un)
            insert_user_result = connection.execute(insert_user_statement)
        else:
            insert_user_statement = USERS.insert().values(first_name=fn, middle_name=mn, last_name=ln, ssn=s, user_name=un, password=pw, email=e, user_id=ui)
            insert_user_result = connection.execute(insert_user_statement)
        insert_parent_child_statement = USERS.insert().values(parent_id=select_result.user_id, spending_cap=cap)
        insert_parent_child_result = connection.execute(insert_parent_child_statement)
        return (insert_user_result, insert_parent_child_result)
