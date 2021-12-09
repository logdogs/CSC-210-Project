from operator import length_hint
from flask import Flask, render_template, url_for, redirect, request, session, abort
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
import random
import bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import base64
import onetimepass
import pyqrcode
from flask_wtf import FlaskForm
from io import BytesIO
from wtforms.validators import DataRequired, Length
from wtforms import StringField, PasswordField, SubmitField
import os


#Flask and sqlalchemy stuff initialized here
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "AJHHJAKKHJASKHJDKAJHJHELPHKFHJAKSASHJKADHJKHJKASHJKSAHDSJA"

#Email confirmation stuff here
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'ccebankrochester@gmail.com'
app.config['MAIL_PASSWORD'] = 'thisisapassword'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
s = URLSafeTimedSerializer('AJHHJAKKHJASKHJDKAJHJHELPHKFHJAKSASHJKADHJKHJKASHJKSAHDSJA')

#Database created
db = SQLAlchemy(app)

#Database model class. Can add more columns for more properties
class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    ssn = db.Column(db.String(9))
    username = db.Column(db.String(100))
    email = db.Column(db.String(100))
    hash = db.Column(db.String(100))
    user_id = db.Column(db.String(10))
    saving_balance = db.Column(db.String(10))
    saving_acc_no = db.Column(db.String(10))
    checking_balance = db.Column(db.String(10))
    checking_acc_no = db.Column(db.String(10))
    otp_secret = db.Column(db.String(16))

    def __init__(self, first_name, middle_name, last_name, ssn, username, email, hash, user_id, saving_balance, saving_acc_no, checking_balance, checking_acc_no, otp_secret):
        self.first_name = first_name
        self.middle_name = middle_name
        self.last_name = last_name
        self.ssn = ssn
        self.username = username
        self.email = email
        self.hash = hash
        self.user_id = user_id
        self.saving_balance = saving_balance
        self.saving_acc_no = saving_acc_no
        self.checking_balance = checking_balance
        self.checking_acc_no = checking_acc_no
        self.otp_secret = otp_secret

    def get_totp_uri(self):
        return 'otpauth://totp/CCE:{0}?secret={1}&issuer=CCE' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, pin):
        return onetimepass.valid_totp(pin, self.otp_secret)
# Stands for "parent-child relation"
class pcr(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    # Represents the parent and child id's, respectively
    parent = db.Column(db.Integer) 
    child = db.Column(db.Integer)
    
    def __init__(self, parent_id, child_id):
        self.parent = parent_id
        self.child = child_id

#wtforms login 
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    pin = StringField('Token', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Login')

#Home page
#@app.route("/", methods=["POST", "GET"])
#def home():
#    return redirect(url_for("login"))


#Create account
@app.route("/create", methods=["POST", "GET"])
def create():
    #If we've just entered information, it will be stored in session and db
    #First check if account with the same username already exists
    if request.method == "POST":
        first_name = request.form["first_name"]
        middle_name = request.form["middle_name"]
        last_name = request.form["last_name"]
        ssn = request.form["ssn"]
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        #If duplicate account found
        found_user = users.query.filter_by(username=username).first()
        if found_user:
            flash("Account with same username already exists.")
            return redirect(url_for("create")) 

        #Hash password and, create new user instance
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        #print("CREATE HASHED IS {hashed}".format(hashed=hashed))

        usr = users(first_name, middle_name, last_name, ssn, username, email, hashed, random.randint(0, 9999999999), 0, random.randint(0, 9999999999), 0, random.randint(0, 9999999999), otp_secret)
        db.session.add(usr)
        db.session.commit()

        found_user = users.query.filter_by(username=username).first()
        user_id = found_user.user_id
        saving_balance = found_user.saving_balance
        saving_acc_no = found_user.saving_acc_no
        checking_balance = found_user.checking_balance
        checking_acc_no = found_user.checking_acc_no

        session["first_name"] = first_name
        session["middle_name"] = middle_name
        session["last_name"] = last_name
        session["ssn"] = ssn
        session["username"] = username
        session["email"] = email
        session["password"] = password
        session["user_id"] = user_id
        session["saving_balance"] = saving_balance
        session["saving_acc_no"] = saving_acc_no
        session["checking_balance"] = checking_balance
        session["checking_acc_no"] = checking_acc_no
        session["otp_secret"] = otp_secret
        
        return redirect(url_for('two_factor_setup'))
    #If we enter this page without filling form, check if user is already logged in
    #If so, log out, otherwise show create form
    else:
        if "username" in session:
            end_session()
        return render_template("create.html")

#Sends to QR code page 
@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    found_user = users.query.filter_by(username=session['username']).first()
    if found_user is None:
        return redirect(url_for('index'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two_factor_setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

#QRcode to make FreeTOTP
@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    found_user = users.query.filter_by(username=session['username']).first()
    if found_user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    url = pyqrcode.create(found_user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

#Login page
#@app.route("/login", methods=["POST", "GET"])
#def login():
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        found_user = users.query.filter_by(username=form.username.data).first()
        if not bcrypt.checkpw(form.password.data.encode('utf-8'), found_user.hash) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))
        if found_user:
            session["first_name"] = found_user.first_name
            session["middle_name"] = found_user.middle_name
            session["last_name"] = found_user.last_name
            session["ssn"] = found_user.ssn
            session["username"] = form.username
            session["email"] = found_user.email
            session["password"] = found_user.hash
            session["user_id"] = found_user.user_id
            session["saving_balance"] = found_user.saving_balance
            session["saving_acc_no"] = found_user.saving_acc_no
            session["checking_balance"] = found_user.checking_balance
            session["checking_acc_no"] = found_user.checking_acc_no
           
            return redirect(url_for("user", user_id=session["user_id"]))
        #Otherwise, let the user know they have entered wrong information
        else:
            flash("Username or password is incorrect. Try again.")
            return render_template('login.html', form=form)
    else:
        if "username" in session:
            return redirect(url_for("user", user_id=session["user_id"]))
        return render_template('login.html', form=form)

#Home page
@app.route("/", methods=["POST", "GET"])
def home():
    #If we've just entered information, it will use that information to check if user exists
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        #Check if name existed
        found_user = users.query.filter_by(username=username).first()
        #If found, check if password is correct
        if not bcrypt.checkpw(password.encode('utf-8'), found_user.hash):
            flash("Username or password is incorrect. Try again.")
            return redirect(url_for("home")) 
        #If password is correct, add user's info to session, then go to the page
        if found_user:
            session["first_name"] = found_user.first_name
            session["middle_name"] = found_user.middle_name
            session["last_name"] = found_user.last_name
            session["ssn"] = found_user.ssn
            session["username"] = username
            session["email"] = found_user.email
            session["password"] = found_user.hash
            session["user_id"] = found_user.user_id
            session["saving_balance"] = found_user.saving_balance
            session["saving_acc_no"] = found_user.saving_acc_no
            session["checking_balance"] = found_user.checking_balance
            session["checking_acc_no"] = found_user.checking_acc_no

            return redirect(url_for("user", user_id=session["user_id"]))
        #Otherwise, let the user know they have entered wrong information
        else:
            flash("Username or password is incorrect. Try again.")
            return redirect(url_for("home")) 

    #If we enter this page without filling form, check if user is already logged in
    #If so, return user, otherwise show login form
    else:
        if "username" in session:
            return redirect(url_for("user", user_id=session["user_id"]))
        return render_template("index.html")


#User dashboard. All information for users will be displayed here.
@app.route("/user/<user_id>", methods=["POST", "GET"])
def user(user_id):
    #If there is session, get info from that user
    if "username" in session:
        first_name = session["first_name"]
        middle_name = session["middle_name"]
        last_name = session["last_name"]
        ssn = session["ssn"]
        username = session["username"]
        email = session["email"]
        password = session["password"]
        user_id = session["user_id"]
        # Want to reload the saving_balance and checking_balance
        updated_user = users.query.filter_by(username=username).first()
        session["saving_balance"] = updated_user.saving_balance
        session["checking_balance"] = updated_user.checking_balance
        saving_balance = session["saving_balance"] # ****
        saving_acc_no = session["saving_acc_no"]
        checking_balance = session["checking_balance"] # ***
        checking_acc_no = session["checking_acc_no"]

        # Get the children of the user
        children = pcr.query.filter_by(parent=user_id).all()

        return render_template("user.html", first_name=first_name, middle_name=middle_name, last_name=last_name, ssn=ssn, username=username, email=email, password=password, user_id=user_id, saving_balance=saving_balance, saving_acc_no=saving_acc_no, checking_balance=checking_balance, checking_acc_no=checking_acc_no, children=children)
    #If there is no session, make user log in
    else:
        return redirect(url_for("home"))


#This ends session and redirects the user to the home page
@app.route("/logout")
def logout():
    end_session()
    return redirect(url_for("home"))

# This will go to a place that has the user register an account for their child
@app.route("/create_child_account", methods=["POST", "GET"])
def create_child_account():
    if request.method == "POST":
        # Need to create a new account in the database, as well as link it via the has-child relation to the parent
        firstName = request.form['first_name']
        middleName = request.form['middle_name']
        lastName = request.form['last_name']
        social = request.form['ssn']
        parent_social = request.form['parent_ssn']
        username = request.form['user_name']
        mail = request.form['email']
        pw = request.form['password']
        
        # Make sure they didn't re-add their child
        forgotten_child = users.query.filter_by(ssn=social).first()
        if forgotten_child:
            flash("Child account already exists.")
            return render_template("create_child.html")

        # Create and add the child to the database
        child = users(firstName, middleName, lastName, social, username, mail, pw)
        db.add(child)
        # Find the parent, create the relation between them and their child, then add that to the database
        parent = users.query().filter_by(ssn=parent_social).fetchone()
        parent_child_rel = pcr(parent.ssn, social)
        db.add(parent_child_rel)

    return render_template("create_child.html")

#
@app.route("/addToChecking")
def changeMoney():
    return render_template("addToChecking.html")

#
@app.route("/addToSavings")
def addToSavings():
    return render_template("addToSavings.html")

#
@app.route("/checking_deposit", methods=["POST", "GET"])
def checking_deposit():
    # Update the database
    user = users.query.filter_by(username=session['username']).first()
    current_amount = user.checking_balance
    updated_amount = str(float(current_amount) + float(request.form['amount']))
    stmt = (db.update(users).where(users.ssn==user.ssn).values(checking_balance=updated_amount))
    db.session.execute(stmt)
    db.session.commit()
    return render_template("successful_add.html")
#
@app.route("/savings_deposit", methods=["POST", "GET"])
def savings_deposit():
    user = users.query.filter_by(username=session['username']).first()
    current_amount = user.saving_balance
    updated_amount = str(float(current_amount) + float(request.form['amount']))
    stmt = (db.update(users).where(users.ssn==user.ssn).values(saving_balance=updated_amount))
    db.session.execute(stmt)
    db.session.commit()
    return render_template("successful_add.html")

#Pops everything from session
def end_session():
    session.pop("first_name", None)
    session.pop("middle_name", None)
    session.pop("last_name", None)
    session.pop("ssn", None)
    session.pop("username", None)
    session.pop("email", None)
    session.pop("password", None)
    session.pop("user_id", None)
    session.pop("saving_balance", None)
    session.pop("saving_acc_no", None)
    session.pop("checking_balance", None)
    session.pop("checking_acc_no", None)


#User List. Only admin has access to this
@app.route("/user_list")
def user_list():
    try:
        if session["username"] == "admin":
            return render_template("user_list.html", values=users.query.all())
        else:
            flash("You have to be admin to view this list!")
            return redirect(url_for("home")) 
    except:
            flash("You have to be admin to view this list!")
            return redirect(url_for("home")) 


# Aks for email address, so it can send reset link
@app.route("/reset", methods=["POST", "GET"])
def reset():
    #If we've just entered information, it will use that information to check if user exists
    if request.method == "POST":
        email = request.form["email"]
        #Check if email existed
        found_user = users.query.filter_by(email=email).first()

        if found_user:
            token = s.dumps(email, salt='email-confirm')

            msg = Message('CCE Reset Password', sender='cengizjahnozel@gmail.com', recipients=[email])
            link = url_for('change_pw', token=token, _external=True)
            msg.body = "Your password reset link is {}".format(link)
            mail.send(msg)

            flash("Password reset link has been sent to " + email)
            flash("Make sure to check your spam folder!")
            return redirect(url_for("reset"))
        else:
            flash("User with this email does not exist.")
            return redirect(url_for("reset"))
    else:
        return render_template("reset.html")


# Reset password
@app.route("/change_pw/<token>", methods=["POST", "GET"])
def change_pw(token):
    #If we've just entered information, it will use that information to check if user exists
    if request.method == "POST":
        email = s.loads(token, salt='email-confirm', max_age=3600)
        password = request.form["password"]
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        stmt = (db.update(users).where(users.email==email).values(hash=hashed))
        db.session.execute(stmt)
        db.session.commit()
        
        flash("Password has been successfully reset!")
        return redirect(url_for("home")) 

    else:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        return render_template("change_pw.html")


#Main creates db table before running Flask
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
