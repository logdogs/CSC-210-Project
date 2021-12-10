from operator import length_hint
from flask import Flask, render_template, url_for, redirect, request, session, abort
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user
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

run_first = True

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

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)
#Database model class. Can add more columns for more properties
class users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    ssn = db.Column(db.String(9))
    username = db.Column(db.String(100))
    email = db.Column(db.String(100))
    hash = db.Column(db.String(100))
    uid = db.Column(db.String(10))
    saving_balance = db.Column(db.String(10))
    saving_acc_no = db.Column(db.String(10))
    checking_balance = db.Column(db.String(10))
    checking_acc_no = db.Column(db.String(10))
    otp_secret = db.Column(db.String(16))

    def __init__(self, first_name, middle_name, last_name, ssn, username, email, hash, uid, saving_balance, saving_acc_no, checking_balance, checking_acc_no, otp_secret):
        self.first_name = first_name
        self.middle_name = middle_name
        self.last_name = last_name
        self.ssn = ssn
        self.username = username
        self.email = email
        self.hash = hash
        self.uid = uid
        self.saving_balance = saving_balance
        self.saving_acc_no = saving_acc_no
        self.checking_balance = checking_balance
        self.checking_acc_no = checking_acc_no
        self.otp_secret = otp_secret
    @login_manager.user_loader
    def load_user(uid):
        return users.query.get(uid)
    def get_totp_uri(self):
        return 'otpauth://totp/CCE:{0}?secret={1}&issuer=CCE' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):   
        return onetimepass.valid_totp(token, self.otp_secret,window=2)
# Stands for "parent-child relation"
class pcr(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    # Represents the parent and child id's, respectively
    parent = db.Column(db.Integer) 
    child = db.Column(db.Integer)
    
    def __init__(self, parent_id, child_id):
        self.parent = parent_id
        self.child = child_id

class child_limits(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    child = db.Column(db.String(9))
    saving_spending_limit = db.Column(db.String(10))
    checking_spending_limit = db.Column(db.String(10))
    saving_spent = db.Column(db.String(10))
    checking_spent = db.Column(db.String(10))

    def __init__(self, child, saving_spending_limit, checking_spending_limit):
        self.child = child
        self.saving_spending_limit = saving_spending_limit
        self.checking_spending_limit = checking_spending_limit
        self.saving_spent = "0"
        self.checking_spent = "0"

#wtforms login 
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    pin = StringField('Token', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Submit')

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
        uid = found_user.uid
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
        session["uid"] = uid
        session["saving_balance"] = saving_balance
        session["saving_acc_no"] = saving_acc_no
        session["checking_balance"] = checking_balance
        session["checking_acc_no"] = checking_acc_no
        
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
@app.route('/login')
def login():
    form = LoginForm(request.method)
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        pin = form.pin.data
        remember = True if request.form.get('remember') else False

        found_user = users.query.filter_by(username=username).first()
        if not bcrypt.checkpw(password.encode('utf-8'), found_user.hash) or \
            not found_user.verify_totp(pin):
                flash('Invalid username, password or token.')
                return redirect(url_for('login'))
        if found_user:
            login_user(found_user, remember=remember)
            return redirect(url_for("user", uid=session["uid"]))
        #Otherwise, let the user know they have entered wrong information

    return render_template('login.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_post():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            pin = form.pin.data
            remember = True if request.form.get('remember') else False
            found_user = users.query.filter_by(username=username).first()
            if users is None or not bcrypt.checkpw(password.encode('utf-8'), found_user.hash) or \
                not found_user.verify_totp(pin):
                    flash('Invalid username, password or token.')
                    return redirect(url_for('login'))
            if found_user:
                login_user(found_user, remember=remember)
                session["first_name"] = found_user.first_name
                session["middle_name"] = found_user.middle_name
                session["last_name"] = found_user.last_name
                session["ssn"] = found_user.ssn
                session["username"] = form.username
                session["email"] = found_user.email
                session["password"] = found_user.hash
                session["uid"] = found_user.uid
                session["saving_balance"] = found_user.saving_balance
                session["saving_acc_no"] = found_user.saving_acc_no
                session["checking_balance"] = found_user.checking_balance
                session["checking_acc_no"] = found_user.checking_acc_no
                return redirect(url_for("user", uid=session["uid"]))
            #Otherwise, let the user know they have entered wrong information
        else:
                flash("Invalid username, password or token.")
                return render_template('login.html', form=form)
    else:
        if "username" in session:
            return redirect(url_for("user", uid=session["uid"]))
        return render_template('login.html', form=form)

#Home page
@app.route("/", methods=["POST", "GET"])
def home():
    if run_first:
        end_session()
    if "username" in session:
        return redirect(url_for("user", uid=session["uid"]))
    return render_template("index.html")


#User dashboard. All information for users will be displayed here.
# @app.route("/", methods=["POST", "GET"])
@app.route("/user/<uid>", methods=["POST", "GET"])
def user(uid):
    #If there is session, get info from that user
    if "username" in session:
        child_relation = pcr.query.filter_by(child=session['ssn']).first()
        print(child_relation)
        if child_relation is None:
            first_name = session["first_name"]
            middle_name = session["middle_name"]
            last_name = session["last_name"]
            ssn = session["ssn"]
            username = session["username"]
            email = session["email"]
            password = session["password"]
            uid = session["uid"]
            # Want to reload the saving_balance and checking_balance
            updated_user = users.query.filter_by(ssn=ssn).first()

            session["saving_balance"] = updated_user.saving_balance
            session["checking_balance"] = updated_user.checking_balance
            session["ssn"] = updated_user.ssn
            saving_balance = session["saving_balance"]
            saving_acc_no = session["saving_acc_no"]
            checking_balance = session["checking_balance"]
            checking_acc_no = session["checking_acc_no"]

            # Get the children of the user
            children = pcr.query.filter_by(parent=ssn).all()
            print(children)

            return render_template("user.html", first_name=first_name, middle_name=middle_name, last_name=last_name, ssn=ssn, username=username, email=email, password=password, uid=uid, saving_balance=saving_balance, saving_acc_no=saving_acc_no, checking_balance=checking_balance, checking_acc_no=checking_acc_no, children=children)
        else:
            first_name = session["first_name"]
            middle_name = session["middle_name"]
            last_name = session["last_name"]
            ssn = session["ssn"]
            username = session["username"]
            email = session["email"]
            password = session["password"]
            uid = session["uid"]
            # Want to reload the saving_balance and checking_balance
            updated_user = users.query.filter_by(username=username).first()

            session["saving_balance"] = updated_user.saving_balance
            session["checking_balance"] = updated_user.checking_balance
            session["ssn"] = updated_user.ssn
            saving_balance = session["saving_balance"]
            saving_acc_no = session["saving_acc_no"]
            checking_balance = session["checking_balance"]
            checking_acc_no = session["checking_acc_no"]

            # Get the relations relevant to children accounts
            limits = child_limits.query.filter_by(child=ssn).first()

            return render_template("child_user.html", first_name=first_name, middle_name=middle_name, last_name=last_name, ssn=ssn, username=username, email=email, password=password, uid=uid, saving_balance=saving_balance, saving_acc_no=saving_acc_no, checking_balance=checking_balance, checking_acc_no=checking_acc_no, saving_spending_limit=limits.saving_spending_limit, checking_spending_limit=limits.checking_spending_limit, checking_spent=limits.checking_spent, saving_spent=limits.saving_spent)
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
        password = request.form['password']
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

        saving_spending_limit = request.form['saving_spending_limit']
        checking_spending_limit = request.form['checking_spending_limit']
        
        # Make sure they didn't re-add their child
        forgotten_child = users.query.filter_by(ssn=social).first()
        if forgotten_child:
            flash("Child account already exists.")
            return render_template("create_child.html")

        # Create and add the child to the database
        child = users(firstName, middleName, lastName, social, username, mail, hashed, random.randint(0, 9999999999), 0, random.randint(0, 9999999999), 0, random.randint(0, 9999999999), otp_secret)
        db.session.add(child)
        # Find the parent, create the relation between them and their child, then add that to the database
        parent = users.query.filter_by(ssn=parent_social).first()
        parent_child_rel = pcr(parent.ssn, social)
        db.session.add(parent_child_rel)

        # Set the limits
        limits = child_limits(social, saving_spending_limit, checking_spending_limit)
        db.session.add(limits)

        db.session.commit()
        return render_template("child_successfully_created.html")

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
    user = users.query.filter_by(ssn=session['ssn']).first()
    current_amount = user.saving_balance
    updated_amount = str(float(current_amount) + float(request.form['amount']))
    stmt = (db.update(users).where(users.ssn==user.ssn).values(saving_balance=updated_amount))
    db.session.execute(stmt)
    db.session.commit()
    return render_template("successful_add.html")

@app.route("/transferChecking", methods=["POST", "GET"])
def transferChecking():
    
    return render_template("checking_transfer.html")
@app.route("/transferSavings", methods=["POST", "GET"])
def transferSavings():
    
    return render_template("savings_transfer.html")

@app.route("/savings_transfer_deposit", methods=["POST", "GET"])
def savings_transfer_deposit():
    # Make sure the recipient exists
    recipient = users.query.filter_by(username=request.form["recipient"]).first()
    if recipient is None:
        return render_template("transfer_recipient_error.html")
    # Recipient is found
    # Now check to make sure that the amount they want to transfer is less than or equal to their balance
    if recipient.saving_balance > request.form['amount']:
        return render_template("transfer_amount_error.html")
    
    # Check if the user is a child
    is_child = pcr.query.filter_by(child=session['ssn']).first()
    if is_child is not None:
        # Check the limit and amount spent alread
        limit = child_limits.query.filter_by(child=session['ssn']).first()
        if limit.saving_spent + request.form['amount'] > limit.saving_spending_limit:
            return render_template("transfer_amount_error.html")
        
    # Amount to transfer is acceptable, now make the transaction
    # Take the money out of the session account
    updated_giver_amount = str(float(session['saving_balance']) - float(request.form['amount']))
    session['saving_balance'] = updated_giver_amount
    stmt = (db.update(users).where(users.ssn==session['ssn']).values(saving_balance=updated_giver_amount))
    db.session.execute(stmt)
    updated_recipient_amount = str(float(recipient.saving_balance) + float(request.form['amount']))
    stmt = (db.update(users).where(users.ssn==recipient.ssn).values(saving_balance=updated_recipient_amount))
    db.session.execute(stmt)
    if is_child is not None:
        stmt = (db.update(child_limits).where(child_limits.child==session['ssn']).values(checking_spent=str(float(limit.checking_spent)+float(request.form['amount']))))
        db.session.execute(stmt)
    db.session.commit()
    return render_template("successful_transfer.html")

@app.route("/checking_transfer_deposit", methods=["POST", "GET"])
def checking_transfer_deposit():
    # Make sure the recipient exists
    recipient = users.query.filter_by(username=request.form["recipient"]).first()
    if recipient is None:
        return render_template("transfer_recipient_error.html")
    # Recipient is found
    # Now check to make sure that the amount they want to transfer is less than or equal to their balance
    if recipient.saving_balance > request.form['amount']:
        return render_template("transfer_amount_error.html")

    # Check if it's a child
    is_child = pcr.query.filter_by(child=session['ssn']).first()
    limit = None
    if is_child is not None:
        # Check to make sure they won't exceed their limit
        limit = child_limits.query.filter_by(child=session['ssn']).first()
        if limit.checking_spent + request.form['amount'] > limit.checking_spending_limit:
            return render_template("transfer_amount_error.html")
    # Amount to transfer is acceptable, now make the transaction
    # Take the money out of the session account
    updated_giver_amount = str(float(session['saving_balance']) - float(request.form['amount']))
    session['saving_balance'] = updated_giver_amount
    stmt = (db.update(users).where(users.ssn==session['ssn']).values(saving_balance=updated_giver_amount))
    db.session.execute(stmt)
    updated_recipient_amount = str(float(recipient.saving_balance) + float(request.form['amount']))
    stmt = (db.update(users).where(users.ssn==recipient.ssn).values(saving_balance=updated_recipient_amount))
    db.session.execute(stmt)
    if is_child is not None:
        # Update the saving
        stmt = (db.update(child_limits).where(child_limits.child==session['ssn']).values(saving_spent=str(float(limit.saving_spent)+float(request.form['amount']))))
        db.execute(stmt)
    db.session.commit()
    return render_template("successful_transfer.html")

#Pops everything from session
def end_session():
    session.pop("first_name", None)
    session.pop("middle_name", None)
    session.pop("last_name", None)
    session.pop("ssn", None)
    session.pop("username", None)
    session.pop("email", None)
    session.pop("hashed", None)
    session.pop("uid", None)
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

            msg = Message('CCE Reset Password', sender='ccebankrochester@gmail.com', recipients=[email])
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
