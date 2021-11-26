from flask import Flask, render_template, url_for, redirect, request, session
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
import random

#Flask and sqlalchemy stuff initialized here
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "AJHHJAKKHJASKHJDKAJHJHELPHKFHJAKSASHJKADHJKHJKASHJKSAHDSJA"

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
    password = db.Column(db.String(100))
    user_id = db.Column(db.String(10))
    saving_balance = db.Column(db.String(10))
    saving_acc_no = db.Column(db.String(10))
    checking_balance = db.Column(db.String(10))
    checking_acc_no = db.Column(db.String(10))

    def __init__(self, first_name, middle_name, last_name, ssn, username, email, password, user_id, saving_balance, saving_acc_no, checking_balance, checking_acc_no):
        self.first_name = first_name
        self.middle_name = middle_name
        self.last_name = last_name
        self.ssn = ssn
        self.username = username
        self.email = email
        self.password = password
        self.user_id = user_id
        self.saving_balance = saving_balance
        self.saving_acc_no = saving_acc_no
        self.checking_balance = checking_balance
        self.checking_acc_no = checking_acc_no

# Stands for "parent-child relation"
class pcr(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    # Represents the parent and child id's, respectively
    parent = db.Column(db.Integer) 
    child = db.Column(db.Integer)
    
    def __init__(self, parent_id, child_id):
        self.parent = parent_id
        self.child = child_id

#Home page
@app.route("/", methods=["POST", "GET"])
def home():
    return render_template("index.html")


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


        #If duplicate account found
        found_user = users.query.filter_by(username=username).first()
        if found_user:
            flash("Account with same username already exists.")
            return redirect(url_for("create")) 

        #Can create new user instance
        usr = users(first_name, middle_name, last_name, ssn, username, email, password, random.randint(0, 9999999999), 0, random.randint(0, 9999999999), 0, random.randint(0, 9999999999))
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

        return redirect(url_for("user", user_id=user_id))
    #If we enter this page without filling form, check if user is already logged in
    #If so, log out, otherwise show create form
    else:
        if "username" in session:
            end_session()
        return render_template("create.html")


#Login page
@app.route("/login", methods=["POST", "GET"])
def login():
    #If we've just entered information, it will use that information to check if user exists
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        #Check if name existed
        found_user = users.query.filter_by(username=username).first()
        #If found, check if password is correct
        if password != found_user.password:
            flash("Username or password is incorrect. Try again.")
            return redirect(url_for("login")) 
        #If password is correct, add user's info to session, then go to the page
        if found_user:
            session["first_name"] = found_user.first_name
            session["middle_name"] = found_user.middle_name
            session["last_name"] = found_user.last_name
            session["ssn"] = found_user.ssn
            session["username"] = username
            session["email"] = found_user.email
            session["password"] = found_user.password
            session["user_id"] = found_user.user_id
            session["saving_balance"] = found_user.saving_balance
            session["saving_acc_no"] = found_user.saving_acc_no
            session["checking_balance"] = found_user.checking_balance
            session["checking_acc_no"] = found_user.checking_acc_no

            return redirect(url_for("user", user_id=session["user_id"]))
        #Otherwise, let the user know they have entered wrong information
        else:
            flash("Username or password is incorrect. Try again.")
            return redirect(url_for("login")) 

    #If we enter this page without filling form, check if user is already logged in
    #If so, return user, otherwise show login form
    else:
        if "username" in session:
            return redirect(url_for("user", user_id=session["user_id"]))
        return render_template("login.html")


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
        saving_balance = session["saving_balance"]
        saving_acc_no = session["saving_acc_no"]
        checking_balance = session["checking_balance"]
        checking_acc_no = session["checking_acc_no"]

        return render_template("user.html", first_name=first_name, middle_name=middle_name, last_name=last_name, ssn=ssn, username=username, email=email, password=password, user_id=user_id, saving_balance=saving_balance, saving_acc_no=saving_acc_no, checking_balance=checking_balance, checking_acc_no=checking_acc_no)
    #If there is no session, make user log in
    else:
        return redirect(url_for("login"))


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



#Main creates db table before running Flask
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)