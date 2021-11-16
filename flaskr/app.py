from flask import Flask, redirect, render_template, url_for
# from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
# app.config['AQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# db = SQLAlchemy(app)

# class users(db.Model):
#     _id = db.Column("id", db.Integer, primary_key=True)
#     fname = db.Column(db.String(100))

#     def __init__(self, fname):
#         self.fname = fname

'''Database info

-First Name -> This is for member dashboard
-Last Name -> This is for member dashboard
-User Name -> This is for logging in
-User ID -> This is for URLs
-Checking Account Number
-Saving Account Number
-Checking Balance
-Saving Balane

'''

test_db = [["Joe", "Mama", "jmama", "6688846993", "12345", "54321", "0.69", "420"],
            ["Brendon", "Hmmmp", "bhmmmp", "1111111111", "12346", "64321", "0.70", "421"]]

@app.route('/')
def index():
    return render_template('index.html', db = test_db)


@app.route('/create')
def create():
    return render_template('create.html')


@app.route('/forgot_pwd')
def forgot_pwd():
    return render_template('forgot_pwd.html')


@app.route('/profile/<int:uid>', methods=["GET"])
def profile(uid):
    return render_template('profile.html', db = test_db, uid=str(uid))


if __name__ == "__main__":
    # db.create_all()
    import database
    app.register_blueprint(database.bp)
    import auth 
    app.register_blueprint(auth.bp)
    # database.init_db()
    app.run(debug=True)

