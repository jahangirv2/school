from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, make_response
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")



@app.route("/")
def index():
    """Show portfolio of stocks"""

    # look up the current user
    students_list = db.execute("Select * from students")
    return render_template("test.html", students_list=students_list)

@app.route("/test")
def test():
    students_list = db.execute("Select * from students")
    return render_template("test.html", students_list=students_list)

@app.route('/delete/<string:entry_id>')
def delete_entry(entry_id):
    db.execute("delete from  students where gr_num = :entry_id", entry_id=entry_id)
    students_list = db.execute("Select * from students")
    return render_template("test.html", students_list=students_list)



@app.route("/addStudent", methods=["GET", "POST"])
def addStudent():
    if request.method == "POST":
       new_user_id = db.execute("INSERT INTO students  (gr_num, class_sec, students_name, dob, birth, student_iqama, passport_number, blood_group,       father_name, father_iqama, father_passport, mother_name, mother_iqama, mother_passport, address, telephone, email, relative_name, relative_phone) VALUES (:gr_num, :class_sec, :students_name, :dob, :birth, :student_iqama, :passport_number, :blood_group, :father_name, :father_iqama, :father_passport, :mother_name, :mother_iqama, :mother_passport, :address, :telephone, :email, :relative_name, :relative_phone)",
       gr_num=request.form.get("gr_num"), class_sec=request.form.get("class_sec"), students_name=request.form.get("students_name"),
       dob=request.form.get("dob"), birth=request.form.get("birth"), student_iqama=request.form.get("student_iqama"), passport_number=request.form.get("passport_number"),
       blood_group=request.form.get("blood_group"), father_name=request.form.get("father_name"), father_iqama=request.form.get("father_iqama"),
       father_passport=request.form.get("father_passport"), mother_name=request.form.get("mother_name"), mother_iqama=request.form.get("mother_iqama"),
       mother_passport=request.form.get("mother_passport"), address=request.form.get("address"), telephone=request.form.get("telephone"),
       email=request.form.get("email"), relative_name=request.form.get("relative_name"), relative_phone=request.form.get("relative_phone"))

       if not new_user_id:
        flash("GR already TAKEN!")
        return render_template("addStudent.html")

       flash("Registered!")
       return redirect(url_for("index"))
    else:
        return render_template("addStudent.html")



@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change her password"""

    if request.method == "POST":

        # Ensure current password is not empty
        if not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Query database for user_id
        rows = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("invalid password", 400)

        # Ensure new password is not empty
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure new password confirmation is not empty
        elif not request.form.get("new_password_confirmation"):
            return apology("must provide new password confirmation", 400)

        # Ensure new password and confirmation match
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return apology("new password and confirmation must match", 400)

        # Update database
        hash = generate_password_hash(request.form.get("new_password"))
        rows = db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)

        # Show flash
        flash("Changed!")

    return render_template("change_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect(url_for("index"))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect(url_for("index"))



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password and confirmation match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # hash the password and insert a new user in the database
        hash = generate_password_hash(request.form.get("password"))
        new_user_id = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                                 username=request.form.get("username"),
                                 hash=hash)

        # unique username constraint violated?
        if not new_user_id:
            flash("Registered!")
            return apology("username taken", 400)

        # Remember which user has logged in
        session["user_id"] = new_user_id

        # Display a flash message
        flash("Registered!")

        # Redirect user to home page
        return redirect(url_for("index"))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/students", methods=["GET", "POST"])
def students():
    if request.method == "POST":
       new_user_id = db.execute("INSERT INTO students  (gr_num, class_sec, students_name, dob, birth, student_iqama, passport_number, blood_group,       father_name, father_iqama, father_passport, mother_name, mother_iqama, mother_passport, address, telephone, email, relative_name, relative_phone) VALUES (:gr_num, :class_sec, :students_name, :dob, :birth, :student_iqama, :passport_number, :blood_group, :father_name, :father_iqama, :father_passport, :mother_name, :mother_iqama, :mother_passport, :address, :telephone, :email, :relative_name, :relative_phone)",
       gr_num=request.form.get("gr_num"), class_sec=request.form.get("class_sec"), students_name=request.form.get("students_name"),
       dob=request.form.get("dob"), birth=request.form.get("birth"), student_iqama=request.form.get("student_iqama"), passport_number=request.form.get("passport_number"),
       blood_group=request.form.get("blood_group"), father_name=request.form.get("father_name"), father_iqama=request.form.get("father_iqama"),
       father_passport=request.form.get("father_passport"), mother_name=request.form.get("mother_name"), mother_iqama=request.form.get("mother_iqama"),
       mother_passport=request.form.get("mother_passport"), address=request.form.get("address"), telephone=request.form.get("telephone"),
       email=request.form.get("email"), relative_name=request.form.get("relative_name"), relative_phone=request.form.get("relative_phone"))

       if not new_user_id:
        flash("GR already TAKEN!")
        return render_template("students.html")



       return redirect(url_for("test"))
    else:
        return render_template("students.html")



def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
