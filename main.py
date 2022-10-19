import os
from flask import Flask, flash, render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.dialects.sqlite.json import JSON
from json import dumps, loads
import imghdr

# SETUP
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config["SECRET_KEY"] = "abcxyz"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['UPLOAD_FOLDER'] = 'static/pfps'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.debug = True

def allowed_file(file):
    return '.' in file and \
           file.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return '.' + (format if format != 'jpeg' else 'jpg')

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

def calculate_score():
    current_user.score = 0
    for i in range(0, 126, 2):
        if real_scores[i] == preDICTions["payload"][i] and real_scores[i+1] == preDICTions["payload"][i+1]:
            current_user.score += 3
        elif real_scores[i] > real_scores[i+1] and preDICTions["payload"][i] > preDICTions["payload"][i+1]:
            current_user.score += 1
        elif real_scores[i] < real_scores[i+1] and preDICTions["payload"][i] < preDICTions["payload"][i+1]:
            current_user.score += 1
        elif real_scores[i] == real_scores[i+1] and preDICTions["payload"][i] == preDICTions["payload"][i+1]: 
            current_user.score += 1

real_scores = [0] * 126
groupstagecountries = [
"Qatar", "Ecuador", "Senegal", "Netherlands", "Qatar", "Senegal", "Netherlands", "Ecuador", "Netherlands", "Qatar", "Ecuador", "Senegal",
"England", "Iran", "USA", "Wales", "Wales", "Iran", "England", "USA", "Wales", "England", "Iran", "USA", 
"Argentina", "Saudi Arabia", "Mexico", "Poland", "Poland", "Saudi Arabia", "Argentina", "Mexico", "Poland", "Argentina", "Saudi Arabia", "Mexico",
"Denmark", "Tunisia", "France", "Australia", "Tunisia", "Australia", "France", "Denmark", "Tunisia", "France", "Australia", "Denmark",
"Germany", "Japan", "Spain", "Costa Rica", "Japan", "Costa Rica", "Spain", "Germany", "Japan", "Spain", "Costa Rica", "Germany",
"Morocco", "Croatia", "Belgium", "Canada", "Belgium", "Morocco", "Croatia", "Canada", "Croatia", "Belgium", "Canada", "Morocco",
"Switzerland", "Cameroon", "Brazil", "Serbia", "Cameroon", "Serbia", "Brazil", "Switzerland", "Cameroon", "Brazil", "Serbia", "Switzerland",
"Uruguay", "South Korea", "Portugal", "Ghana", "South Korea", "Ghana", "Portugal", "Uruguay", "South Korea", "Portugal", "Ghana", "Uruguay", 
]
roundof16countries = ["test1", "test2", "test3", "test4", "test1", "test2", "test3", "test4", "test1", "test2", "test3", "test4",
"test1", "test2", "test3", "test4"]
quarterfinalcountries = ["test1", "test2", "test3", "test4", "test1", "test2", "test3", "test4"]
semifinalcountries = ["test1", "test2", "test3", "test4"]
finalcountries = ["test1", "test2"]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(20))
    predictions = db.Column(JSON)
    score = db.Column(db.Integer)
    position = db.Column(db.Integer)
    image = db.Column(db.String(100))

db.create_all()  # This is required on first-time ONLY   

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        #if password reset:
        #    current_user.password = generate_password_hash(password, salt_length=8, method="pbkdf2:sha256")

        user_obj = User.query.filter_by(email=email).first()

        if user_obj is None:
            return render_template("home.html", error="That email is not registered.")

        elif check_password_hash(user_obj.password, password):
            login_user(user_obj)
            return redirect(url_for("submitted"))

        else:
            return render_template("login.html", error="That password is incorrect.")

    return render_template("login.html")

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    global user
    if request.method == "POST":
        email = request.form['email']
        username = email[0: email.index('@')]
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if User.query.filter_by(email=email).first() is not None:
            return render_template("signup.html", error="That email is already in use, please login or use another one.")

        if password != confirm_password:
            return render_template("signup.html", error="The password does not match the confirmation password.")

        preDICTions = {"payload": [0] * 126}
      
        user = User(
            email=email, username=username, password=generate_password_hash(password, salt_length=8, method="pbkdf2:sha256"), predictions=dumps(preDICTions),
            score=0, position=0, image="pfp.png"
        )

        db.session.add(user)  # Add user temporarily
        db.session.commit()  # Add user permanently

        login_user(user)
        return redirect(url_for("submitted"))

    return render_template("signup.html")

@app.route("/forgotpassword", methods=['GET', 'POST'])
def forgotpassword():
    if request.method == "POST":
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            return render_template("signup.html", error="The password does not match the confirmation password.")

        current_user.password = password
        return redirect(url_for("submitted", username=username, predictions=preDICTions['payload'], score=current_user.score, position=position))
    return render_template("forgotpassword.html")

@app.route("/submitted", methods=['GET', 'POST'])
@login_required
def submitted():
    global preDICTions, username, position
    username = current_user.username
    position = current_user.position
    preDICTions = loads(current_user.predictions)
    calculate_score()
    if request.method == "POST":
        for num, i in enumerate(request.form):
            preDICTions['payload'][num] = request.form[i]

        current_user.predictions = dumps(preDICTions)
        db.session.commit()
        return render_template("submitted.html", username=username, predictions=preDICTions['payload'], score=current_user.score, position=position)

    return render_template("groupstages.html", username=username, predictions=preDICTions['payload'], score=current_user.score, countries=groupstagecountries)

@app.route("/leaderboard", methods=['GET', 'POST'])
@login_required
def leaderboard():
    sorted_records = User.query.order_by(User.score).all()[::-1]
    return render_template("leaderboard.html", username=username, score=current_user.score, position=position, records=sorted_records)


@app.route("/settings", methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file_ext = os.path.splitext(filename)[1]
        if file and allowed_file(filename) and file_ext != validate_image(file.stream):
            file.save(os.path.join("static/pfps", current_user.get_id()))
            return redirect(url_for('settings'))
        print("Not an accepted file type.")
    return render_template("settings.html", username=username, score=current_user.score, position=position, image=current_user.image)
        

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0")
    except:
        pass