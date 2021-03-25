import json
import requests
import datetime

from flask import Flask, redirect, make_response, render_template, request, url_for, session
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies, unset_access_cookies
)
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client

from models.user import UserModel
from models.log import LogModel
from twilio_credentials import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, SENDER_PHONE_NUMBER
from db import db

app = Flask(__name__)

# configuration settings
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False        # we don't want Flask's modification tracker
app.config['JWT_SECRET_KEY'] = 'mfa-super-secret-key'       # Needs to be super complicated!
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=150)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True                # prevents Cross-Site Request Forgery(CSRF) attack
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['OTP_GENERATION_URL'] = "https://api.generateotp.com/"
app.secret_key = "veryVERYsecret"                           # Needs to be super complicated!

jwt = JWTManager(app)


# loaders go here
# creates table before any command execution
@app.before_first_request
def create_table():
    db.create_all()


# called when NO access tokens are provided
@jwt.unauthorized_loader
def unauthorized_callback(error):
    """no auth header provided"""
    print("Unauthorized Token Loaded!!")
    # return redirect(app.config['BASE_URL'] + '/', 302)
    return redirect(url_for("home"))


# called when wrong tokens are provided
@jwt.invalid_token_loader
def invalid_token_callback(error):
    """Invalid Fresh/Non-Fresh Access token in auth header"""
    print("Invalid Token Loaded!!")
    resp = make_response(redirect(url_for("home")))
    unset_jwt_cookies(resp)
    resp.set_cookie('username', max_age=0)
    return resp, 302


# called when expired access token is provided
@jwt.expired_token_loader
def expired_token_callback(header, payload):
    """Expired auth header"""
    print("Expired Token Loaded!!")
    resp = make_response(redirect(url_for("refresh")))
    unset_access_cookies(resp)
    return resp, 302


# refreshes the access token
@app.route('/token/refresh', methods=['GET'])
@jwt_required(refresh=True)
def refresh():
    """Refreshing expired Access token"""
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    resp = make_response(redirect(url_for("home")))
    set_access_cookies(resp, access_token)
    return resp


def assign_access_refresh_tokens(user_id, url):
    """assigns access & refresh tokens and stores in cookies"""
    access_token = create_access_token(identity=str(user_id), fresh=True)
    refresh_token = create_refresh_token(identity=str(user_id))
    resp = make_response(redirect(url, 302))
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    # resp.set_cookie('username', str(user_id))
    return resp


def unset_jwt():
    """deletes the access and refresh token from cookies"""
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie('locationData', max_age=0)
    unset_jwt_cookies(resp)
    return resp


# homepage: displayed at beginning
@app.route("/")
@jwt_required(optional=True)
def home():
    username = get_jwt_identity()
    if not username:
        return render_template("login.html")
    else:
        return render_template("success.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    """route for login of user"""
    if request.method == "GET":
        return render_template("login.html")            # showing the login page

    if request.method == 'POST':
        username = request.form['username']             # fetching data from html page
        password = request.form['password']

        user = UserModel.find_by_username(username)
        if user:
            if check_password_hash(user.password, password):
                # storing in session; to be stored in db only if otp valid
                session['username'] = username
                session['password'] = password
                session['phone_number'] = user.phone_number
                # if password is correct
                raw_data = request.cookies.get('locationData')
                # fetching location of user
                try:
                    location = json.loads(raw_data)
                except:
                    return render_template("error_page.html")
                # fetching IP of user
                if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
                    session['ip'] = request.environ['REMOTE_ADDR']
                else:
                    session['ip'] = request.environ['HTTP_X_FORWARDED_FOR']

                session['latitude'] = location['latitude']
                session['longitude'] = location['longitude']
                session['time'] = location['time']

                # --- printing for convenience ---
                # print(f"IP Address: {session['ip']}")
                # print(f"Latitude : {latitude}")
                # print(f"Longitude : {longitude}")
                # print(f"Time : {time}")
                # --- could be deleted up to here---

                # ---- checking for safe zone -----
                if safe_zone():
                    save_data_to_db()
                    return assign_access_refresh_tokens(session['username'], url_for("success"))

                # -------- OTP VERIFICATION ---------
                otp_code = request_otp(user.phone_number)  # requesting for generation of otp from third party api
                msg = send_otp(user.phone_number, otp_code)  # sending otp to given number via message
                if msg:  # invalid phone number
                    # error = msg
                    return render_template('register.html',
                                           info="Invalid Phone Number. Please enter valid phone number.")
                # if valid phone number
                return redirect(url_for('validate', phone_number=user.phone_number))
            else:
                return render_template("login.html", info="** Wrong Password...")
        else:
            return render_template("login.html", info="** You are not a registered user. Please Sign Up to continue...")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template("register.html")

    # ----- fetching location of user -----
    raw_data = request.cookies.get('locationData')
    try:
        location = json.loads(raw_data)
    except:
        return render_template("register.html", info="Location access denied. Please enable location to continue...")

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        session['ip'] = request.environ['REMOTE_ADDR']
    else:
        session['ip'] = request.environ['HTTP_X_FORWARDED_FOR']

    session['latitude'] = location['latitude']
    session['longitude'] = location['longitude']
    session['time'] = location['time']

    if request.method == 'POST':
        session['username'] = request.form['username']
        session['password'] = request.form['password']
        session['phone_number'] = request.form['phone_number']

        if UserModel.find_by_username(session['username']):
            return render_template("register.html", info="Username already taken. Please try a new username...")

        # -------- OTP VERIFICATION ---------
        otp_code = request_otp(session['phone_number'])  # requesting for generation of otp from third party api
        msg = send_otp(session['phone_number'], otp_code)  # sending otp to given number via message
        if msg:  # invalid phone number
            return render_template('register.html', info="Invalid Phone Number. Please enter valid phone number.")

        # print(f"Username: {username}")
        # print(f"Password: {password}")
        # print(f"Mobile Number: {phone_number}")  # apply all checks in html file
        # print(f"IP Address: {ip}")
        # print(f"Latitude : {latitude}")
        # print(f"Longitude : {longitude}")
        # print(f"Time : {time}")

        # valid number
        return redirect(url_for('validate'))


@app.route("/success")
@jwt_required()
def success():
    return render_template("success.html")


@app.route('/logout')
@jwt_required()
def logout():
    try:
        log_entries = LogModel.find_log(session['username'], session['time'])
    except:
        return unset_jwt(), 302
    for logout_log in log_entries:
        logout_log.time_end = str(datetime.datetime.now().time())[:5]
        logout_log.save_to_db()

    return unset_jwt(), 302


@app.route('/user-logs')
def user_logs():
    return {'users': [user.json() for user in UserModel.query.all()]}


@app.route("/validate", methods=['GET', 'POST'])
def validate():
    if request.method == "GET":
        return render_template('validate.html', phone_number=session['phone_number'])

    input_otp = request.form['otp_code']
    phone_number = session['phone_number']
    is_valid = validate_otp(input_otp, phone_number)

    if is_valid:
        save_data_to_db()
        return assign_access_refresh_tokens(session['username'], url_for("success"))
    info = "Invalid OTP. Please try again."
    return render_template('validate.html', info=info, phone_number=session['phone_number'])  # redirects to the same url u r in


def safe_zone():
    return True


def request_otp(phone_number):
    print("inside request_otp")
    req = requests.post(f"{app.config['OTP_GENERATION_URL']}/generate", data={"initiator_id": phone_number})

    if req.status_code == 201:
        # OK
        data = req.json()  # converting to json
        return data['code']


def send_otp(phone_number, otp_code):
    print("inside send_otp")
    account_sid = TWILIO_ACCOUNT_SID  # from own twilio_credentials.py
    auth_token = TWILIO_AUTH_TOKEN  # from own twilio_credentials.py
    client = Client(account_sid, auth_token)

    try:
        message = client.messages.create(
            to=f"+91{phone_number}",
            from_=SENDER_PHONE_NUMBER,
            body=f"Your OTP is {otp_code}")

        print(message.sid)
        return None
    except:
        print("invalid phone number")
        return "Invalid phone number"


def validate_otp(otp_code, phone_number):
    req = requests.post(f"{app.config['OTP_GENERATION_URL']}/validate/{otp_code}/{phone_number}")
    print(f"code: {req.status_code}")
    # data = req.json()
    # print(data['message'])

    if req.status_code == 200:
        print("ok")
        # OK
        data = req.json()
        print(data)
        return data['status']


def save_data_to_db():
    """function to interact with database"""
    if not UserModel.find_by_username(session['username']):
        new_user = UserModel(
            session['username'], generate_password_hash(session['password']), session['phone_number'],
            None, None, None, None, None
        )
        new_user.save_to_db()

    log = LogModel(
        session['username'], session['ip'], session['latitude'],
        session['longitude'], session['time'], None
    )
    log.save_to_db()


if __name__ == '__main__':
    db.init_app(app)
    app.run(port=5000, debug=True)
