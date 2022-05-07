from flask import Blueprint, redirect, url_for, render_template, flash, request
from flask_login import current_user, login_required, login_user, logout_user

from .. import bcrypt
from ..forms import RegistrationForm, LoginForm, UpdateUsernameForm
from ..models import User

users = Blueprint("users", __name__)

@users.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated():
        return redirect(url_for("movies.index"))
    temp_form = RegistrationForm()
    if temp_form.validate_on_submit():
        encrypted = bcrypt.generate_password_hash(temp_form.password.data).decode("utf-8")
        user = User(username=temp_form.username.data, email=temp_form.email.data, password=encrypted)
        user.save()
        return redirect(url_for("users.login"))
    return render_template(url_for("register.html", title="Register", form=temp_form))

@users.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated():
        return redirect(url_for("movies.index"))
    temp_form = LoginForm()
    if temp_form.validate_on_submit():
        user = User.objects(username=temp_form.username.data).first()
        if user is not None and bcrypt.check_password_hash(user.password, temp_form.password.data):
            login_user(user)
            return redirect(url_for("users.account"))
        else:
            flash("Invalid username or password")
            return redirect(url_for("users.login"))
    return render_template("login.html", title="Login", form=temp_form)

@users.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("movies.index"))

@users.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user_form = UpdateUsernameForm()
    if user_form.validate_on_submit():
        current_user.modify(username=user_form.username.data)
        current_user.save()
        return redirect(url_for("users.account"))
    return render_template("account.html", title="Account", username_form=user_form)
