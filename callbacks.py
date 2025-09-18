import random
import string
from datetime import datetime, timedelta

from jose import jwt
import requests
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

import config
from cache import h_card_cache
from config import (EMAIL_SENDER, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET,
                    GITHUB_OAUTH_REDIRECT, POSTMARK_API_KEY, MASTODON_CLIENT_ID, MASTODON_OAUTH_REDIRECT,
                    TUMBLR_CLIENT_ID, TUMBLR_CLIENT_SECRET, TUMBLR_OAUTH_REDIRECT)
from forms import EmailVerificationCode
from helpers import is_authenticated_as_allowed_user
from urllib.parse import urlparse as parse_url

callbacks = Blueprint("callbacks", __name__)

@callbacks.route("/auth/wikimedia")
def wikimedia_auth():
    session["wikimedia_state"] = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(32)
    )
    print(session["wikimedia_state"])

    return redirect(
        f"https://en.wikipedia.org/w/rest.php/oauth2/authorize?client_id={config.MEDIAWIKI_CLIENT_ID}&redirect_uri={config.MEDIAWIKI_OAUTH_REDIRECT}&response_type=code&state={session['wikimedia_state']}"
    )


@callbacks.route("/auth/wikimedia/callback")
def wikimedia_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("wikimedia_state"):
        return redirect("/login")

    session.pop("wikimedia_state")

    r = requests.post(
        f"https://en.wikipedia.org/w/rest.php/oauth2/access_token",
        data={
            "client_id": config.MEDIAWIKI_CLIENT_ID,
            "client_secret": config.MEDIAWIKI_CLIENT_SECRET,
            "code": access_token,
            "redirect_uri": config.MEDIAWIKI_OAUTH_REDIRECT,
            "grant_type": "authorization_code",
        },
        headers={"User-Agent": "Alto/1.0 (https://alto.jamesg.blog)"}
    )

    if not r.json().get("access_token"):
        flash({"message": "There was an error authenticating with MediaWiki.", "type": "fail"})
        return redirect("/login")
    
    print('dddd', r.json()['access_token'])

    user_request = requests.get(
        "https://en.wikipedia.org/w/rest.php/oauth2/resource/profile",
        headers={"Authorization": f"Bearer {r.json()['access_token']}", "User-Agent": "Alto/1.0 (https://alto.jamesg.blog)"}
    )

    if user_request.status_code != 200:
        flash({"message": "There was an error authenticating with MediaWiki.", "type": "fail"})
        return redirect("/login")

    me_url = "https://en.wikipedia.org/wiki/User:" + user_request.json().get("username")

    signed_in_with_correct_user = is_authenticated_as_allowed_user(
        session.get("rel_me_check"), me_url
    )

    if signed_in_with_correct_user is False:
        flash({"message": "You are not signed in with the correct user.", "type": "fail"})
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")

@callbacks.route("/auth/tumblr")
def tumblr_auth():
    session["tumblr_state"] = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(32)
    )

    return redirect(
        f"https://www.tumblr.com/oauth2/authorize?client_id={config.TUMBLR_CLIENT_ID}&redirect_uri={config.TUMBLR_OAUTH_REDIRECT}&response_type=code&state={session['tumblr_state']}&scope=basic"
    )


@callbacks.route("/auth/tumblr/callback")
def tumblr_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("tumblr_state"):
        return redirect("/login")

    session.pop("tumblr_state")

    r = requests.post(
        f"https://api.tumblr.com/v2/oauth2/token?client_id={TUMBLR_CLIENT_ID}&client_secret={TUMBLR_CLIENT_SECRET}&code={access_token}&redirect_uri={TUMBLR_OAUTH_REDIRECT}&grant_type=authorization_code",
        headers={"Accept": "application/json"},
    )

    if not r.json().get("access_token"):
        flash({"message": "There was an error authenticating with Tumblr.", "type": "fail"})
        return redirect("/login")

    user_request = requests.get(
        "https://api.tumblr.com/v2/user/info",
        headers={"Authorization": f"Bearer {r.json()['access_token']}"},
    )

    if user_request.status_code != 200:
        flash({"message": "There was an error authenticating with Tumblr.", "type": "fail"})
        return redirect("/login")

    me_url = "https://tumblr.com/" + user_request.json().get("response").get("user").get("name")

    signed_in_with_correct_user = is_authenticated_as_allowed_user(
        session.get("rel_me_check"), me_url
    )

    if signed_in_with_correct_user is False:
        flash({"message": "You are not signed in with the correct user."})
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")

@callbacks.route("/auth/mastodon")
def mastodon_auth():
    state = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(32)
    )
    url = request.args.get("url")

    instance = parse_url(url).netloc
    username = parse_url(url).path.strip("/")
    
    session["mastodon_state"] = state
    session["mastodon_instance"] = instance
    session["mastodon_username"] = username

    return redirect(
        f"https://{instance}/oauth/authorize?client_id={MASTODON_CLIENT_ID}&scope=profile&redirect_uri={MASTODON_OAUTH_REDIRECT}&response_type=code&state={state}"
    )

@callbacks.route("/auth/mastodon/callback")
def mastodon_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("mastodon_state"):
        return redirect("/login")

    session.pop("mastodon_state")

    r = requests.post(
        f"https://{session.get('mastodon_instance')}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": MASTODON_CLIENT_ID,
            "client_secret": config.MASTODON_CLIENT_SECRET,
            "redirect_uri": MASTODON_OAUTH_REDIRECT,
            "code": access_token,
        },
        headers={"Accept": "application/json"},
    )

    if not r.json().get("access_token"):
        flash({"message": "There was an error authenticating with Mastodon."})
        return redirect("/login")


    user_request = requests.get(
        f"https://{session.get('mastodon_instance')}/api/v1/accounts/verify_credentials",
        headers={"Authorization": f"Bearer {r.json()['access_token']}"},
    )

    if user_request.status_code != 200:
        flash({"message": "There was an error authenticating with Mastodon."})
        return redirect("/login")

    user = user_request.json()

    me = user.get("username")
    me_url = "https://" + session.get("mastodon_instance") + "/" + "@" + me

    signed_in_with_correct_user = is_authenticated_as_allowed_user(
        session.get("rel_me_check"), me_url
    )

    if signed_in_with_correct_user is False:
        flash({"message": "You are not signed in with the correct user."})
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")

@callbacks.route("/auth/github")
def github_auth():
    state = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(32)
    )
    session["github_state"] = state
    return redirect(
        f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_OAUTH_REDIRECT}&state={state}"
    )


@callbacks.route("/auth/github/callback")
def github_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("github_state"):
        return redirect("/login")

    session.pop("github_state")

    r = requests.post(
        f"https://github.com/login/oauth/access_token?client_id={GITHUB_CLIENT_ID}&client_secret={GITHUB_CLIENT_SECRET}&code={access_token}&redirect_uri={GITHUB_OAUTH_REDIRECT}",
        headers={"Accept": "application/json"},
    )

    if not r.json().get("access_token"):
        flash({"message": "There was an error authenticating with GitHub."})
        return redirect("/login")

    user_request = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {r.json()['access_token']}"},
    )

    if user_request.status_code != 200:
        flash({"message": "There was an error authenticating with GitHub."})
        return redirect("/login")

    user = user_request.json()

    me = user.get("login")
    me_url = "https://github.com/" + me

    signed_in_with_correct_user = is_authenticated_as_allowed_user(
        session.get("rel_me_check"), me_url
    )

    if signed_in_with_correct_user is False:
        flash({"message": "You are not signed in with the correct user.", "type": "fail"})
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")


@callbacks.route("/callbacks/verify_email")
def verify_email():
    token = request.args.get("token")
    if not token:
        flash({"message": "There was an error verifying your email."})
        return redirect("/login")

    try:
        decoded_token = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as e:
        flash({"message": "The verification link has expired. Please try signing in again."})
        return redirect("/login")
    except jwt.InvalidTokenError:
        flash({"message": "The verification link is invalid. Please try signing in again."})
        return redirect("/login")

    if decoded_token.get("action") != "email_auth":
        flash({"message": "The verification link is invalid. Please try signing in again."})
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")


@callbacks.route("/auth/email", methods=["GET", "POST"])
def email_auth():
    email_verification_form = EmailVerificationCode()
    no_resend = request.args.get("no_resend")
    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")
    if request.method == "GET":
        me = session.get("rel_me_check")
        email = session.get("rel_me_email")
        # use int for exp and iat
        jwt_payload = {
            "me": me,
            "email": email,
            "action": "email_auth",
            "exp": int((datetime.utcnow() + timedelta(hours=1, minutes=15)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "random": "".join(
                random.choices(string.ascii_uppercase + string.digits, k=12)
            ),
        }

        jwt_token = jwt.encode(jwt_payload, config.SECRET_KEY, algorithm="HS256")

        if no_resend != "true":
            random_code = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=6)
            )
            session["set_email_code"] = random_code
            session["set_email_code_time"] = datetime.utcnow().isoformat()

            message = f"""<p>Hello there,</p>

            <p>Alto wants you to sign in as {me}.</p>

            <p>You can click the link below to sign in, or enter the code below on the Alto sign-in page.</p>

            <p><a href="{request.url_root}callbacks/verify_email?token={jwt_token}">{request.url_root}callbacks/verify_email?token={jwt_token}</a></p>

            <p>Your sign in code is:</p>

            <p><b>{random_code}</b></p>
            """

            url = "https://api.postmarkapp.com/email"

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Postmark-Server-Token": POSTMARK_API_KEY,
            }

            data = {
                "From": EMAIL_SENDER,
                "To": email,
                "Subject": "Sign in with Alto",
                "HtmlBody": message,
                "MessageStream": "outbound",
            }

            try:
                response = requests.post(url, headers=headers, json=data)
                response.raise_for_status()
            except Exception as e:
                print(e)
                flash(
                    {
                        "message": "A passcode email was not sent due to an error. Please try again, or contact support at "
                        + EMAIL_SENDER
                        + ".",
                        "type": "fail",
                    }
                )

        return render_template(
            "authentication_flow/email_auth.html",
            email_verification_form=email_verification_form,
            title="Email Authentication",
            representative_h_card=h_card_cache.get(session.get("rel_me_check")),
        )

    if email_verification_form.validate_on_submit():
        if email_verification_form.code.data == session.get("set_email_code"):
            # if time is more than 5 minutes from set_email_code_time, reject
            code_time = datetime.fromisoformat(session.get("set_email_code_time"))
            if datetime.utcnow() > code_time + timedelta(minutes=5):
                flash({"message": "The code you entered has expired. Please try again."})
                return redirect(url_for("callbacks.email_auth") + "?no_resend=true")
            
            session["me"] = session.get("rel_me_check")
            session["logged_in"] = True
            session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

            if session.get("user_redirect"):
                redirect_uri = session.get("user_redirect")
                session.pop("user_redirect")
                return redirect(redirect_uri)

            return redirect("/")

        else:
            flash({"message": "The code you entered was incorrect. Please try again."})
            return redirect(url_for("callbacks.email_auth") + "?no_resend=true")

