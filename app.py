import datetime
import json
import sqlite3
import time
from datetime import timedelta
from urllib.parse import urlparse as parse_url

import indieweb_utils
from jose import jwt
import requests
import random
import string

import validators
from cachetools import TLRUCache
from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, session)

import config
from cache import h_card_cache
from forms import ConfirmAuth
from scopes import SCOPE_DEFINITIONS

def compose_profile_response(me, scope, response={}):
    h_card = h_card_cache.get(me, {})
    if "profile" in scope:
        profile = {}

        if h_card.get("name"):
            profile["name"] = h_card.get("name")
        if h_card.get("photo"):
            profile["photo"] = h_card.get("photo")

        response["profile"] = profile
    # if email in scope
    if "email" in scope and h_card.get("email"):
        if not response.get("profile"):
            response["profile"] = {}

        response["profile"]["email"] = h_card.get("email")

    return response

def datetime_ttu(_key, value, now):
    return now + timedelta(hours=1)


client_information_cache = TLRUCache(
    maxsize=100, ttu=datetime_ttu, timer=datetime.datetime.now
)


app = Blueprint("app", __name__)


@app.route("/")
def index():
    return render_template(
        "index.html",
        AUTH_SERVER_URL=config.AUTH_SERVER_URL,
        TOKEN_SERVER_URL=config.TOKEN_SERVER_URL,
    )

@app.route("/accessibility")
def accessibility():
    return render_template("accessibility.html", title="Accessibility Statement")

@app.route("/sustainability")
def sustainability():
    return render_template("sustainability.html", title="Sustainability")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html", title="Privacy Policy")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("me", None)
    session.pop("h_card", None)
    session.pop("user_redirect", None)
    session.pop("redirect_after_auth", None)
    session.pop("rel_me_check", None)
    flash({"message": "You have been logged out.", "category": "info"})

    return redirect("/")


@app.route("/auth", methods=["GET", "POST"])
def authorization_endpoint():
    confirm_auth_form = ConfirmAuth()

    if request.method == "GET":
        me = request.args.get("me")

        if (
            request.args.get("me")
            and session.get("me")
            and request.args.get("me").strip("/") != session.get("me").strip("/")
        ):
            flash(
                {"message": f"""
                {request.args.get('client_id')} is requesting you to sign in as {request.args.get('me')}.
                Please sign in as {request.args.get('me')}.
            """}
            )
            return redirect(f"/logout?r={request.url}")

        if not session.get("logged_in"):
            return redirect(f"/login?r={request.url}")

        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        response_type = request.args.get("response_type")
        state = request.args.get("state")
        code_challenge = request.args.get("code_challenge")
        code_challenge_method = request.args.get("code_challenge_method")
        scope = request.args.get("scope")

        if not client_id or not redirect_uri or not response_type or not state:
            print("missing data")
            return jsonify({"error": "invalid_request."})

        if response_type != "code" and response_type != "id":
            print("invalid response type")
            return jsonify({"error": "invalid_request"})

        client_id_app = None

        try:
            if validators.url(url, private=False):
                client_id_app = requests.get(client_id)
        except Exception as e:
            pass

        h_app_item = client_information_cache.get(client_id)

        parsed_redirect_uri = parse_url(redirect_uri)
        parsed_client_id = parse_url(client_id)

        redirect_uri_domain = parsed_redirect_uri.netloc
        client_id_domain = parsed_client_id.netloc

        redirect_uri_scheme = parsed_redirect_uri.scheme
        client_id_scheme = parsed_client_id.scheme

        if (
            redirect_uri_domain != client_id_domain
            or redirect_uri_scheme != client_id_scheme
        ):
            confirmed_redirect_uri = False

            links = indieweb_utils.discover_endpoints(client_id, ["redirect_uri"])

            for url in links:
                if url.startswith("/"):
                    url = redirect_uri_scheme + redirect_uri_domain.strip("/") + url

                if url == redirect_uri:
                    confirmed_redirect_uri = True

            if not confirmed_redirect_uri:
                print("not confirmed redirect uri")
                return jsonify({"error": "invalid_request"})

        if not h_app_item and client_id_app and client_id_app.status_code == 200:
            # if client id is json, return it
            if client_id_app.headers.get("Content-Type") == "application/json":
                response = client_id_app.json()
                h_app_item = {
                    "name": response.get("client_name"),
                    "logo": response.get("client_logo"),
                    "url": response.get("client_uri"),
                    "summary": response.get("client_description"),
                }
            elif client_id.endswith("/client.json"):
                if validators.url(client_id, private=False):
                    try:
                        client_file = requests.get(client_id).json()

                        h_app_item = {
                            "logo": client_file["client_logo"],
                            "name": client_file["client_name"],
                            "url": client_file["client_uri"],
                        }
                    except:
                        h_app_item = {}
                else:
                    h_app_item = {}
            else:
                try:
                    response = indieweb_utils.get_h_app_item(client_id_app.text)
                    h_app_item = {
                        "name": response.name,
                        "logo": response.logo,
                        "url": response.url,
                        "summary": response.summary,
                    }
                except:
                    h_app_item = {}

            connection = sqlite3.connect("tokens.db")
            with connection:
                cursor = connection.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO clients (client_id, name, logo, url, summary) VALUES (?, ?, ?, ?, ?)",
                    (
                        client_id,
                        h_app_item.get("name"),
                        h_app_item.get("logo"),
                        h_app_item.get("url"),
                        h_app_item.get("summary"),
                    ),
                )

        if h_app_item:
            client_information_cache[client_id] = h_app_item

        confirm_auth_form.me.data = session.get("me")
        confirm_auth_form.client_id.data = client_id
        confirm_auth_form.redirect_uri.data = redirect_uri
        confirm_auth_form.response_type.data = response_type
        confirm_auth_form.state.data = state
        confirm_auth_form.code_challenge.data = code_challenge
        confirm_auth_form.code_challenge_method.data = code_challenge_method
        confirm_auth_form.scope.data = scope

        return render_template(
            "authentication_flow/confirm_auth.html",
            scope=scope,
            me=me,
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            h_app_item=h_app_item,
            confirm_auth_form=confirm_auth_form,
            SCOPE_DEFINITIONS=SCOPE_DEFINITIONS,
            title=f"Authenticate to {client_id.replace('https://', '').replace('http://', '').strip()}",
        )

    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    try:
        redeem_code = indieweb_utils.redeem_code(
            grant_type,
            code,
            client_id,
            redirect_uri,
            code_verifier,
            config.SECRET_KEY
        )

        access_token = redeem_code.access_token
        scope = redeem_code.scope
        me = redeem_code.me
    except Exception as e:
        print(e)
        return jsonify({"error": "invalid_request"})
    
    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()

        # if the code has already been redeemed, return an error
        existing_token = cursor.execute(
            "SELECT * FROM issued_tokens WHERE redeemed_from_code = ?", (code,)
        ).fetchone()
        if existing_token:
            return jsonify({"error": "invalid_grant"})

        # generate a refresh token as random string
        refresh_token = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=24)
        )
        
        h_app_item = client_information_cache.get(client_id)

        if not h_app_item:
            if validators.url(client_id, private=False):
                try:
                    client_id_app = requests.get(client_id, timeout=5)

                    h_app_item = indieweb_utils.get_h_app_item(client_id_app.text, client_id)
                    client_information_cache[client_id] = h_app_item
                except Exception:
                    pass

        # create table if not exists issued_tokens (encoded_code, h_app, refresh_token, redeemed_from_code);
        cursor.execute(
            "INSERT INTO issued_tokens VALUES (?, ?, ?, ?, ?, ?)",
            (
                access_token,
                json.dumps(h_app_item),
                refresh_token,
                code,
                me,
                int(time.time())
            ),
        )

    response = {"me": me.strip("/") + "/"}

    response = compose_profile_response(me, scope, response)

    return jsonify(response)


@app.route("/issued")
def view_issued_tokens():
    if not session.get("logged_in"):
        return redirect("/login")

    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()
        issued_tokens = cursor.execute(
            "SELECT * FROM issued_tokens WHERE me = ? ORDER BY issued_on DESC",
            (session.get("me"),),
        ).fetchall()

        decoded_tokens = []

        for item in issued_tokens:
            ix = jwt.decode(item[0], config.SECRET_KEY, algorithms=["HS256"], options={'verify_exp': False})
            ix["h-app"] = json.loads(item[1]) if item[1] else {}
            ix["issued_on"] = datetime.datetime.fromtimestamp(item[5]).strftime("%d %b %Y, %H:%M")
            ix["token_encoded"] = item[0]
            ix["scopes"] = ix.get("scope", "").split(" ") if ix.get("scope") else []
            decoded_tokens.append(ix)

    return render_template(
        "admin/issued.html",
        title="Issued Tokens",
        issued_tokens=decoded_tokens,
        SCOPE_DEFINITIONS=SCOPE_DEFINITIONS,
        me=session.get("me"),
    )


@app.route("/generate", methods=["POST"])
def generate_key():
    if session.get("logged_in") != True:
        return redirect(f"/login?r={request.url}")

    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    response_type = request.form.get("response_type")
    state = request.form.get("state")
    code_challenge_method = request.form.get("code_challenge_method")
    scope = request.form.get("scope").lower()
    is_manually_issued = request.form.get("is_manually_issued")

    final_scope = ""

    for item in scope.split(" "):
        if request.form.get(f"scope_{item}"):
            final_scope += f"{item} "

    try:
        response = indieweb_utils.generate_auth_token(
            request.form.get("me"),
            client_id,
            redirect_uri,
            response_type,
            state,
            code_challenge_method,
            final_scope,
            config.SECRET_KEY,
            code_challenge=request.form.get("code_challenge")
        )

        encoded_code = response.code
    except Exception as e:
        print(e)
        return jsonify({"error": "invalid_request"})

    if is_manually_issued and is_manually_issued == "true":
        flash(
            {"message": f"Your token was successfully issued. Your new token is: {encoded_code}"}
        )
        return redirect("/issued")

    return redirect(redirect_uri.strip("/") + f"?code={encoded_code}&state={state}&iss={config.BASE_URL}")


@app.route("/token", methods=["POST"])
def token_endpoint():
    grant_type = request.form.get("grant_type")
    refresh_token = request.form.get("refresh_token")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    if grant_type == "refresh_token":
        db = sqlite3.connect("tokens.db")
        with db:
            cursor = db.cursor()

            issued_tokens = cursor.execute(
                "SELECT * FROM issued_tokens WHERE refresh_token = ?", (me,)
            ).fetchone()

            if not issued_tokens:
                return jsonify({"error": "invalid_grant"})

            me = issued_tokens[1]
            client_id = issued_tokens[3]
            scope = issued_tokens[6]

            exp = int(time.time()) + 86400 * 90
            iat = int(time.time())

            client_requested_scope = request.args.get("scope")

            client_requested_scope_items = client_requested_scope.split(" ") if client_requested_scope else []

            # intersect requested scope with original scope
            # this will allow us to only issue the maximum scopes that were already authorised
            # clients should never be able to add an additional scope at the refresh stage
            previously_issued_scopes = scope.split(" ")

            if client_requested_scope:
                scope = " ".join(
                    list(
                        set(client_requested_scope_items) & set(previously_issued_scopes)
                    )
                )

            new_token = jwt.encode(
                {
                    "me": me,
                    "client_id": client_id,
                    "scope": scope,
                    "exp": exp,
                    "iat": iat
                },
                config.SECRET_KEY,
                algorithm="HS256"
            )

            cursor.execute(
                "UPDATE issued_tokens SET encoded_code = ? WHERE encoded_code = ?",
                (new_token, issued_tokens[0],)
            )

            return jsonify(
                {"access_token": new_token, "token_type": "Bearer", "scope": scope, "me": me, "refresh_token": refresh_token, "expires_in": expires_in}
            )

    try:
        redeem_code = indieweb_utils.redeem_code(
            grant_type,
            code,
            client_id,
            redirect_uri,
            code_verifier,
            config.SECRET_KEY
        )

        access_token = redeem_code.access_token
        scope = redeem_code.scope
        me = redeem_code.me
        exp = redeem_code.exp
        iat = redeem_code.iat
    except Exception as e:
        print(e)
        return jsonify({"error": "invalid_request"})
    
    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()

        # if the code has already been redeemed, return an error
        existing_token = cursor.execute(
            "SELECT * FROM issued_tokens WHERE redeemed_from_code = ?", (code,)
        ).fetchone()
        if existing_token:
            return jsonify({"error": "invalid_grant"})

        # generate a refresh token as random string
        refresh_token = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=24)
        )
        
        h_app_item = client_information_cache.get(client_id)

        if not h_app_item:
            if validators.url(client_id, private=False):
                try:
                    client_id_app = requests.get(client_id, timeout=5)
                except Exception as e:
                    h_app_item = indieweb_utils.get_h_app_item(client_id_app.text, client_id)
                    client_information_cache[client_id] = h_app_item
                except Exception:
                    pass

        # create table if not exists issued_tokens (encoded_code, h_app, refresh_token, redeemed_from_code);
        cursor.execute(
            "INSERT INTO issued_tokens VALUES (?, ?, ?, ?, ?, ?)",
            (
                access_token,
                json.dumps(h_app_item),
                refresh_token,
                code,
                me,
                iat
            ),
        )

    return jsonify(
        {"access_token": access_token, "token_type": "Bearer", "scope": scope, "me": me, "refresh_token": refresh_token, "expires_in": exp}
    )

@app.route("/.well-known/oauth-authorization-server")
def oauth_authorization_server():
    oauth_server = {
        "authorization_endpoint": config.AUTH_SERVER_URL,
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
        "issuer": config.AUTH_SERVER_URL,
        "response_modes_supported": ["query"],
        "response_types_supported": ["code"],
        "scopes_supported": SCOPE_DEFINITIONS,
        "token_endpoint": config.TOKEN_SERVER_URL,
        "revocation_endpoint": config.BASE_URL + "/revocation",
        "introspection_endpoint": config.BASE_URL + "/introspection",
        "userinfo_endpoint": config.BASE_URL + "/userinfo",
        "service_documentation": "https://indieauth.spec.indieweb.org"
    }

    return jsonify(oauth_server)

@app.route("/revocation", methods=["POST"])
def revoke_access_token():
    token = request.form.get("token")
    if not token:
        return jsonify({"error": "invalid_request"}), 400

    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()
        
        cursor.execute("DELETE FROM issued_tokens WHERE encoded_code = ?", (token,))

    return "", 200

@app.route("/introspection", methods=["POST"])
def introspect_access_token():
    token = request.form.get("token")
    if not token:
        return jsonify({"error": "invalid_request"}), 400

    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()

        issued_token = cursor.execute(
            "SELECT * FROM issued_tokens WHERE encoded_code = ?", (token,)
        ).fetchone()

        if not issued_token:
            return jsonify({"active": False})
        
        try:
            decoded_token = jwt.decode(issued_token[0], config.SECRET_KEY, algorithms=["HS256"])
        except Exception as e:
            return jsonify({"active": False})

    return jsonify(
        {
            "active": True,
            "scope": decoded_token["scope"],
            "client_id": decoded_token["client_id"],
            "me": decoded_token["me"],
            "token_type": "Bearer",
            "exp": decoded_token["exp"],
            "iat": decoded_token["iat"],
        }
    )

@app.route("/userinfo")
def userinfo():
    authorization = request.headers.get("authorization")

    if authorization is None:
        return jsonify({"error": "invalid_request"}), 400

    authorization = authorization.replace("Bearer ", "")

    try:
        decoded_authorization_code = jwt.decode(
            authorization, config.SECRET_KEY, algorithms=["HS256"]
        )
    except Exception as e:
        return jsonify({"error": "invalid_token"}), 401

    me = decoded_authorization_code["me"]
    scope = decoded_authorization_code["scope"]

    if "profile" not in scope:
        return jsonify({"error": "insufficient_scope"}), 403
    
    response = compose_profile_response(me, scope, {})

    return jsonify(response)