import re

import indieweb_utils
from flask import Blueprint, redirect, render_template, request, session

from cache import h_card_cache
from forms import AskForDomain

user_auth = Blueprint("user_auth", __name__)


@user_auth.route("/login", methods=["GET", "POST"])
def login():
    ask_for_domain_form = AskForDomain()

    if request.args.get("r"):
        session["user_redirect"] = request.args.get("r")
        # if has me, redirect to /rel
        if request.args.get("me"):
            # url is all text after https://alto.jamesg.blog/login root domain
            url = request.url
            url = url.split("login?r=")[-1]
            # if url doesn't start with http[s]://alto.jamesg.blog, break
            if re.match(r"^https?://alto\.jamesg\.blog", url):
                session["user_redirect"] = url
                session["rel_me_check"] = request.args.get("me")
                return redirect("/rel")

    if session.get("rel_me_check"):
        return redirect("/rel")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    if request.method == "POST":
        if ask_for_domain_form.validate_on_submit():
            session["rel_me_check"] = ask_for_domain_form.domain.data
            return redirect("/rel")

    return render_template(
        "authentication_flow/ask_for_domain.html",
        title="Login to the Alto Server",
        ask_for_domain_form=ask_for_domain_form,
    )


@user_auth.route("/rel")
def rel_login_stage():
    if not session.get("rel_me_check"):
        return redirect("/login")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    rel_me_links = indieweb_utils.get_valid_relmeauth_links(
        session.get("rel_me_check"), require_rel_me_link_back=False
    )

    try:
        representative_h_card = indieweb_utils.get_representative_h_card(
            session.get("rel_me_check")
        )
    except Exception:
        representative_h_card = None

    profile_picture = None
    name = None

    if representative_h_card:
        representative_h_card = representative_h_card["properties"]
        if "photo" in representative_h_card:
            profile_picture = representative_h_card["photo"][0]
            if isinstance(profile_picture, dict) and "value" in profile_picture:
                profile_picture = profile_picture["value"]
        if "name" in representative_h_card:
            name = representative_h_card["name"][0]

        h_card_cache[session.get("rel_me_check")] = {
            "name": name,
            "photo": profile_picture,
            "url": session.get("rel_me_check"),
        }

    # order rel me links alphabetically
    rel_me_links = sorted(rel_me_links, key=lambda x: x.lower())

    for link in rel_me_links:
        if link.startswith("mailto:"):
            session["rel_me_email"] = link.replace("mailto:", "")
            break

    return render_template(
        "authentication_flow/login.html",
        rel_me_links=rel_me_links,
        me=session.get("rel_me_check"),
        profile_picture=profile_picture,
        name=name,
        representative_h_card=representative_h_card,
        title="Authenticate with a rel=me link",
    )
