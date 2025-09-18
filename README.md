# Alto

Alto is an open source [IndieAuth](https://indieauth.spec.indieweb.org) server that will power the Artemis web sign in authentication system.

Using this project, you can authenticate yourself to a service by using [RelMeAuth](https://indieweb.org/RelMeAuth). RelMeAuth requires you have rel="me" links on your blog that link to social profiles. At the moment, this project supports the following rel=me links:

- GitHub
- Email
- Tumblr
- Mastodon
- Wikipedia

![An example of an Alto consent screen showing the application name that wants to sign in via Alto, the scopes that are requested, and options to authorise or cancel the authentication request](./screenshot.png)

## Setup

To setup this project, first install the required dependencies. You can do this using the following command:

    pip3 install -r requirements.txt

Next, you will need to add some configration variables to a file called config.py.

### Create a configuration file

Create a file called config.py in the root directory of the project.

Then, add your GitHub OAuth API keys (leave all values you do not want to specify as ""):

    GITHUB_CLIENT_ID = "ID"
    GITHUB_OAUTH_REDIRECT = "URL"
    GITHUB_CLIENT_SECRET = "SECRET"

You can retrieve these pieces of information by following the GitHub "[Creating an OAuth App](https://docs.github.com/en/developers/apps/building-oauth-apps/creating-an-oauth-app)" guide.

### Running the server

Finally, add a secret key to your config.py file:

    SECRET_KEY = "KEY"

This key is used by Flask and is required for this web application to run. Your secret key must be kept secret.

Next, run the IndieAuth server using Flask:

    python3 run.py

If you plan to deploy the server on production, please use an appropriate production deployment method (i.e. using Gunicorn) as you would for any other Flask application.

## Issuing an access token

There are two ways to issue an access token with this endpoint:

1. Sign in with a service that supports IndieAuth and follow the authenication and authorization flows. Authentication is when you sign in and authorization is when you grant an application access to certain permissions.
2. Sign in to the endpoint at /login and issue a token at /issued.

The second approach is useful if you need a testing key for development. You can create a key and then use it in your application without having to worry about getting localhost to work with the authentication and authorization flows.

### Access token management

On the /issued endpoint, you can:

1. Issue access tokens, as aforementioned.
2. View information about issued access tokens (although not full access tokens).
3. Revoke an access token.

When an access token is revoked, it will immediately become invalid as per the revocation guidelines in the [IndieAuth specification](https://indieauth.spec.indieweb.org/).

## Licence

The code in this project is licensed under an [MIT No Attribution License](LICENSE).

Any and all images are All Rights Reserved.

## Contributors

- capjamesg