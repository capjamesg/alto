# create tokens.db
import sqlite3

conn = sqlite3.connect("tokens.db")

c = conn.cursor()

c.execute(
    """
    CREATE TABLE IF NOT EXISTS clients (
        id integer primary key autoincrement not null,
        client_id text,
        name text,
        logo text,
        url text,
        summary text
    );
    """
)

c.execute(
    """
    CREATE TABLE IF NOT EXISTS issued_tokens (
        encoded_code text primary key not null,
        h_app text text,
        refresh_token text,
        redeemed_from_code text,
        me text,
        issued_on integer
    );
    """
)

print("Database and tables created.")
