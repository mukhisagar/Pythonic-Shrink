from flask import Flask, request, redirect, jsonify,render_template
import psycopg2
import os
import hashlib
import base64
import re
from psycopg2.extras import DictCursor

app = Flask(__name__)

# Database Configuration
# Function to get the database connection
def get_db_connection():
    # 1. Retrieve the connection string from the OS environment.
    # We use DB_CONFIG as the environment variable name, as you specified.
    DB_CONFIG_URL = os.environ.get('DB_CONFIG') 

    # 2. Check if the URL was found and then connect to the Postgres database.
    if DB_CONFIG_URL:
        # psycopg2.connect() accepts the full connection string as an argument.
        return psycopg2.connect(DB_CONFIG_URL) 
    else:
        # This block is for safety; it will prevent the app from crashing 
        # locally if the environment variable isn't set.
        raise Exception("DB_CONFIG environment variable not set. Cannot connect to database.")


# Function to generate a short URL
def generate_short_url(long_url):
     hash_object = hashlib.sha256(long_url.encode())
     short_hash = base64.urlsafe_b64encode(hash_object.digest())[:6].decode()
     return short_hash

# Serve the HTML form
@app.route('/')
def home():
     return render_template('index.html')



# Define your custom shortened host URL
CUSTOM_HOST_URL = "https://pythonic-shrink.onrender.com/"

# Handle URL shortening
@app.route('/shorten', methods=['POST'])
def shorten_url():
    long_url = request.form.get('long_url')
    custom_short_url = request.form.get('custom_short_url')  # Get custom short URL from the form
    expiration_date = request.form.get('expiration_date')  # Get expiration date from the form

    if not long_url:
        return "Invalid URL", 400

    if not long_url.startswith(('http://', 'https://')):
        long_url = 'http://' + long_url

    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)

        # Check if a custom short URL is provided
        if custom_short_url:
            # Ensure the custom short URL is unique
            cursor.execute("SELECT * FROM url_mapping WHERE short_url = %s", (custom_short_url,))
            existing_custom_entry = cursor.fetchone()
            if existing_custom_entry:
                conn.close()
                return "Error: Custom short URL already exists. Please choose another one.", 400

            # Validate custom short URL
            if not re.match("^[a-zA-Z0-9_-]+$", custom_short_url):
                return "Error: Custom short URL contains invalid characters. Only letters, numbers, dashes, and underscores are allowed.", 400
            if len(custom_short_url) > 20:
                return "Error: Custom short URL is too long. Maximum length is 20 characters.", 400

            short_url = custom_short_url
        else:
            # Generate a short URL if no custom short URL is provided
            cursor.execute("SELECT short_url FROM url_mapping WHERE long_url = %s", (long_url,))
            existing_entry = cursor.fetchone()
            if existing_entry:
                conn.close()
                short_url = f"{CUSTOM_HOST_URL}{existing_entry['short_url']}"
                return render_template('shortened.html', short_url=short_url)

            short_url = generate_short_url(long_url)

        # Set default expiration date if not provided
        if not expiration_date:
            cursor.execute("SELECT CURRENT_TIMESTAMP + INTERVAL '30 days' AS default_expiration")
            expiration_date = cursor.fetchone()['default_expiration']

        # Insert the new URL into the database
        cursor.execute(
            "INSERT INTO url_mapping (long_url, short_url, expiration_date) VALUES (%s, %s, %s)",
            (long_url, short_url, expiration_date)
        )
        conn.commit()
        conn.close()

        short_url = f"{CUSTOM_HOST_URL}{short_url}"
        return render_template('shortened.html', short_url=short_url)
    except Exception as e:
        return f"Database error: {e}", 500


# Redirect shortened URLs
@app.route('/<short_url>', methods=['GET'])
def redirect_url(short_url):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)

    # Check if the URL exists and is not expired
    cursor.execute(
        "SELECT long_url, expiration_date FROM url_mapping WHERE short_url = %s",
        (short_url,)
    )
    entry = cursor.fetchone()
    if entry:
        if entry['expiration_date'] and entry['expiration_date'] < cursor.execute("SELECT CURRENT_TIMESTAMP"):
            conn.close()
            return "Error: This shortened URL has expired.", 410  # HTTP 410 Gone

        # Update the clicks and last_accessed columns
        cursor.execute(
            "UPDATE url_mapping SET clicks = clicks + 1, last_accessed = CURRENT_TIMESTAMP WHERE short_url = %s",
            (short_url,)
        )
        conn.commit()
        conn.close()
        return redirect(entry['long_url'])

    conn.close()
    return "Error: URL not found", 404

@app.route('/analytics/<short_url>', methods=['GET'])
def analytics(short_url):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)

        # Fetch analytics data for the given short URL
        cursor.execute(
            "SELECT long_url, clicks, created_at, last_accessed FROM url_mapping WHERE short_url = %s",
            (short_url,)
        )
        entry = cursor.fetchone()
        conn.close()

        if entry:
            return render_template('analytics.html', data=entry)
        else:
            return "Error: URL not found", 404
    except Exception as e:
        return f"Database error: {e}", 500
# Run the Flask application
if __name__ == '__main__':
     app.run(debug=True)
