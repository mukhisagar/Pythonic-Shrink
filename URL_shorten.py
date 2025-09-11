from flask import Flask, request, redirect, jsonify,render_template
import mysql.connector
import hashlib
import base64

app = Flask(__name__)

# Database Configuration

DB_CONFIG = {
     'host': 'localhost',
     'user': 'root',
     'password': 'root',
     'database': 'test'
}



def get_db_connection():
     return mysql.connector.connect(**DB_CONFIG)


# Function to generate a short URL
def generate_short_url(long_url):
     hash_object = hashlib.sha256(long_url.encode())
     short_hash = base64.urlsafe_b64encode(hash_object.digest())[:6].decode()
     return short_hash

# Serve the HTML form
@app.route('/')
def home():
     return render_template('index.html')



# Handle URL shortening
@app.route('/shorten', methods=['POST'])
def shorten_url():
    long_url = request.form.get('long_url')
    if not long_url:
        return "Invalid URL", 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check if URL exists
    cursor.execute("SELECT short_url FROM url_mapping WHERE long_url = %s", (long_url,))
    existing_entry = cursor.fetchone()
    if existing_entry:
        conn.close()
        short_url = f"{request.host_url}{existing_entry['short_url']}"
        return render_template('shortened.html', short_url=short_url)

    short_url = generate_short_url(long_url)
    cursor.execute("INSERT INTO url_mapping (long_url, short_url) VALUES (%s, %s)", (long_url, short_url))
    conn.commit()
    conn.close()

    short_url = f"{request.host_url}{short_url}"
    return render_template('shortened.html', short_url=short_url)


# Redirect shortened URLs
@app.route('/<short_url>', methods=['GET'])
def redirect_url(short_url):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT long_url FROM url_mapping WHERE short_url = %s", (short_url,))
    entry = cursor.fetchone()
    if entry:
        cursor.execute("UPDATE url_mapping SET clicks = clicks + 1 WHERE short_url = %s", (short_url,))
        conn.commit()
        conn.close()
        return redirect(entry['long_url'])
    
    conn.close()
    return "Error: URL not found", 404
# Run the Flask application
if __name__ == '__main__':
     app.run(debug=True)
