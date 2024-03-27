import cryptography
from flask import Flask, render_template, request, redirect, url_for, session
from cryptography.fernet import Fernet
import pymysql

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Generate a key for AES encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'users',
}

# Encrypt the password using AES
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

# Decrypt the password using AES
def decrypt_password(encrypted_password):
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
        return decrypted_password
    except cryptography.fernet.InvalidToken:
        print("Invalid token: Failed to decrypt password.")
        return None


def authenticate_user(username, password):
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    query = f"SELECT * FROM newusers WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return user
    return None

# Function to insert new user with encrypted password
def insert_new_user(username, password):
    encrypted_password = encrypt_password(password)
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    insert_query = "INSERT INTO newusers (username, password) VALUES (%s, %s)"
    cursor.execute(insert_query, (username, encrypted_password))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id

def get_user_data(user_id):
    try:
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        query = f"SELECT * FROM newusers WHERE id = {user_id}"
        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()
        return user_data
    except Exception as e:
        print(f"Error fetching user data: {e}")
        return None


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if password matches confirm_password
        if password != confirm_password:
            error = "Passwords do not match. Please try again."
            return render_template('signup2.html', error=error)

        user_id = insert_new_user(username, password)
        session['user_id'] = user_id
        return redirect(url_for('mainpage'))
    else:
        return render_template('signup2.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user[0]
            return redirect(url_for('mainpage'))
        else:
            error = "Invalid username or password. Please try again."
            return render_template('login.html')+ "<script>displayErrorMessage('" + error + "');</script>"
    else:
        return render_template('login.html')

@app.route('/mainpage')
def mainpage():
    if 'user_id' in session:
        user_id = session['user_id']
        # Assuming you have a function to fetch user-specific data from the database
        user_data = get_user_data(user_id)
        return render_template('mainpage.html', user_data=user_data)
    else:
        return redirect(url_for('login'))
    

@app.route('/charge', methods=['POST'])
def charge():
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = request.form['amount']
        comment = request.form['comment']
        user_id = session['user_id']  # Get user ID from session

        # Store transaction data in the database
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        insert_query = "INSERT INTO transactions (user_id, recipient, amount, comment) VALUES (%s, %s, %s, %s)"
        cursor.execute(insert_query, (user_id, recipient, amount, comment))
        conn.commit()
        conn.close()

                # Redirect to transfer details page
        return redirect(url_for('transfer_details', recipient=recipient, amount=amount, comment=comment))
    else:
        return redirect(url_for('login'))

@app.route('/transfer_details')
def transfer_details():
    recipient = request.args.get('recipient')
    amount = request.args.get('amount')
    comment = request.args.get('comment')
    return render_template('transfer_details.html', recipient=recipient, amount=amount, comment=comment)



@app.route('/transfer')
def transfer():
    return render_template('transfer.html')

@app.route('/balance')
def balance():
    return render_template('balance.html')

@app.route('/payees')
def payees():
    return render_template('payees.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/front')
def front():
    return render_template('front.html')

@app.route('/signup2')
def signup2():
    return render_template('signup2.html')


@app.route('/forgotpassword')
def forgotpassword():
    return render_template('forgotpassword.html')


if __name__ == '__main__':
    app.run(debug=True)