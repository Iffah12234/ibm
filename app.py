from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
import bcrypt

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'  # Replace with your MySQL host
app.config['MYSQL_USER'] = 'root'       # Replace with your MySQL username
app.config['MYSQL_PASSWORD'] = ''       # Replace with your MySQL password
app.config['MYSQL_DB'] = 'users'        # Replace with your MySQL database name
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Return results as dictionaries
mysql = MySQL(app)

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not username or not password or not confirm_password:
            return jsonify({'error': 'Please provide username, password, and confirm password'}), 400
        
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        # Hash the password before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Database insertion
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Registration successful'})
    except Exception as e:
        return jsonify({'error': 'An error occurred while registering user', 'details': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
