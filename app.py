from flask import Flask, render_template, request
import mysql.connector
import bcrypt

app = Flask(__name__)

def connector():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='user'
    )

@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['name']
    password = request.form['password']
    email = request.form['email']
    mobile = request.form['mobile']

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    db = connector()
    cur = db.cursor()
    cur.execute("INSERT INTO user (username, password, emailid, mobile) VALUES (%s, %s, %s, %s)", (username, hashed, email, mobile))
    db.commit()
    cur.close()
    db.close()
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['name']
    password = request.form['password']

    db = connector()
    cur = db.cursor()
    cur.execute("SELECT password FROM user WHERE username=%s", (username,))
    result = cur.fetchone()
    db.close()

    if result:
        stored_hash = result[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return render_template('change.html')
    
    return "❌ Invalid Username or Password. <a href='/login'>Try again</a>"

@app.route('/change', methods=['GET', 'POST'])
def change():
    if request.method == 'GET':
        return render_template('change.html')  # Your password change form

    username = request.form.get('username')
    oldpassword = request.form.get('oldpassword')
    newpassword = request.form.get('newpassword')
    confirmpassword = request.form.get('confirmpassword')

    if not all([username, oldpassword, newpassword, confirmpassword]):
        return "❌ All fields are required. <a href='/change'>Try again</a>"

    if newpassword != confirmpassword:
        return "❌ New passwords do not match. <a href='/change'>Try again</a>"

    try:
        db = connector()
        cur = db.cursor(buffered=True)
        cur.execute("SELECT password FROM user WHERE username = %s", (username,))
        result = cur.fetchone()

        if not result:
            return "❌ Username not found. <a href='/change'>Try again</a>"

        stored_hash = result[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')

        if not bcrypt.checkpw(oldpassword.encode('utf-8'), stored_hash):
            return "❌ Old password is incorrect. <a href='/change'>Try again</a>"
        
        new_hash = bcrypt.hashpw(newpassword.encode('utf-8'), bcrypt.gensalt())
        cur.execute("UPDATE user SET password=%s WHERE username=%s",
                    (new_hash.decode('utf-8'), username))
        db.commit()
        cur.close()
        db.close()

        return "✅ Password changed successfully! <a href='/login'>Login again</a>"

    except Exception as e:
        return f"❌ An error occurred: {str(e)} <a href='/change'>Try again</a>"


if __name__ =="__main__":
    app.run(debug=True)
