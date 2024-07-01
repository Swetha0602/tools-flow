from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# List of authorized users
authorized_users = [
    {'username': 'admin', 'password': 'password'},
    {'username': 'swetha', 'password': '123'}
]

# Dictionary to store failed login attempts and lock times
login_attempts = {}

# Login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.', 'success')
            return redirect(url_for('login'))
    return wrap

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the user is locked out
        if username in login_attempts and login_attempts[username]['lock_time'] > datetime.now():
            lock_time = login_attempts[username]['lock_time']
            flash(f"Your account is locked until {lock_time.strftime('%Y-%m-%d %H:%M:%S')}. Please try again later.", 'danger')
            return render_template('login.html')
        
        # Check if the user is authorized
        user = next((user for user in authorized_users if user['username'] == username and user['password'] == password), None)
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            
            # Reset failed login attempts if the user is authorized
            if username in login_attempts:
                del login_attempts[username]
            
            flash('You are now logged in.', 'success')
            return redirect(url_for('index'))
        else:
            # Store failed login attempt and lock time if the user is not authorized
            if username in login_attempts:
                login_attempts[username]['attempts'] += 1
            else:
                login_attempts[username] = {'attempts': 3, 'lock_time': datetime.now() + timedelta(minutes=3)}
            
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You are now logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
