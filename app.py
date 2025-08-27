from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from datetime import date

app = Flask(__name__)
app.config.from_pyfile('config.py')

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# ---------- Home (redirect to login) ----------
@app.route('/')
def home():
    return redirect(url_for('login'))

# ---------- Register ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO students (name, email, password, registration_date, is_registered) VALUES (%s, %s, %s, %s, %s)",
            (name, email, password, date.today(), 1)
        )
        mysql.connection.commit()
        flash("Registered successfully! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']  # student or admin

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        if role == "student":
            cursor.execute("SELECT * FROM students WHERE email=%s", (email,))
            user = cursor.fetchone()
            if user and bcrypt.check_password_hash(user['password'], password):
                session['student_id'] = user['student_id']
                return redirect(url_for('student_dashboard'))
        elif role == "admin":
            cursor.execute("SELECT * FROM admins WHERE username=%s", (email,))
            admin = cursor.fetchone()
            # ⚠️ You should also hash admin passwords, but for now we keep plain text
            if admin and admin['password'] == password:
                session['admin'] = admin['username']
                return redirect(url_for('admin_dashboard'))

        flash("Invalid credentials", "danger")
    return render_template('login.html')

# ---------- Student Dashboard ----------
@app.route('/student/dashboard')
def student_dashboard():
    if 'student_id' not in session:
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM students WHERE student_id=%s", (session['student_id'],))
    student = cursor.fetchone()
    return render_template('student_dashboard.html', student=student)

# ---------- Admin Dashboard ----------
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        action = request.form['action']

        if action == "paid":
            cursor.execute("UPDATE students SET is_paid=1, payment_date= NOW() WHERE student_id=%s", (student_id))
        elif action == "accept":
            cursor.execute("UPDATE students SET is_form_accepted=1 WHERE student_id=%s", (student_id,))
        mysql.connection.commit()

    cursor.execute("SELECT * FROM students")
    students = cursor.fetchall()
    return render_template('admin_dashboard.html', students=students)

# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
