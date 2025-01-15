from flask import Flask, render_template, redirect, url_for, request, flash, session, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import json
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Check if the database file exists, if not, create it
if not os.path.exists('database.db'):
    with app.app_context():
        db.create_all()

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    profile_data = db.Column(db.String(500), default="{}")  # Store additional profile info as JSON

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    make = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    color = db.Column(db.String(50), nullable=False)
    service = db.Column(db.String(200))
    license_plate = db.Column(db.String(20), nullable=False, unique=True)
    vehicle_type = db.Column(db.String(50), nullable=False)


# Create tables (run this once)
with app.app_context():
    db.create_all()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        else:
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/inventory', methods=['GET', 'POST'])
@login_required
def inventory():
    if request.method == 'POST':
        data = request.get_json()
        new_vehicle = Vehicle(
            user_id=current_user.id,
            make=data['make'],
            model=data['model'],
            year=data['year'],
            color=data['color'],
            service=data.get('service'),
            license_plate=data['license_plate'],
            vehicle_type=data['vehicle_type']
        )
        db.session.add(new_vehicle)
        db.session.commit()
        return {'success': True}, 200

    # Fetch vehicles for the logged-in user
    vehicles = Vehicle.query.filter_by(user_id=current_user.id).all()
    return render_template('inventory.html', vehicles=vehicles)

def remove_vehicle_from_database(vehicle_id):
    """
    Removes a vehicle from the database using its ID.
    """
    try:
        # Assuming you're using SQLAlchemy
        vehicle = Vehicle.query.get(vehicle_id)
        if vehicle:
            db.session.delete(vehicle)
            db.session.commit()
            return True
        else:
            return False
    except Exception as e:
        print(f"Error removing vehicle: {e}")
        return False

@app.route('/remove_vehicle', methods=['POST'])
def remove_vehicle():
    """
    Removes a vehicle based on its ID received from the frontend.
    """
    data = request.get_json()
    vehicle_id = data.get('vehicle_id')  # Ensure the frontend sends this ID

    if not vehicle_id:
        return jsonify({'success': False, 'message': 'Vehicle ID not provided.'}), 400

    success = remove_vehicle_from_database(vehicle_id)
    if success:
        return jsonify({'success': True, 'message': 'Vehicle removed successfully.'})
    else:
        return jsonify({'success': False, 'message': 'Failed to remove vehicle.'}), 500

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Extract data from request
        data = request.get_json()
        current_user.profile_data = json.dumps(data)  # Store as JSON or individual fields
        db.session.commit()
        return {'message': 'Profile updated successfully!'}, 200
    else:
        # Serve profile page
        profile_data = json.loads(current_user.profile_data or '{}')
        return render_template('profile.html', **profile_data)

@app.route('/logout')
def logout():
    session.clear()  # Clears the user's session
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
