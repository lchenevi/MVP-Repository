from flask import Flask, render_template, url_for, flash, redirect, request, send_from_directory
from forms import RegistrationForm, LoginForm, MessageForm
from models import db, User, Consultation, Message
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash
import os
from flask_socketio import SocketIO, emit

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres.rorllosppiqkybjszkgu:oQe0CzXvjDV4B6HI@aws-0-eu-central-1.pooler.supabase.com:6543/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJvcmxsb3NwcGlxa3lianN6a2d1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcyMDI4NTgxNSwiZXhwIjoyMDM1ODYxODE1fQ.dSzJc_rGiKjPXzYlbGmiM18iB8VZneEd4vfN_2b9-YE'
app.config['SESSION_PERMANENT'] = False

db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

login_manager.init_app(app)

socketio = SocketIO(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template('index2.html', username=current_user.username if current_user.is_authenticated else None)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, is_admin=False)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
    return render_template('register2.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login2.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/messages", methods=['GET', 'POST'])
@login_required
def messages():
    form = MessageForm()

    if current_user.is_admin:
        # Admin can see all users and select whom to reply to
        users = User.query.filter(User.id != current_user.id).all()
        if form.validate_on_submit():
            receiver_id = request.form.get('receiver_id')
            message_content = form.content.data

            # Ensure receiver_id is valid and message content is not empty
            if receiver_id and message_content:
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=receiver_id,
                    content=message_content,
                    timestamp=datetime.utcnow()
                )
                db.session.add(message)
                db.session.commit()

                # Emit the new message to the selected user's chat box
                socketio.emit('new_message', {
                    'sender': current_user.username,
                    'content': message_content,
                    'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                }, room=f'user_{receiver_id}')

                flash('Your message has been sent!', 'success')
                return redirect(url_for('messages'))

        return render_template('admin_messages.html', form=form, users=users)
    else:
        # Regular users send messages to the admin
        if form.validate_on_submit():
            message_content = form.content.data

            # Ensure message content is not empty
            if message_content:
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=1,  # Assuming user ID 1 is the admin
                    content=message_content,
                    timestamp=datetime.utcnow()
                )
                db.session.add(message)
                db.session.commit()

                # Emit the new message to the admin's chat box
                socketio.emit('new_message', {
                    'sender': current_user.username,
                    'content': message_content,
                    'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                }, room='admin')

                flash('Your message has been sent!', 'success')
                return redirect(url_for('messages'))

        received_messages = Message.query.filter_by(receiver_id=current_user.id).all()
        sent_messages = Message.query.filter_by(sender_id=current_user.id).all()

        return render_template('messages.html', form=form, received_messages=received_messages, sent_messages=sent_messages)


@socketio.on('send_message')
def handle_send_message(data):
    content = data['content']
    sender = current_user.username
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    if current_user.is_admin:
        receiver_id = data['receiver_id']
        room = f'user_{receiver_id}'
    else:
        # Fetch admin user ID dynamically
        admin_user = User.query.filter_by(is_admin=True).first()
        if admin_user:
            receiver_id = admin_user.id
        else:
            # Handle case where no admin user found (optional)
            flash('No admin user found.', 'danger')
            return

        room = 'admin'

    message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content, timestamp=timestamp)
    db.session.add(message)
    db.session.commit()

    # Emit the new message to the appropriate room
    emit('new_message', {
        'sender': sender,
        'content': content,
        'timestamp': timestamp
    }, room=room)

@app.route("/admin/messages")
@login_required
def admin_messages():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    # Query all messages sent to the admin
    received_messages = Message.query.filter_by(receiver_id=1).all()

    # Debug: Print received messages
    for message in received_messages:
        print(f"{message.timestamp} - {message.sender.username}: {message.content}")

    users = User.query.all()  # This will list all users, modify as necessary for your use case
    return render_template('admin_messages.html', received_messages=received_messages, users=users)

@app.route("/submit_search", methods=['POST'])
@login_required
def submit_search():
    if request.method == 'POST':
        search_type = request.form.get('search_type')
        location = request.form.get('location')
        budget = request.form.get('budget')
        details = request.form.get('details')
        more = request.form.get('more')
        m2 = request.form.get('m2')
        subject = f"Search for {search_type} in {location}"
        if current_user.is_authenticated:
            user_id = current_user.id
            new_consultation = Consultation(
                user_id=user_id,
                subject=subject,
                description=details,
                budget=budget,
                more=more,
                m2=m2,
                status='pending',
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            try:
                db.session.add(new_consultation)
                db.session.commit()
                flash('Your search has been submitted successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}', 'danger')
        else:
            flash('You must be logged in to submit a search.', 'danger')
            return redirect(url_for('login'))
        return redirect(url_for('home'))

@app.route("/news")
def news():
    return render_template('news.html')

@app.route("/your_search")
def your_search():
    return render_template('votre_recherche2.html')

@app.route("/our_mission")
def our_mission():
    return render_template('notre_mission2.html')

@app.route("/why_ethics")
def why_ethics():
    return render_template('pourquoi_ethics2.html')

@app.route("/purchase_process")
def purchase_process():
    return render_template('processus_achat2.html')

@app.route("/our_partnerships")
def our_partnerships():
    return render_template('nos_partenaires2.html')

@app.route('/account', methods=['GET'])
@login_required  # Ensure user is logged in
def account():
    return render_template('account.html')

@app.route('/update_account', methods=['POST'])
@login_required  # Ensure user is logged in
def update_account():
    username = request.form['username']
    phone_number = request.form.get('phone_number')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if password and password == confirm_password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # Update user password in the database
        current_user.password = hashed_password

    # Update username and phone number in the database
    current_user.username = username
    if phone_number:
        current_user.phone_number = phone_number

    # Commit changes to the database
    db.session.commit()

    flash('Account updated successfully', 'success')
    return redirect(url_for('account'))


@app.route('/styles2.css')
def styles():
    return send_from_directory(app.static_folder, 'styles2.css')

@app.route('/images/<path:filename>')
def images(filename):
    return send_from_directory(os.path.join(app.static_folder, 'images'), filename)

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5001)
