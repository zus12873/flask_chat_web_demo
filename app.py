from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import time
import threading
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    last_heartbeat = db.Column(db.DateTime, nullable=True)  # 添加最后心跳时间
    sent_messages = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    received_messages = db.relationship('Message', backref='receiver', lazy=True, foreign_keys='Message.receiver_id')
    is_online = db.Column(db.Boolean, default=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    message_type = db.Column(db.String(10), nullable=False, default='text')  # 'text', 'voice' 或 'image'

class RegisterForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('注册')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('users'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_login = db.func.current_timestamp()  # 更新最后登录时间
            db.session.commit()
            return redirect(url_for('users'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))
        
        user = User(username=username)
        user.password_hash = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
        
        flash('注册成功，请登录')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/users')
@login_required
def users():
    users = User.query.filter(User.id != current_user.id).order_by(User.last_login.desc()).all()
    return render_template('users.html', users=users)

@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    receiver = User.query.get_or_404(user_id)
    
    # 获取两个用户之间的历史消息
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    return render_template('chat.html', receiver=receiver, messages=messages)

@socketio.on('send_message')
def handle_message(data):
    receiver_id = data['receiver_id']
    content = data['content']
    message_type = data.get('message_type', 'text')
    
    message = Message(
        content=content,
        sender_id=current_user.id,
        receiver_id=receiver_id,
        message_type=message_type
    )
    db.session.add(message)
    db.session.commit()
    
    room = f"chat_{min(current_user.id, receiver_id)}_{max(current_user.id, receiver_id)}"
    emit('receive_message', {
        'content': content,
        'sender_id': current_user.id,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'message_type': message_type
    }, room=room)

@socketio.on('join')
def on_join(data):
    receiver_id = data['receiver_id']
    room = f"chat_{min(current_user.id, receiver_id)}_{max(current_user.id, receiver_id)}"
    join_room(room)

@socketio.on('leave')
def on_leave(data):
    receiver_id = data['receiver_id']
    room = f"chat_{min(current_user.id, receiver_id)}_{max(current_user.id, receiver_id)}"
    leave_room(room)

@socketio.on('typing')
def handle_typing(data):
    if current_user.is_authenticated:
        receiver_id = data.get('receiver_id')
        if receiver_id:
            emit('user_typing', {
                'user_id': current_user.id
            }, room=f'user_{receiver_id}')

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.is_online = True
        current_user.last_heartbeat = db.func.current_timestamp()
        db.session.commit()
        emit('user_status_update', {
            'user_id': current_user.id,
            'is_online': True
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_heartbeat = db.func.current_timestamp()
        db.session.commit()
        emit('user_status_update', {
            'user_id': current_user.id,
            'is_online': False
        }, broadcast=True)

@socketio.on('request_users_update')
def handle_users_update_request():
    if current_user.is_authenticated:
        users = User.query.filter(User.id != current_user.id).order_by(User.last_login.desc()).all()
        users_data = [{
            'id': user.id,
            'username': user.username,
            'is_online': user.is_online,
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
        } for user in users]
        emit('users_list_update', {'users': users_data})

@socketio.on('heartbeat')
def handle_heartbeat():
    if current_user.is_authenticated:
        current_user.last_heartbeat = db.func.current_timestamp()
        current_user.is_online = True
        db.session.commit()
        emit('heartbeat_ack')

def check_user_offline():
    """检查用户是否离线（超过30秒没有心跳）"""
    with app.app_context():
        offline_threshold = datetime.utcnow() - timedelta(seconds=30)
        offline_users = User.query.filter(
            User.last_heartbeat < offline_threshold,
            User.is_online == True
        ).all()
        
        for user in offline_users:
            user.is_online = False
            db.session.commit()
            socketio.emit('user_status_update', {
                'user_id': user.id,
                'is_online': False
            }, broadcast=True)

# 启动心跳检查任务
def start_heartbeat_checker():
    while True:
        check_user_offline()
        time.sleep(10)  # 每10秒检查一次

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # with app.app_context():
    #     db.drop_all()  # 删除所有表
    #     db.create_all()  # 重新创建所有表
    
    # 启动心跳检查线程
    heartbeat_thread = threading.Thread(target=start_heartbeat_checker, daemon=True)
    heartbeat_thread.start()
    
    # 运行应用（允许外部访问）
    socketio.run(app, 
                host='127.0.0.1',  # 允许外部访问
                port=8000, 
                debug=True, 
                allow_unsafe_werkzeug=True) 