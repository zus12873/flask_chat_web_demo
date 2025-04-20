from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
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
import requests
import json
import hashlib
import urllib.parse
import logging
from sqlalchemy import event
from sqlalchemy.engine import Engine
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 配置日志记录
if not app.debug:
    # 创建日志处理器，写入日志文件
    file_handler = logging.FileHandler('app.log')
    file_handler.setLevel(logging.INFO)
    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    # 添加处理器到应用
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

# 配置SQLite以支持UTF-8
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        # 使用SQLite自带的UNICODE支持
        cursor.execute("PRAGMA encoding='UTF-8'")
        cursor.close()

# 确保在应用启动时记录重要信息
app.logger.info('应用启动')

# 微信开放平台配置
# WECHAT_APP_ID = 'wxf0c7b15c60bfe206'
# WECHAT_APP_SECRET = '4202892bfe8f4d95e3c0b1ccb44c6349'
# WECHAT_APP_ID = 'wx67addda9cc8c3b9d'
# WECHAT_APP_SECRET = 'e68ba6bcb806bf5bd0f17799ee0f1748'
#wx1a8f377ff2392bb3
WECHAT_APP_ID = os.getenv('WECHAT_APP_ID')
WECHAT_APP_SECRET = os.getenv('WECHAT_APP_SECRET')

# 授权后重定向的回调链接地址，请使用urlEncode对链接进行处理
WECHAT_REDIRECT_URI = urllib.parse.quote(os.getenv('WECHAT_REDIRECT_URI'))
app.logger.info(f'微信重定向URI: {WECHAT_REDIRECT_URI}')

# 微信测试号配置
WECHAT_TOKEN = os.getenv('WECHAT_TOKEN')  # 替换为您的Token

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)  # 改为可空，因为微信登录不需要密码
    last_login = db.Column(db.DateTime, nullable=True)
    last_heartbeat = db.Column(db.DateTime, nullable=True)
    sent_messages = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    received_messages = db.relationship('Message', backref='receiver', lazy=True, foreign_keys='Message.receiver_id')
    is_online = db.Column(db.Boolean, default=False)
    wechat_openid = db.Column(db.String(64), unique=True, nullable=True)  # 添加微信openid字段
    wechat_nickname = db.Column(db.String(128), nullable=True)  # 添加微信昵称
    wechat_headimgurl = db.Column(db.String(255), nullable=True)  # 添加微信头像URL
    is_admin = db.Column(db.Boolean, default=False)  # 添加管理员角色字段

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
        # 如果是管理员，重定向到用户列表页面
        if current_user.is_admin:
            return redirect(url_for('users'))
        else:
            # 如果是普通用户，重定向到与管理员的聊天页面
            # 查找管理员用户
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                return redirect(url_for('chat', user_id=admin.id))
            else:
                flash('未找到管理员用户，请联系系统管理员')
                return render_template('index.html')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        app.logger.info(f"用户 {current_user.username} 已登录，重定向到适当页面")
        if current_user.is_admin:
            return redirect(url_for('users'))
        else:
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                return redirect(url_for('chat', user_id=admin.id))
            else:
                return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        app.logger.info(f"尝试登录: 用户名={username}")
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            app.logger.info(f"登录成功: 用户名={username}, ID={user.id}, 是否管理员={user.is_admin}")
            login_user(user)
            user.last_login = db.func.current_timestamp()
            user.is_online = True
            user.last_heartbeat = db.func.current_timestamp()
            db.session.commit()
            
            # 发送用户状态更新
            socketio.emit('user_status_update', {
                'user_id': user.id,
                'is_online': True
            }, to=None)
            
            # 根据角色重定向
            if user.is_admin:
                app.logger.info(f"管理员登录: 重定向到用户列表页面")
                return redirect(url_for('users'))
            else:
                # 查找管理员用户
                admin = User.query.filter_by(is_admin=True).first()
                if admin:
                    app.logger.info(f"普通用户登录: 重定向到与管理员({admin.username})的聊天页面")
                    return redirect(url_for('chat', user_id=admin.id))
                else:
                    app.logger.warning("未找到管理员用户")
                    return redirect(url_for('index'))
        else:
            app.logger.warning(f"登录失败: 用户名={username}")
            flash('用户名或密码不正确')
    
    return render_template('login.html')

@app.route('/wechat/login')
def wechat_login():
    """
    微信网页授权第一步：用户同意授权，获取code
    """
    # 1. 构造微信授权URL - 使用正确的网页授权接口
    oauth_url = (
        f"https://open.weixin.qq.com/connect/oauth2/authorize?"
        f"appid={WECHAT_APP_ID}&"
        f"redirect_uri={WECHAT_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=snsapi_userinfo&"  # 使用snsapi_userinfo以获取用户基本信息
        f"state=STATE#wechat_redirect"
    )
    
    # 重定向到微信授权页面
    app.logger.info(f"微信授权URL: {oauth_url}")
    return redirect(oauth_url)

@app.route('/wechat/verify', methods=['GET', 'POST'])
def wechat_verify():
    """
    微信接口处理路由：
    1. 处理微信服务器验证请求（GET请求，带有signature等参数）
    2. 处理微信授权回调（GET请求，带有code参数）
    3. 处理微信消息推送（POST请求）
    """
    # 记录请求参数，便于调试
    app.logger.info(f"微信请求: {request.method} 参数: {request.args}")
    
    # 处理微信服务器验证请求
    if request.method == 'GET' and 'signature' in request.args and 'echostr' in request.args:
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        
        # 按照微信的规则进行验证
        temp_list = [WECHAT_TOKEN, timestamp, nonce]
        temp_list.sort()
        temp_str = ''.join(temp_list)
        
        # 进行sha1加密
        temp_str = hashlib.sha1(temp_str.encode('utf-8')).hexdigest()
        
        # 验证签名
        app.logger.info(f"微信验证: 计算签名={temp_str}, 提供签名={signature}")
        if temp_str == signature:
            return echostr
        return 'verification failed'
    
    # 处理微信授权回调
    elif request.method == 'GET' and 'code' in request.args:
        code = request.args.get('code')
        app.logger.info(f"微信授权回调: code={code}")
        
        # 使用code获取access_token
        token_url = (
            f"https://api.weixin.qq.com/sns/oauth2/access_token?"
            f"appid={WECHAT_APP_ID}&"
            f"secret={WECHAT_APP_SECRET}&"
            f"code={code}&"
            f"grant_type=authorization_code"
        )
        
        try:
            response = requests.get(token_url)
            token_data = handle_wechat_json_response(response)
            
            if 'errcode' in token_data:
                app.logger.error(f"微信授权错误: {token_data}")
                flash(f'获取access_token失败: {token_data.get("errmsg", "未知错误")}')
                return redirect(url_for('login'))
            
            # 提取access_token和openid
            access_token = token_data.get('access_token')
            openid = token_data.get('openid')
            
            # 使用access_token和openid获取用户信息
            user_info_url = (
                f"https://api.weixin.qq.com/sns/userinfo?"
                f"access_token={access_token}&"
                f"openid={openid}&"
                f"lang=zh_CN"
            )
            
            user_response = requests.get(user_info_url)
            user_data = handle_wechat_json_response(user_response)
            
            if 'errcode' in user_data:
                app.logger.error(f"获取用户信息错误: {user_data}")
                flash(f'获取用户信息失败: {user_data.get("errmsg", "未知错误")}')
                return redirect(url_for('login'))
            
            # 确保nickname是UTF-8编码
            nickname = user_data.get('nickname', '')
            # 记录原始数据，便于调试
            app.logger.info(f"原始用户数据: {user_data}")
            app.logger.info(f"获取用户信息成功，昵称: {nickname}")
            
            # 查找或创建用户
            user = User.query.filter_by(wechat_openid=openid).first()
            
            if not user:
                # 创建新用户
                safe_nickname = nickname if nickname else f'微信用户_{openid[:8]}'
                
                # 确保用户名唯一
                existing_user = User.query.filter_by(username=safe_nickname).first()
                if existing_user:
                    safe_nickname = f"{safe_nickname}_{int(time.time())}"
                    
                user = User(
                    username=safe_nickname,
                    wechat_openid=openid,
                    wechat_nickname=nickname,
                    wechat_headimgurl=user_data.get('headimgurl')
                )
                db.session.add(user)
                db.session.commit()
                app.logger.info(f"创建新用户: {safe_nickname}")
            
            # 登录用户
            login_user(user)
            user.last_login = db.func.current_timestamp()
            db.session.commit()
            
            # 根据用户角色重定向到不同页面
            if user.is_admin:
                return redirect(url_for('users'))
            else:
                # 查找管理员用户
                admin = User.query.filter_by(is_admin=True).first()
                if admin:
                    return redirect(url_for('chat', user_id=admin.id))
                else:
                    flash('未找到管理员用户，请联系系统管理员')
                    return redirect(url_for('index'))
        
        except Exception as e:
            app.logger.error(f"微信授权过程中发生错误: {str(e)}")
            flash(f'微信授权过程中发生错误: {str(e)}')
            return redirect(url_for('login'))
    
    # 处理微信消息推送
    elif request.method == 'POST':
        # 处理微信发送的消息（这里仅作示例）
        try:
            xml_data = request.data.decode('utf-8')
            app.logger.info(f"收到微信消息: {xml_data}")
            # 在这里解析XML并处理消息
            # ...
            
            # 返回响应消息
            response = """
            <xml>
                <ToUserName><![CDATA[{}]]></ToUserName>
                <FromUserName><![CDATA[{}]]></FromUserName>
                <CreateTime>{}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[您好，这是自动回复消息。]]></Content>
            </xml>
            """
            # 这里需要填入实际的微信用户ID和公众号ID
            return response
        except Exception as e:
            app.logger.error(f"处理微信消息错误: {str(e)}")
            return 'error'
    
    return 'invalid request'

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
    # 只有管理员可以访问用户列表
    if not current_user.is_admin:
        flash('您没有权限访问用户列表')
        # 查找管理员用户
        admin = User.query.filter_by(is_admin=True).first()
        if admin:
            return redirect(url_for('chat', user_id=admin.id))
        else:
            return redirect(url_for('index'))
    
    # 管理员可以看到所有非管理员用户
    users = User.query.filter(User.id != current_user.id).filter(User.is_admin == False).order_by(User.last_login.desc()).all()
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
        socketio.emit('user_status_update', {
            'user_id': current_user.id,
            'is_online': True
        }, to=None)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_heartbeat = db.func.current_timestamp()
        db.session.commit()
        socketio.emit('user_status_update', {
            'user_id': current_user.id,
            'is_online': False
        }, to=None)

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
            }, to=None)

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

@app.route('/profile')
@login_required
def profile():
    """用户个人资料页"""
    return render_template('profile.html')

def handle_wechat_json_response(response):
    """
    处理微信API返回的JSON响应，确保正确处理UTF-8编码
    """
    response.encoding = 'utf-8'
    text = response.text
    try:
        # 尝试直接解析JSON
        return response.json()
    except:
        # 如果失败，尝试手动解析
        app.logger.warning(f"JSON解析失败，尝试手动处理编码: {text[:100]}...")
        import json
        return json.loads(text)

def create_admin_user():
    """创建超级管理员用户"""
    admin_username = 'admin'
    admin_password = 'admin123'  # 您应该使用更强的密码
    
    app.logger.info("开始创建管理员用户...")
    
    # 检查是否已存在管理员
    existing_admin = User.query.filter_by(is_admin=True).first()
    if existing_admin:
        app.logger.info(f"管理员用户已存在: ID={existing_admin.id}, 用户名={existing_admin.username}")
        return existing_admin
    
    # 检查用户名是否被占用
    existing_user = User.query.filter_by(username=admin_username).first()
    if existing_user:
        # 如果用户存在但不是管理员，将其设为管理员
        existing_user.is_admin = True
        db.session.commit()
        app.logger.info(f"已将现有用户设置为管理员: ID={existing_user.id}, 用户名={existing_user.username}")
        return existing_user
    
    # 创建新的管理员用户
    admin = User(
        username=admin_username,
        password_hash=generate_password_hash(admin_password),
        is_admin=True,
        is_online=False
    )
    db.session.add(admin)
    try:
        db.session.commit()
        app.logger.info(f"已创建新管理员用户: ID={admin.id}, 用户名={admin_username}")
        return admin
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"创建管理员用户失败: {str(e)}")
        return None

# 添加一个管理员设置路由（受密码保护）
@app.route('/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    setup_key = request.args.get('key')
    # 使用简单的密钥来保护此路由
    if setup_key != 'setup_secret_key':
        return "访问被拒绝", 403
    
    if request.method == 'POST':
        admin_username = request.form.get('username')
        admin_password = request.form.get('password')
        
        if not admin_username or not admin_password:
            return "用户名和密码不能为空", 400
        
        # 检查是否已存在管理员
        existing_admin = User.query.filter_by(is_admin=True).first()
        if existing_admin:
            flash(f"管理员用户已存在: {existing_admin.username}")
            return redirect(url_for('index'))
        
        # 检查用户名是否被占用
        existing_user = User.query.filter_by(username=admin_username).first()
        if existing_user:
            # 如果用户存在但不是管理员，将其设为管理员
            existing_user.is_admin = True
            existing_user.password_hash = generate_password_hash(admin_password)
            db.session.commit()
            flash(f"已将现有用户 {existing_user.username} 设置为管理员")
            return redirect(url_for('index'))
        
        # 创建新的管理员用户
        admin = User(
            username=admin_username,
            password_hash=generate_password_hash(admin_password),
            is_admin=True,
            is_online=False
        )
        db.session.add(admin)
        db.session.commit()
        flash(f"已创建新管理员用户: {admin_username}")
        return redirect(url_for('index'))
    
    return '''
    <form method="POST">
        <div>
            <label>管理员用户名:</label>
            <input type="text" name="username" required>
        </div>
        <div>
            <label>管理员密码:</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit">创建管理员</button>
    </form>
    '''

if __name__ == '__main__':
    with app.app_context():
        app.logger.info("开始初始化应用...")
        try:
            db.drop_all()  # 删除所有表
            app.logger.info("已删除所有数据库表")
            
            db.create_all()  # 重新创建所有表
            app.logger.info("已重新创建所有数据库表")
            
            # 创建默认的超级管理员
            admin = create_admin_user()
            if admin:
                app.logger.info(f"管理员用户创建成功: ID={admin.id}, 用户名={admin.username}")
            else:
                app.logger.error("管理员用户创建失败")
        except Exception as e:
            app.logger.error(f"应用初始化过程中出错: {str(e)}")
    
    # 启动心跳检查线程
    try:
        heartbeat_thread = threading.Thread(target=start_heartbeat_checker, daemon=True)
        heartbeat_thread.start()
        app.logger.info("心跳检查线程已启动")
    except Exception as e:
        app.logger.error(f"启动心跳检查线程失败: {str(e)}")
    
    # 运行应用（允许外部访问）
    app.logger.info("开始运行应用服务器...")
    socketio.run(app, 
                host='127.0.0.1',  # 允许外部访问
                port=8000, 
                debug=True, 
                allow_unsafe_werkzeug=True) 