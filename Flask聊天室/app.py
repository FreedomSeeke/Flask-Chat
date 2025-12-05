import os
import uuid
import random
import platform
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pymysql

# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = '30cd3ad5fa7e09f62affc67c14700d54d24f3fc3fceac272'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123456@localhost:3306/wechat_chat?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 5
app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600

# -------------- 文件上传配置 --------------
UPLOAD_FOLDER = os.path.join(app.root_path, 'static/uploads')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg', 'm4a', 'flac'}
MAX_IMAGE_SIZE = 20 * 1024 * 1024
MAX_AUDIO_SIZE = 100 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 初始化数据库和SocketIO
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# -------------- 数据库模型修改 --------------
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    online = db.Column(db.Boolean, default=False)
    # 登录验证相关字段
    login_attempts = db.Column(db.Integer, default=0)  # 登录失败次数
    lock_time = db.Column(db.DateTime, nullable=True)  # 账号锁定时间
    verify_code = db.Column(db.String(4), nullable=True)  # 验证码
    # 权限/状态字段
    role = db.Column(db.String(20), default='user')  # user:普通用户, admin:管理员
    is_banned = db.Column(db.Boolean, default=False)  # 是否封号
    is_muted = db.Column(db.Boolean, default=False)  # 是否禁言
    # 登录信息
    login_device = db.Column(db.String(100), nullable=True)  # 登录设备
    last_login_time = db.Column(db.DateTime, nullable=True)  # 最后登录时间


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_type = db.Column(db.String(20), nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')


# -------------- 工具函数 --------------
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


# 生成4位数字验证码
def generate_verify_code():
    return str(random.randint(1000, 9999))


# 检查账号是否锁定（临时锁定）
def is_user_locked(user):
    if not user.lock_time:
        return False
    if datetime.now() - user.lock_time < timedelta(minutes=1):
        return True
    # 超过锁定时间，重置状态
    user.lock_time = None
    user.login_attempts = 0
    db.session.commit()
    return False


# 获取登录设备信息
def get_login_device():
    """获取用户登录设备/系统信息"""
    user_agent = request.headers.get('User-Agent', '')
    system = platform.system()  # Windows/Linux/Mac
    device_info = f"{system} - {user_agent[:50]}..."  # 截取部分UA信息
    return device_info


# 初始化管理员账号
def init_admin_account():
    """启动时自动创建管理员账号"""
    admin = User.query.filter_by(username='Administrator').first()
    if not admin:
        # 管理员密码：admin123（可自行修改）
        hashed_pwd = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin = User(
            username='Administrator',
            password=hashed_pwd,
            role='admin',
            is_banned=False,
            is_muted=False
        )
        db.session.add(admin)
        db.session.commit()
        print("管理员账号初始化完成：用户名=Administrator，密码=admin123")


# -------------- 登录管理器回调 --------------
@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    # 封号用户无法加载
    if user and user.is_banned:
        return None
    return user


# -------------- 权限装饰器 --------------
def admin_required(f):
    """管理员权限装饰器"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# -------------- 路由修改 --------------
@app.route('/')
@login_required
def index():
    # 管理员跳转到管理面板
    if current_user.role == 'admin':
        return redirect(url_for('admin_panel'))
    # 普通用户检查是否禁言/封号（封号已在load_user中拦截）
    users = User.query.filter(
        User.id != current_user.id,
        User.is_banned == False  # 不显示封号用户
    ).all()
    return render_template('index.html',
                           current_user=current_user,
                           users=users,
                           is_muted=current_user.is_muted)


# 管理员面板
@app.route('/admin/panel')
@login_required
@admin_required
def admin_panel():
    """管理员面板：查看所有用户"""
    users = User.query.all()
    return render_template('admin_panel.html',
                           current_user=current_user,
                           users=users)


# 管理员修改用户状态（禁言/封号）
@app.route('/admin/update_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user_status(user_id):
    user = User.query.get_or_404(user_id)
    # 禁止管理员修改自己的状态
    if user.id == current_user.id:
        return jsonify({'code': 0, 'msg': '无法修改自身状态'})

    action = request.form.get('action')
    if action == 'mute':
        user.is_muted = not user.is_muted
        msg = f"用户{user.username}已{'禁言' if user.is_muted else '解除禁言'}"
    elif action == 'ban':
        user.is_banned = not user.is_banned
        # 封号同时下线
        if user.is_banned:
            user.online = False
        msg = f"用户{user.username}已{'封号' if user.is_banned else '解封'}"
    else:
        return jsonify({'code': 0, 'msg': '无效操作'})

    db.session.commit()
    return jsonify({'code': 1, 'msg': msg})


# 管理员查看所有聊天记录
@app.route('/admin/view_messages/<int:user_id>')
@login_required
@admin_required
def view_all_messages(user_id):
    """查看指定用户的所有聊天记录"""
    target_user = User.query.get_or_404(user_id)
    # 查询该用户发送/接收的所有消息
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).order_by(Message.timestamp.desc()).all()

    # 格式化消息数据
    message_list = []
    for msg in messages:
        sender = User.query.get(msg.sender_id)
        receiver = User.query.get(msg.receiver_id)
        message_list.append({
            'id': msg.id,
            'sender': sender.username,
            'receiver': receiver.username,
            'content': msg.content,
            'file_type': msg.file_type,
            'file_path': msg.file_path,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })

    return render_template('admin_messages.html',
                           current_user=current_user,
                           target_user=target_user,
                           messages=message_list)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        verify_code_input = request.form.get('verify_code', '')

        # 查询用户
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('login.html', error='用户名不存在', show_verify=False)

        # 检查是否封号
        if user.is_banned:
            return render_template('login.html', error='该账号已被封号，无法登录', show_verify=False)

        # 检查临时锁定
        if is_user_locked(user):
            remain_time = (user.lock_time + timedelta(minutes=1) - datetime.now()).seconds
            return render_template('login.html', error=f'账号已锁定，请{remain_time}秒后重试', show_verify=False)

        # 验证码验证逻辑
        if user.login_attempts >= 3:
            if not verify_code_input or verify_code_input != user.verify_code:
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.lock_time = datetime.now()
                    db.session.commit()
                    return render_template('login.html', error='验证码错误，账号已锁定1分钟', show_verify=False)
                user.verify_code = generate_verify_code()
                db.session.commit()
                return render_template('login.html', error='验证码错误，请重新输入', verify_code=user.verify_code,
                                       show_verify=True)

            # 验证码正确，验证密码
            if check_password_hash(user.password, password):
                # 登录成功，更新登录信息
                user.login_attempts = 0
                user.verify_code = None
                user.online = True
                user.login_device = get_login_device()
                user.last_login_time = datetime.now()
                db.session.commit()
                login_user(user)
                return redirect(url_for('index'))
            else:
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.lock_time = datetime.now()
                    db.session.commit()
                    return render_template('login.html', error='密码错误，账号已锁定1分钟', show_verify=False)
                user.verify_code = generate_verify_code()
                db.session.commit()
                return render_template('login.html', error='密码错误，请重新输入', verify_code=user.verify_code,
                                       show_verify=True)
        else:
            # 无验证码，直接验证密码
            if check_password_hash(user.password, password):
                # 登录成功，更新登录信息
                user.login_attempts = 0
                user.verify_code = None
                user.online = True
                user.login_device = get_login_device()
                user.last_login_time = datetime.now()
                db.session.commit()
                login_user(user)
                return redirect(url_for('index'))
            else:
                user.login_attempts += 1
                db.session.commit()
                if user.login_attempts >= 3:
                    user.verify_code = generate_verify_code()
                    db.session.commit()
                    return render_template('login.html', error=f'密码错误（{user.login_attempts}/5），请输入验证码',
                                           verify_code=user.verify_code, show_verify=True)
                return render_template('login.html', error=f'密码错误（{user.login_attempts}/5）', show_verify=False)

    return render_template('login.html', error='', show_verify=False)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # 禁止注册管理员账号
    if request.method == 'POST':
        username = request.form['username']
        if username == 'Administrator':
            return '禁止注册该用户名'
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return '用户名已存在'
        hashed_pwd = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pwd)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))


# -------------- 文件上传接口 --------------
@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    # 禁言/封号用户禁止上传文件
    if current_user.is_muted or current_user.is_banned:
        return jsonify({'code': 0, 'msg': '您无权限上传文件'})

    if 'file' not in request.files:
        return jsonify({'code': 0, 'msg': '未选择文件'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'code': 0, 'msg': '文件名为空'})

    file_ext = file.filename.rsplit('.', 1)[1].lower()
    file_size = len(file.read())
    file.seek(0)

    file_type = None
    max_size = 0
    if allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
        file_type = 'image'
        max_size = MAX_IMAGE_SIZE
    elif allowed_file(file.filename, ALLOWED_AUDIO_EXTENSIONS):
        file_type = 'audio'
        max_size = MAX_AUDIO_SIZE
    else:
        return jsonify({'code': 0,
                        'msg': f'不支持的文件格式，仅支持图片({",".join(ALLOWED_IMAGE_EXTENSIONS)})和音频({",".join(ALLOWED_AUDIO_EXTENSIONS)})'})

    if file_size > max_size:
        return jsonify({'code': 0, 'msg': f'文件过大，{file_type}最大支持{max_size // 1024 // 1024}MB'})

    unique_filename = str(uuid.uuid4()) + '.' + file_ext
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)

    relative_path = f'/static/uploads/{unique_filename}'
    return jsonify({'code': 1, 'msg': '文件上传成功', 'data': {'file_type': file_type, 'file_path': relative_path}})


# -------------- 消息接口 --------------
@app.route('/get_messages/<int:receiver_id>')
@login_required
def get_messages(receiver_id):
    # 禁言用户仅能查看消息，无法发送
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()

    message_list = []
    for msg in messages:
        message_list.append({
            'sender': msg.sender.username,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'file_type': msg.file_type,
            'file_path': msg.file_path,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
        })
    return jsonify(message_list)


@app.route('/search_messages/<int:receiver_id>', methods=['GET'])
@login_required
def search_messages(receiver_id):
    keyword = request.args.get('keyword', '').strip()
    if not keyword:
        return jsonify({'code': 0, 'msg': '请输入搜索关键词', 'data': []})

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id)),
        Message.content.like(f'%{keyword}%')
    ).order_by(Message.timestamp).all()

    message_list = []
    for msg in messages:
        message_list.append({
            'sender': msg.sender.username,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'file_type': msg.file_type,
            'file_path': msg.file_path,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
        })
    return jsonify({'code': 1, 'msg': f'找到{len(message_list)}条结果', 'data': message_list})


@app.route('/clear_messages/<int:receiver_id>', methods=['POST'])
@login_required
def clear_messages(receiver_id):
    Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).delete()
    db.session.commit()
    return jsonify({'code': 1, 'msg': '聊天记录已清空'})


# -------------- SocketIO --------------
@socketio.on('connect')
@login_required
def handle_connect():
    # 禁言/封号用户禁止连接
    if current_user.is_muted or current_user.is_banned:
        emit('connect_error', {'msg': '您无权限连接聊天'})
        return
    print(f'用户 {current_user.username} 已连接')
    join_room(str(current_user.id))


@socketio.on('send_text_message')
@login_required
def handle_send_text_message(data):
    # 禁言/封号用户禁止发送消息
    if current_user.is_muted or current_user.is_banned:
        emit('message_error', {'msg': '您已被禁言/封号，无法发送消息'})
        return

    receiver_id = data['receiver_id']
    content = data['content'].strip()
    if not content:
        return

    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content,
        file_type=None,
        file_path=None
    )
    db.session.add(new_message)
    db.session.commit()

    message_data = {
        'sender': current_user.username,
        'sender_id': current_user.id,
        'content': content,
        'file_type': None,
        'file_path': None,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
    }
    emit('receive_message', message_data, room=str(receiver_id))
    emit('receive_message', message_data, room=str(current_user.id))


@socketio.on('send_file_message')
@login_required
def handle_send_file_message(data):
    # 禁言/封号用户禁止发送文件
    if current_user.is_muted or current_user.is_banned:
        emit('message_error', {'msg': '您已被禁言/封号，无法发送文件'})
        return

    receiver_id = data['receiver_id']
    file_type = data['file_type']
    file_path = data['file_path']

    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=None,
        file_type=file_type,
        file_path=file_path
    )
    db.session.add(new_message)
    db.session.commit()

    message_data = {
        'sender': current_user.username,
        'sender_id': current_user.id,
        'content': None,
        'file_type': file_type,
        'file_path': file_path,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
    }
    emit('receive_message', message_data, room=str(receiver_id))
    emit('receive_message', message_data, room=str(current_user.id))


@socketio.on('disconnect')
@login_required
def handle_disconnect():
    print(f'用户 {current_user.username} 已断开连接')
    current_user.online = False
    db.session.commit()
    leave_room(str(current_user.id))


# -------------- 初始化数据库 --------------
with app.app_context():
    db.create_all()
    init_admin_account()  # 初始化管理员账号
    print("MySQL数据库表初始化完成！")

# -------------- 运行应用 --------------
if __name__ == '__main__':
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)