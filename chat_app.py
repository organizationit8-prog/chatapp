# chat_app.py
"""
Single-file Flask + Flask-SocketIO chat app with:
- responsive mobile-first UI (yellow theme)
- clickable unread notifications -> opens chat
- image sending (uploads to static/uploads)
- typing indicator, presence (online), read receipts (seen)
- admin user and admin panel
- emoji profile pictures + emoji picker in chat
Run: python chat_app.py
"""
import eventlet
eventlet.monkey_patch()

import os
import random
import string
import sqlite3
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, request, redirect, session, url_for, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, join_room, leave_room, emit

# ----- Config & paths -----
BASE = Path(__file__).parent
DB = str(BASE / "chat_app.db")
UPLOAD_DIR = BASE / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "replace-in-prod")
socketio = SocketIO(app, cors_allowed_origins="*")  # you can restrict origins in production

# ----- DB helpers -----
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            code TEXT UNIQUE,
            password TEXT,
            avatar TEXT,
            is_admin INTEGER DEFAULT 0,
            online INTEGER DEFAULT 0,
            emoji TEXT DEFAULT '🙂'
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            friend_id INTEGER,
            UNIQUE(user_id, friend_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            message TEXT,
            msg_type TEXT DEFAULT 'text',
            seen INTEGER DEFAULT 0,
            timestamp TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            from_user INTEGER,
            unread INTEGER DEFAULT 1,
            last_ts TEXT
        )
    ''')
    conn.commit()

    # Backwards-compatible: ensure emoji column exists (for older DBs)
    c.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in c.fetchall()]
    if 'emoji' not in cols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN emoji TEXT DEFAULT '🙂'")
            conn.commit()
            print("[init_db] Added emoji column to users table")
        except Exception as e:
            print("[init_db] Could not add emoji column:", e)

    # create admin if not exists
    # user asked admin login to be: username 'ansh' password 'ansh17'
    ADMIN_USER = "ansh"
    ADMIN_PASS = "ansh17"
    c.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,))
    if not c.fetchone():
        pw = generate_password_hash(ADMIN_PASS)
        code = "ADMIN" + ''.join(random.choices(string.digits, k=3))
        avatar = "https://i.pravatar.cc/150?u=admin"
        # note: we explicitly set is_admin=1 and emoji '👑'
        c.execute("INSERT INTO users (username, code, password, avatar, is_admin, emoji) VALUES (?,?,?,?,1,?)",
                  (ADMIN_USER, code, pw, avatar, '👑'))
        print(f"[init_db] created admin '{ADMIN_USER}' code='{code}'")
    conn.commit()
    conn.close()

def db_query_one(q, params=()):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(q, params)
    r = c.fetchone()
    conn.close()
    return r

def db_query_all(q, params=()):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(q, params)
    r = c.fetchall()
    conn.close()
    return r

def db_exec(q, params=()):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(q, params)
    conn.commit()
    conn.close()

init_db()

# ----- Utility functions -----
def generate_code(n=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

def allowed_file(fn):
    return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED

# return user tuple including emoji at index 7 (id,username,code,password,avatar,is_admin,online,emoji)
def get_user_by_username(u): return db_query_one("SELECT id,username,code,password,avatar,is_admin,online,emoji FROM users WHERE username=?", (u,))
def get_user_by_code(c): return db_query_one("SELECT id,username,code,password,avatar,is_admin,online,emoji FROM users WHERE code=?", (c,))
def get_user_by_id(i): return db_query_one("SELECT id,username,code,password,avatar,is_admin,online,emoji FROM users WHERE id=?", (i,))

def ensure_contact(user_id, other_id):
    if user_id == other_id: return
    db_exec("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?,?)", (user_id, other_id))

# get_friends returns: id, username, avatar, code, unread, emoji
def get_friends(user_id):
    # Use COALESCE to ensure unread is numeric (0 if none)
    return db_query_all('''
        SELECT u.id, u.username, u.avatar, u.code,
               COALESCE((SELECT SUM(unread) FROM notifications n WHERE n.user_id=? AND n.from_user=u.id), 0) as unread,
               u.emoji
        FROM users u JOIN friends f ON f.friend_id=u.id
        WHERE f.user_id=?
        ORDER BY u.username
    ''', (user_id, user_id))

# get_messages returns sender_id, message, msg_type, seen, timestamp
def get_messages(a,b):
    return db_query_all('''
        SELECT sender_id, message, msg_type, seen, timestamp FROM messages
        WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
        ORDER BY id ASC
    ''', (a,b,b,a))

def add_notification(to_user, from_user):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    existing = db_query_one("SELECT id FROM notifications WHERE user_id=? AND from_user=?", (to_user, from_user))
    if existing:
        db_exec("UPDATE notifications SET unread = unread + 1, last_ts=? WHERE id=?", (now, existing[0]))
    else:
        db_exec("INSERT INTO notifications (user_id, from_user, unread, last_ts) VALUES (?,?,?,?)", (to_user, from_user, 1, now))

def get_unread_total(user_id):
    r = db_query_one("SELECT COALESCE(SUM(unread),0) FROM notifications WHERE user_id=?", (user_id,))
    return int(r[0]) if r and r[0] is not None else 0

def clear_notifications(user_id, from_user):
    db_exec("DELETE FROM notifications WHERE user_id=? AND from_user=?", (user_id, from_user))
    db_exec("UPDATE messages SET seen=1 WHERE receiver_id=? AND sender_id=?", (user_id, from_user))

# ----- Routes -----
@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = get_user_by_username(username)
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = bool(user[5])
            db_exec("UPDATE users SET online=1 WHERE id=?", (user[0],))
            return redirect(url_for('home'))
        return render_template_string(LOGIN_HTML, error="Invalid username/password")
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
def logout():
    uid = session.get('user_id')
    if uid:
        db_exec("UPDATE users SET online=0 WHERE id=?", (uid,))
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            return render_template_string(REGISTER_HTML, error="Fill all fields")
        avatar = f"https://i.pravatar.cc/150?u={username}"
        code = generate_code()
        pw = generate_password_hash(password)
        try:
            db_exec("INSERT INTO users (username, code, password, avatar, emoji) VALUES (?,?,?,?,?)", (username, code, pw, avatar, '🙂'))
            return redirect(url_for('login'))
        except Exception:
            return render_template_string(REGISTER_HTML, error="Username taken")
    return render_template_string(REGISTER_HTML)

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    friends = get_friends(uid)
    unread = get_unread_total(uid)
    recent = db_query_all('''
        SELECT u.id, u.username, u.avatar,
               COALESCE((SELECT SUM(unread) FROM notifications n WHERE n.user_id=? AND n.from_user=u.id), 0) as unread,
               u.emoji
        FROM users u
        WHERE EXISTS (SELECT 1 FROM messages m WHERE (m.receiver_id=? AND m.sender_id=u.id) OR (m.receiver_id=u.id AND m.sender_id=?))
        LIMIT 20
    ''', (uid, uid, uid))
    return render_template_string(HOME_HTML, username=session['username'], friends=friends, unread=unread, recent=recent, is_admin=session.get('is_admin', False))

@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'user_id' not in session: return redirect(url_for('login'))
    code = request.form.get('code','').strip()
    f = get_user_by_code(code)
    if f and f[0] != session['user_id']:
        db_exec("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?,?)", (session['user_id'], f[0]))
    return redirect(url_for('home'))

@app.route('/chat/<int:friend_id>')
def chat(friend_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    friend = get_user_by_id(friend_id)
    if not friend: return "Not found", 404
    uid = session['user_id']
    ensure_contact(uid, friend_id)  # ensure chat shows in list
    messages = get_messages(uid, friend_id)
    # mark messages as seen for this pair and clear notifications
    clear_notifications(uid, friend_id)
    return render_template_string(CHAT_HTML, friend=friend, messages=messages, user_id=uid)

@app.route('/profile', methods=['GET','POST'])
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    if request.method == 'POST':
        # save emoji
        emoji = request.form.get('emoji','🙂').strip()[:4]  # limit length
        db_exec("UPDATE users SET emoji=? WHERE id=?", (emoji, uid))
        return redirect(url_for('profile'))
    u = get_user_by_id(uid)
    friends = get_friends(uid)
    return render_template_string(PROFILE_HTML, user=u, friends=friends)

@app.route('/admin')
def admin():
    # protect admin
    if not session.get('is_admin'):
        return "Access denied"

    # users: show list of users
    users = db_query_all("SELECT id, username, avatar, emoji, code FROM users ORDER BY id DESC")

    # fetch last 300 messages for history
    messages = db_query_all('''
        SELECT m.id, m.sender_id, m.receiver_id, m.message, m.msg_type, m.timestamp
        FROM messages m
        ORDER BY m.id ASC
        LIMIT 300
    ''')

    # attach usernames
    enriched_msgs = []
    for m in messages:
        s_user = get_user_by_id(m[1])
        r_user = get_user_by_id(m[2])
        enriched_msgs.append({
            'sender_id': m[1],
            'sender_name': s_user[1] if s_user else m[1],
            'receiver_id': m[2],
            'receiver_name': r_user[1] if r_user else m[2],
            'message': m[3],
            'msg_type': m[4],
            'timestamp': m[5]
        })

    return render_template_string(ADMIN_HTML, users=users, messages=enriched_msgs)


@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'user_id' not in session: return jsonify({"error":"not logged in"}), 403
    if 'image' not in request.files: return jsonify({"error":"no file"}), 400
    f = request.files['image']
    if f.filename == '' or not allowed_file(f.filename): return jsonify({"error":"invalid"}), 400
    fn = secure_filename(f"{int(datetime.now().timestamp())}_{session['user_id']}_{f.filename}")
    dest = UPLOAD_DIR / fn
    f.save(dest)
    return jsonify({"url": url_for('uploaded_file', filename=fn)})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ----- SocketIO events -----
@socketio.on('connect')
def on_connect():
    pass

@socketio.on('join_user')
def join_user(data):
    try:
        uid = int(data.get('user_id'))
    except:
        return
    join_room(f"user_{uid}")
    db_exec("UPDATE users SET online=1 WHERE id=?", (uid,))
    emit('presence_update', {'user_id': uid, 'online': 1}, broadcast=True)

@socketio.on('leave_user')
def leave_user(data):
    try:
        uid = int(data.get('user_id'))
    except:
        return
    leave_room(f"user_{uid}")
    db_exec("UPDATE users SET online=0 WHERE id=?", (uid,))
    emit('presence_update', {'user_id': uid, 'online': 0}, broadcast=True)

@socketio.on('join_chat')
def join_chat(data):
    try:
        a = int(data.get('a')); b = int(data.get('b'))
    except:
        return
    room = f"chat_{min(a,b)}_{max(a,b)}"
    join_room(room)

@socketio.on('typing')
def on_typing(data):
    emit('typing', data, room=f"user_{data.get('to')}")

@socketio.on('send_message')
def on_send_message(data):
    try:
        s = int(data.get('sender_id')); r = int(data.get('receiver_id'))
    except:
        return
    msg = data.get('message', '')
    msg_type = data.get('msg_type', 'text')
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db_exec("INSERT INTO messages (sender_id, receiver_id, message, msg_type, timestamp) VALUES (?,?,?,?,?)", (s, r, msg, msg_type, ts))
    # ensure receiver sees sender in contacts (so they can open chat)
    ensure_contact(r, s)
    # add/aggregate notification
    add_notification(r, s)
    # emit to conversation room
    room = f"chat_{min(s,r)}_{max(s,r)}"
    emit('receive_message', {'sender_id': s, 'message': msg, 'msg_type': msg_type, 'timestamp': ts}, room=room)
    # emit notification to receiver room so home can update
    emit('notification', {'from': s, 'message': msg, 'msg_type': msg_type, 'timestamp': ts}, room=f"user_{r}")

    # --- ADMIN LIVE MONITOR: emit to admin_room so any admin clients see messages in real-time ---
    try:
        emit('admin_monitor', {'sender_id': s, 'receiver_id': r, 'message': msg, 'msg_type': msg_type, 'timestamp': ts}, room='admin_room')
    except Exception:
        # don't fail message flow if admin room emission fails
        pass

@socketio.on('mark_read')
def on_mark_read(data):
    try:
        uid = int(data.get('user_id')); fr = int(data.get('from_user'))
    except:
        return
    clear_notifications(uid, fr)
    emit('read_update', {'user_id': uid, 'from_user': fr}, room=f"user_{fr}")

@socketio.on('join_admin')
def join_admin(data):
    uid = data.get('user_id')
    if not uid:
        return

    # verify admin
    u = get_user_by_id(uid)
    if not u or not u[5]:  # is_admin is index 5
        return

    join_room("admin_room")
    print("Admin joined live monitor")

# ----- Templates (responsive/mobile-first UI) -----
LOGIN_HTML = '''
<!doctype html><html><head><meta charset="utf-8"><title>Login</title>
<style>
:root{--yellow:#fff0cc;--accent:#ffb74d}
*{box-sizing:border-box;font-family:Inter,Arial}
body{margin:0;background:linear-gradient(0deg,#fff4d6 0%,#fff 120%);display:flex;justify-content:center;align-items:center;height:100vh}
.card{width:100%;max-width:420px;background:#fff;padding:24px;border-radius:16px;box-shadow:0 12px 30px rgba(0,0,0,0.08)}
input{width:100%;padding:12px;border-radius:10px;border:1px solid #eee;margin:8px 0}
button{background:var(--accent);border:none;padding:12px;border-radius:12px;font-weight:700;color:white;width:100%}
small{color:#666}
a{color:#333;text-decoration:none}
.err{color:#b00020}
</style></head><body>
<div class="card">
  <h2>Sign in</h2>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="post">
    <input name="username" placeholder="Username" autofocus>
    <input name="password" type="password" placeholder="Password">
    <button type="submit">Sign in</button>
  </form>
  <p style="text-align:center;margin-top:12px"><small>Don't have an account? <a href="/register">Register</a></small></p>
  <p style="text-align:center;margin-top:6px"><small>Admin login: <strong>ansh</strong> / <strong>ansh17</strong></small></p>
</div>
</body></html>
'''

REGISTER_HTML = '''
<!doctype html><html><head><meta charset="utf-8"><title>Register</title>
<style>body{background:#fff4d6;font-family:Inter,Arial;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#fff;padding:20px;border-radius:16px;max-width:420px;width:100%;box-shadow:0 12px 30px rgba(0,0,0,0.06)}
input{width:100%;padding:10px;border-radius:10px;border:1px solid #eee;margin:8px 0}
button{background:#ffb74d;padding:10px;border-radius:10px;border:none;width:100%}
</style></head><body>
<div class="card">
  <h2>Create account</h2>
  {% if error %}<div style="color:red">{{ error }}</div>{% endif %}
  <form method="post">
    <input name="username" placeholder="Username">
    <input name="password" placeholder="Password" type="password">
    <button>Register</button>
  </form>
  <p style="text-align:center;margin-top:12px"><a href="/login">Back to sign in</a></p>
</div>
</body></html>
'''

HOME_HTML = '''
<!doctype html><html><head><meta charset="utf-8"><title>Messages</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.4/socket.io.min.js"></script>
<style>
:root{--accent:#ffb74d}
body{margin:0;background:linear-gradient(0deg,#fff4d6 0%,#fff 120%);font-family:Inter,Arial}
.container{max-width:420px;margin:0 auto;padding:12px}
.header{display:flex;align-items:center;gap:10px;padding:10px}
.header .right{margin-left:auto}
.card{background:#fff;border-radius:16px;padding:12px;margin-top:10px;box-shadow:0 10px 24px rgba(0,0,0,0.06)}
.friend-item{display:flex;align-items:center;padding:10px;border-bottom:1px solid #f4f4f4}
.friend-item:last-child{border-bottom:none}
.avatar-emoji{width:50px;height:50px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:26px;margin-right:12px;background:#fff}
.avatar-img{width:50px;height:50px;border-radius:50%;overflow:hidden;margin-right:12px}
.friend-meta{flex:1}
.badge{background:#ff5252;color:white;padding:6px 8px;border-radius:14px;font-weight:700}
.small{font-size:13px;color:#666}
.controls{display:flex;gap:8px;margin-top:10px}
.add-input{flex:1;padding:8px;border-radius:10px;border:1px solid #eee}
.btn{background:var(--accent);padding:8px 12px;border-radius:10px;border:none;color:white}
.recent{display:flex;gap:8px;overflow-x:auto;margin-top:8px}
.recent .chip{background:#fff;padding:8px;border-radius:12px;min-width:120px;box-shadow:0 8px 18px rgba(0,0,0,0.04)}
.footer{margin-top:12px;text-align:center;color:#666}
</style></head><body>
<div class="container">
  <div class="header">
    <div><h2 style="margin:0">Messages</h2><div class="small">Hi, <strong>{{ username }}</strong></div></div>
    <div class="right"><a href="/profile">Profile</a> | <a href="/logout">Logout</a> {% if is_admin %}| <a href="/admin">Admin</a>{% endif %}</div>
  </div>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <input id="search" placeholder="Search chats" style="flex:1;padding:8px;border-radius:10px;border:1px solid #eee">
      <div style="margin-left:8px;font-weight:700">{{ unread }} unread</div>
    </div>

    <div style="margin-top:10px" id="friend-list">
      {% for f in friends %}
        <a href="/chat/{{ f[0] }}" style="text-decoration:none;color:inherit">
        <div class="friend-item">
          {% if f[5] %}
            <div class="avatar-emoji">{{ f[5] }}</div>
          {% else %}
            <div class="avatar-img"><img src="{{ f[2] }}" width="50" height="50"></div>
          {% endif %}
          <div class="friend-meta">
            <div style="font-weight:700">{{ f[1] }}</div>
            <div class="small">{{ f[3] }}</div>
          </div>
          {% if f[4] and (f[4]|int) > 0 %}
            <div class="badge">{{ f[4] }}</div>
          {% endif %}
        </div>
        </a>
      {% else %}
        <div style="padding:12px;color:#666">No contacts yet. Add someone by code.</div>
      {% endfor %}
    </div>

    <form class="controls" method="post" action="/add_friend">
      <input name="code" class="add-input" placeholder="Friend code">
      <button class="btn" type="submit">Add</button>
    </form>
  </div>

  <div class="card" style="margin-top:12px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div style="font-weight:700">Recent activity</div>
      <div class="small"><a href="/home">Refresh</a></div>
    </div>
    <div class="recent" id="recent">
      {% for r in recent %}
        <div class="chip">
          <div style="font-weight:700">{{ r[1] }}</div>
          {% if r[3] and (r[3]|int) > 0 %}<div class="small" style="color:#c00">{{ r[3] }} unread</div>{% endif %}
          <div style="margin-top:6px"><a href="/chat/{{ r[0] }}">Open</a></div>
        </div>
      {% endfor %}
    </div>
  </div>

  <div class="footer">Tip: click a notification or a chat to open and mark messages as read.</div>
</div>

<script>
var socket = io();
var user_id = {{ session['user_id'] if session.get('user_id') else 'null' }};
if(user_id){
  socket.emit('join_user', {'user_id': user_id});
}
// simple notification handler (you can expand to update DOM)
socket.on('notification', function(d){
  console.log('notification', d);
});
</script>
</body></html>
'''


CHAT_HTML = '''
<!doctype html><html><head><meta charset="utf-8"><title>Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.4/socket.io.min.js"></script>
<style>
body{margin:0;background:#fff4d6;font-family:Inter,Arial}
.app{max-width:420px;margin:0 auto;padding-bottom:100px}
.header{display:flex;align-items:center;gap:12px;padding:12px}
.avatar-emoji{width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;margin-right:12px;background:#fff}
.avatar{width:48px;height:48px;border-radius:50%;overflow:hidden}
.chatbox{background:#fff;border-radius:16px;margin:12px;padding:12px;min-height:60vh;display:flex;flex-direction:column}
#messages{flex:1;overflow:auto;padding:6px}
.bubble{max-width:76%;padding:12px;border-radius:12px;margin:8px 0;display:inline-block;box-shadow:0 2px 6px rgba(0,0,0,0.06);font-size:15px}
.me{background:#f7f7f7;border-left:8px solid #d1f7c4;margin-left:auto;border-top-right-radius:4px}
.them{background:#fff;border-right:8px solid #e0e0e0;border-top-left-radius:4px}
.timestamp{font-size:11px;color:#666;margin-top:4px}
.compose{position:fixed;left:0;bottom:0;width:100%;display:flex;justify-content:center;padding:10px;background:transparent}
.compose-inner{max-width:420px;display:flex;gap:8px;width:100%;padding:10px}
.input{flex:1;padding:12px;border-radius:999px;border:1px solid #eee;background:#fff}
.btn{background:#ffb74d;border:none;padding:10px 14px;border-radius:999px;cursor:pointer;color:white;font-weight:700}
img.msg-img{max-width:240px;border-radius:8px;display:block}
.typing{font-size:12px;color:#666;margin-left:6px}
.emoji-btn{font-size:22px;background:transparent;border:none;cursor:pointer}
.emoji-panel{position:fixed;right:14px;bottom:84px;background:#fff;padding:8px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.12);display:none;grid-template-columns:repeat(6,1fr);gap:6px}
.emoji-item{font-size:20px;cursor:pointer;padding:6px}
.online-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-left:8px}
.online{background:#4caf50}
.offline{background:#ccc}
</style></head><body>
<div class="app">
  <div class="header">
    {% if friend[7] %}
      <div class="avatar-emoji">{{ friend[7] }}</div>
    {% else %}
      <div class="avatar"><img src="{{ friend[4] }}" width="48" height="48"></div>
    {% endif %}
    <div>
      <div style="font-weight:700">{{ friend[1] }} <span id="presence" class="online-dot {{ 'online' if friend[6] else 'offline' }}"></span></div>
      <div class="small">{{ friend[2] }}</div>
    </div>
    <div style="margin-left:auto"><a href="/home">Back</a></div>
  </div>

  <div class="chatbox">
    <div id="messages">
      {% for m in messages %}
        {% if m[0] == user_id %}
          {% if m[2] == 'image' %}
            <div class="bubble me"><img class="msg-img" src="{{ m[1] }}"></div>
            <div class="timestamp" style="text-align:right">{{ m[4] }}</div>
          {% else %}
            <div class="bubble me">{{ m[1] }}</div>
            <div class="timestamp" style="text-align:right">{{ m[4] }}</div>
          {% endif %}
        {% else %}
          {% if m[2] == 'image' %}
            <div class="bubble them"><img class="msg-img" src="{{ m[1] }}"></div>
            <div class="timestamp">{{ m[4] }}</div>
          {% else %}
            <div class="bubble them">{{ m[1] }}</div>
            <div class="timestamp">{{ m[4] }}</div>
          {% endif %}
        {% endif %}
      {% endfor %}
    </div>
  </div>
</div>

<div class="emoji-panel" id="emojiPanel"></div>

<div class="compose">
  <div class="compose-inner">
    <button class="emoji-btn" id="openEmoji">😀</button>
    <input id="msg" class="input" placeholder="Write a message...">
    <input id="imgfile" type="file" accept="image/*" style="display:none">
    <button class="btn" onclick="document.getElementById('imgfile').click()">📷</button>
    <button class="btn" onclick="sendText()">Send</button>
  </div>
</div>

<script>
var socket = io();
var user_id = {{ session['user_id'] }};
var friend_id = {{ friend[0] }};
var room = 'chat_' + Math.min(user_id,friend_id) + '_' + Math.max(user_id,friend_id);
socket.emit('join_user', {'user_id': user_id});
socket.emit('join_chat', {'a': user_id, 'b': friend_id});
socket.on('connect', ()=>{ socket.emit('join_chat', {'a': user_id, 'b': friend_id}); });

// populate emoji panel
var emojiList = ["😀","😁","😂","🤣","😊","😍","😎","🙂","🙃","😉","😅","😭","😡","🤩","👍","🙏","🔥","🎉","💯","👑"];
var ep = document.getElementById('emojiPanel');
emojiList.forEach(function(e){
  var d = document.createElement('div');
  d.className = 'emoji-item'; d.textContent = e;
  d.onclick = function(){ document.getElementById('msg').value += e; ep.style.display='none'; }
  ep.appendChild(d);
});
document.getElementById('openEmoji').onclick = function(){ ep.style.display = ep.style.display === 'grid' ? 'none' : 'grid'; }

// receive messages
socket.on('receive_message', function(d){
  var m = d.message, t = d.timestamp, type = d.msg_type, s = d.sender_id;
  var c = document.getElementById('messages');
  var html = '';
  if(type=='image'){
    html = '<div class="bubble '+(s==user_id?'me':'them')+'"><img class="msg-img" src="'+m+'"></div><div class="timestamp" style="text-align:'+(s==user_id?'right':'left')+'">'+t+'</div>';
  } else {
    html = '<div class="bubble '+(s==user_id?'me':'them')+'">'+escapeHtml(m)+'</div><div class="timestamp" style="text-align:'+(s==user_id?'right':'left')+'">'+t+'</div>';
  }
  c.innerHTML += html;
  c.scrollTop = c.scrollHeight;
});

// notification event
socket.on('notification', function(d){
  if(d.from == friend_id){
    console.log("new message from", d.from);
  }
});

function sendText(){
  var v = document.getElementById('msg').value;
  if(!v) return;
  socket.emit('send_message', {'sender_id':user_id,'receiver_id':friend_id,'message':v,'msg_type':'text'});
  document.getElementById('msg').value = '';
}

document.getElementById('imgfile').addEventListener('change', function(e){
  var f = e.target.files[0];
  if(!f) return;
  var fd = new FormData();
  fd.append('image', f);
  fetch('/upload_image',{method:'POST',body:fd}).then(r=>r.json()).then(data=>{
    if(data.url){
      socket.emit('send_message', {'sender_id':user_id,'receiver_id':friend_id,'message':data.url,'msg_type':'image'});
    } else {
      alert('Upload failed');
    }
  }).catch(()=>alert('Upload failed'));
});

// typing indicator
var typingTimer;
document.getElementById('msg').addEventListener('input', function(){
  socket.emit('typing', {'from': user_id, 'to': friend_id});
  clearTimeout(typingTimer);
  typingTimer = setTimeout(()=>{}, 1000);
});

function escapeHtml(text){ return (text||'').replace(/[&<>"']/g, function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m];}); }

// mark messages as read when page is opened
fetch('/dummy_mark_read', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({user_id:user_id, from_user: friend_id})})
  .then(()=>{ socket.emit('mark_read', {'user_id': user_id, 'from_user': friend_id}); });

</script>
</body></html>
'''

PROFILE_HTML = '''
<!doctype html><html><head><meta charset="utf-8"><title>Profile</title></head>
<body style="font-family:Inter,Arial;background:#fff4d6;padding:20px">
  <div style="max-width:720px;margin:0 auto;background:#fff;padding:20px;border-radius:12px">
    <h2>{{ user[1] }}'s Profile</h2>
    {% if user[7] %}
      <div style="font-size:64px">{{ user[7] }}</div>
    {% else %}
      <img src="{{ user[4] }}" width="120"><br>
    {% endif %}
    <form method="post">
      <label>Set profile emoji (1 character recommended):</label><br>
      <input name="emoji" value="{{ user[7] }}" style="font-size:20px;padding:6px;border-radius:8px;border:1px solid #ddd"><br><br>
      <button type="submit" style="background:#ffb74d;padding:8px 12px;border-radius:8px;border:none;color:white">Save Emoji</button>
    </form>
    <hr>
    Code: <strong>{{ user[2] }}</strong>
    <h3>Friends</h3>
    <ul>{% for f in friends %}<li>{% if f[5] %}{{ f[5] }} {% else %}<img src="{{ f[2] }}" width="20">{% endif %} {{ f[1] }} ({{ f[3] }})</li>{% endfor %}</ul>
    <a href="/home">Back</a>
  </div>
</body></html>
'''

ADMIN_HTML = '''
<!doctype html><html><head><meta charset="utf-8"><title>Admin</title></head>
<body style="font-family:Inter,Arial;background:#fff4d6;padding:20px">
  <div style="max-width:720px;margin:0 auto;background:#fff;padding:20px;border-radius:12px">
    <h2>Admin Panel</h2>
    <ul>{% for u in users %}<li>{{ u[1] }} - <a href="/chat/{{ u[0] }}">Open Chat</a> ({{ u[4] }})</li>{% endfor %}</ul>
    <a href="/home">Back</a>
  </div>
    <h3>Live message stream</h3>
<div id="live"
     style="background:#fff;border-radius:10px;padding:10px;
            height:300px;overflow:auto;box-shadow:0 0 12px rgba(0,0,0,0.08)">
</div><h4>Message history</h4>
<div id="history"
     style="background:#fff;border-radius:10px;padding:10px;
            max-height:400px;overflow:auto;box-shadow:0 0 12px rgba(0,0,0,0.08)">
    {% for m in messages %}
        <div style="padding:8px;margin-bottom:6px;border-bottom:1px solid #eee">
            <b>{{ m.sender_name }} → {{ m.receiver_name }}</b><br>
            {% if m.msg_type == 'image' %}
                <img src="{{ m.message }}" width="120">
            {% else %}
                {{ m.message }}
            {% endif %}
            <br><small>{{ m.timestamp }}</small>
        </div>
    {% endfor %}
</div>

<h3>Live message stream</h3>
<div id="live"
     style="background:#fff;border-radius:10px;padding:10px;
            height:300px;overflow:auto;box-shadow:0 0 12px rgba(0,0,0,0.08)">
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.4/socket.io.min.js"></script>
<script>
var socket = io();
var admin_id = {{ session['user_id'] }};

// join admin room
socket.emit('join_admin', {'user_id': admin_id});

// listen messages
socket.on('admin_monitor', function(d){
    let box = document.getElementById("live");
    let item = document.createElement("div");
    item.style.padding = "8px";
    item.style.marginBottom = "6px";
    item.style.borderBottom = "1px solid #eee";
    item.innerHTML = "<b>" + d.sender_id + " → " + d.receiver_id + "</b><br>" +
                     (d.msg_type === "image"
                      ? "<img src='" + d.message + "' width='120'>"
                      : d.message) +
                     "<br><small>" + d.timestamp + "</small>";
    box.prepend(item);
});
</script>

</body></html>
'''

# Dummy endpoint used by chat JS to mark read via server (keeps logic server-side)
@app.route('/dummy_mark_read', methods=['POST'])
def dummy_mark_read():
    if 'user_id' not in session: return jsonify({}), 403
    data = request.get_json() or {}
    uid = session['user_id']
    fr = int(data.get('from_user', 0) or 0)
    if fr:
        clear_notifications(uid, fr)
    return jsonify({}), 200

# run app
if __name__ == '__main__':
    print("Starting chat_app on http://0.0.0.0:5000")
    import os
port = int(os.environ.get("PORT", 5000))
socketio.run(app, host='0.0.0.0', port=port)
