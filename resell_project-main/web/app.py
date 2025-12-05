from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, session, flash
import pymysql
import os
import time
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# 업로드 폴더 생성
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# DB 연결 설정
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'db'),
    'user': os.getenv('DB_USER', 'community_user'),
    'password': os.getenv('DB_PASSWORD', 'community_pass'),
    'database': os.getenv('DB_NAME', 'community_db'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db_connection():
    """데이터베이스 연결 (재시도 로직 포함)"""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            return pymysql.connect(**DB_CONFIG)
        except pymysql.Error as e:
            if attempt < max_retries - 1:
                print(f"DB 연결 실패, 재시도 중... ({attempt + 1}/{max_retries})")
                time.sleep(2)
            else:
                raise e

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def format_price(price):
    """가격을 천 단위로 포맷팅"""
    return f"{price:,}원"

@app.template_filter('price_format')
def price_format_filter(price):
    return format_price(price)

@app.template_filter('datetime_format')
def datetime_format_filter(dt):
    if dt:
        if isinstance(dt, str):
            dt = datetime.fromisoformat(str(dt).replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M')
    return ''

def login_required(f):
    """로그인 필요 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """현재 로그인한 사용자 정보 가져오기"""
    if 'user_id' in session:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            # VULNERABLE: SQL Injection 취약
            cursor.execute(f"SELECT id, username, nickname, email FROM users WHERE id = '{session['user_id']}'")
            user = cursor.fetchone()
            conn.close()
            return user
        except:
            return None
    return None

@app.route('/')
def index():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 최근 등록된 상품 8개만 표시
        cursor.execute("""
        SELECT * FROM products
        WHERE status = '판매중'
        ORDER BY created_at DESC
        LIMIT 8
        """)
        products = cursor.fetchall()
        conn.close()
        user = get_current_user()
        return render_template('index.html', products=products, user=user)
    except Exception as e:
        return render_template('index.html', products=[], error=str(e), user=get_current_user())

@app.route('/products')
def product_list():
    try:
        category = request.args.get('category', '')
        location = request.args.get('location', '')
        search = request.args.get('search', '')
        status = request.args.get('status', '판매중')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABLE: SQL Injection 취약 - 동적 쿼리 문자열 연결
        base_query = "SELECT * FROM products WHERE 1=1"
        params = []
        
        if status:
            base_query += f" AND status = '{status}'"
        if category:
            base_query += f" AND category = '{category}'"
        if location:
            base_query += f" AND location LIKE '%{location}%'"
        if search:
            base_query += f" AND (title LIKE '%{search}%' OR description LIKE '%{search}%')"
        
        base_query += " ORDER BY created_at DESC"
        cursor.execute(base_query)  # NO PARAMS - VULNERABLE!
        
        products = cursor.fetchall()
        
        # 카테고리 목록 가져오기
        cursor.execute("SELECT DISTINCT category FROM products ORDER BY category")
        categories = [row['category'] for row in cursor.fetchall()]
        conn.close()
        
        user = get_current_user()   
        return render_template('product_list.html',
                             products=products,
                             categories=categories,
                             current_category=category,
                             current_location=location,
                             current_search=search,
                             current_status=status,
                             user=user)
    except Exception as e:
        return f"데이터베이스 오류: {str(e)}", 500

@app.route('/api/product/<string:product_id>')
def api_product_detail(product_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ✅ UNION 기반 SQLi - 따옴표 문제 해결!
        query = f"SELECT * FROM products WHERE id = '{product_id}'"
        print(f"DEBUG: Executing: {query}")
        
        cursor.execute(query)
        products = cursor.fetchall()  # fetchall()로 여러 행 가능
        conn.close()
        
        return jsonify({
            'status': 'success',
            'count': len(products),
            'products': products[:10],  # 최대 10개
            'sql_query_executed': query
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'debug': f"Query: {query}",
            'input': product_id
        }), 500
@app.route('/products/<int:product_id>')
def product_detail(product_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 조회수 증가 (굳이 필요 없으면 삭제해도 됨)
        cursor.execute("UPDATE products SET views = views + 1 WHERE id = %s", (product_id,))
        conn.commit()

        # 상품 정보 가져오기
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        conn.close()

        if product:
            user = get_current_user()
            return render_template('product_detail.html', product=product, user=user)
        else:
            return "상품을 찾을 수 없습니다.", 404
    except Exception as e:
        return f"데이터베이스 오류: {str(e)}", 500


@app.route('/products/new', methods=['GET', 'POST'])
@login_required
def product_new():
    user = get_current_user()
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            price = request.form.get('price')
            category = request.form.get('category')
            location = request.form.get('location')
            seller_phone = request.form.get('seller_phone', '')
            status = request.form.get('status', '판매중')
            
            if not all([title, description, price, category, location]):
                return render_template('product_new.html',
                                     error='모든 필수 항목을 입력해주세요.',
                                     categories=get_categories(),
                                     user=user)
            
            image_url = ''
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                    filename = timestamp + filename
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    image_url = f'/static/uploads/{filename}'
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO products (title, description, price, category, location,
                               seller, seller_id, seller_phone, image_url, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (title, description, int(price), category, location,
                  user['nickname'], user['id'], seller_phone, image_url, status))
            conn.commit()
            product_id = cursor.lastrowid
            conn.close()
            
            return redirect(url_for('product_detail', product_id=product_id))
        except Exception as e:
            return render_template('product_new.html',
                                 error=f'등록 중 오류가 발생했습니다: {str(e)}',
                                 categories=get_categories(),
                                 user=user)
    return render_template('product_new.html', categories=get_categories(), user=user)

@app.route('/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def product_edit(product_id):
    user = get_current_user()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABLE: SQL Injection 취약
        cursor.execute(f"SELECT * FROM products WHERE id = '{product_id}'")
        product = cursor.fetchone()
        
        if not product:
            conn.close()
            flash('상품을 찾을 수 없습니다.', 'error')
            return redirect(url_for('product_list'))
        
        # 권한 체크: 본인이 올린 상품만 수정 가능
        if product.get('seller_id') != user['id']:
            conn.close()
            flash('본인이 등록한 상품만 수정할 수 있습니다.', 'error')
            return redirect(url_for('product_detail', product_id=product_id))
        
        if request.method == 'POST':
            try:
                title = request.form.get('title')
                description = request.form.get('description')
                price = request.form.get('price')
                category = request.form.get('category')
                location = request.form.get('location')
                seller_phone = request.form.get('seller_phone', '')
                status = request.form.get('status', '판매중')
                
                if not all([title, description, price, category, location]):
                    flash('모든 필수 항목을 입력해주세요.', 'error')
                    conn.close()
                    return render_template('product_edit.html',
                                         product=product,
                                         categories=get_categories(),
                                         user=user)
                
                # 이미지 업로드 처리
                image_url = product.get('image_url', '')
                if 'image' in request.files:
                    file = request.files['image']
                    if file and file.filename and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                        filename = timestamp + filename
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        image_url = f'/static/uploads/{filename}'
                
                cursor.execute("""
                UPDATE products
                SET title = %s, description = %s, price = %s, category = %s,
                    location = %s, seller_phone = %s, image_url = %s, status = %s
                WHERE id = %s
                """, (title, description, int(price), category, location,
                      seller_phone, image_url, status, product_id))
                conn.commit()
                conn.close()
                flash('상품이 성공적으로 수정되었습니다.', 'success')
                return redirect(url_for('product_detail', product_id=product_id))
            except Exception as e:
                conn.close()
                flash(f'수정 중 오류가 발생했습니다: {str(e)}', 'error')
                return render_template('product_edit.html',
                                     product=product,
                                     categories=get_categories(),
                                     user=user)
        conn.close()
        return render_template('product_edit.html',
                             product=product,
                             categories=get_categories(),
                             user=user)
    except Exception as e:
        flash(f'오류가 발생했습니다: {str(e)}', 'error')
        return redirect(url_for('product_list'))

@app.route('/products/<int:product_id>/delete', methods=['POST'])
@login_required
def product_delete(product_id):
    user = get_current_user()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABLE: SQL Injection 취약
        cursor.execute(f"SELECT seller_id FROM products WHERE id = '{product_id}'")
        product = cursor.fetchone()
        
        if not product:
            conn.close()
            flash('상품을 찾을 수 없습니다.', 'error')
            return redirect(url_for('product_list'))
        
        if product.get('seller_id') != user['id']:
            conn.close()
            flash('본인이 등록한 상품만 삭제할 수 있습니다.', 'error')
            return redirect(url_for('product_detail', product_id=product_id))
        
        # VULNERABLE: SQL Injection 취약
        cursor.execute(f"DELETE FROM products WHERE id = '{product_id}'")
        conn.commit()
        conn.close()
        flash('상품이 성공적으로 삭제되었습니다.', 'success')
        return redirect(url_for('product_list'))
    except Exception as e:
        flash(f'삭제 중 오류가 발생했습니다: {str(e)}', 'error')
        return redirect(url_for('product_list'))

def get_categories():
    """카테고리 목록 가져오기"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT category FROM products ORDER BY category")
        categories = [row['category'] for row in cursor.fetchall()]
        conn.close()
        return categories if categories else ['디지털/가전', '가구/인테리어', '패션/의류', '유아동/유아도서', '기타']
    except:
        return ['디지털/가전', '가구/인테리어', '패션/의류', '유아동/유아도서', '기타']

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        nickname = request.form.get('nickname')
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        
        # 유효성 검사
        if not all([username, password, nickname]):
            flash('아이디, 비밀번호, 닉네임은 필수 항목입니다.', 'error')
            return render_template('register.html', user=get_current_user())
        if password != password_confirm:
            flash('비밀번호가 일치하지 않습니다.', 'error')
            return render_template('register.html', user=get_current_user())
        if len(password) < 6:
            flash('비밀번호는 최소 6자 이상이어야 합니다.', 'error')
            return render_template('register.html', user=get_current_user())
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # VULNERABLE: SQL Injection 취약
            cursor.execute(f"SELECT id FROM users WHERE username = '{username}'")
            if cursor.fetchone():
                flash('이미 사용 중인 아이디입니다.', 'error')
                conn.close()
                return render_template('register.html', user=get_current_user())
            
            # 비밀번호 해시 처리
            password_hash = generate_password_hash(password)
            
            # VULNERABLE: SQL Injection 취약
            cursor.execute(f"""
            INSERT INTO users (username, password, nickname, email, phone)
            VALUES ('{username}', '{password_hash}', '{nickname}', '{email}', '{phone}')
            """)
            conn.commit()
            conn.close()
            flash('회원가입이 완료되었습니다. 로그인해주세요.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'회원가입 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('register.html', user=get_current_user())
    return render_template('register.html', user=get_current_user())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('아이디와 비밀번호를 입력해주세요.', 'error')
            return render_template('login.html', user=get_current_user())
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # VULNERABLE: SQL Injection 취약 - 로그인 바이패스 가능 (' OR '1'='1)
            cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
            user = cursor.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['nickname'] = user['nickname']
                flash(f'{user["nickname"]}님 환영합니다!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'error')
                return render_template('login.html', user=get_current_user())
        except Exception as e:
            flash(f'로그인 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('login.html', user=get_current_user())
    return render_template('login.html', user=get_current_user())

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

# 채팅 기능들 (기존과 동일 - 취약점 없음)
@app.route('/chat')
@login_required
def chat_list():
    user = get_current_user()
    return render_template('chat_list.html', user=user)

@app.route('/api/chat/rooms')
@login_required
def get_chat_rooms():
    user = get_current_user()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT
            cr.id as room_id,
            p.id as product_id,
            p.title as product_title,
            p.image_url as product_image_url,
            p.seller_id,
            buyer.id as buyer_id,
            buyer.nickname as buyer_nickname,
            seller.nickname as seller_nickname,
            last_msg.message as last_message,
            last_msg.created_at as last_message_time,
            unread_counts.unread_count
        FROM chat_rooms cr
        JOIN products p ON cr.product_id = p.id
        JOIN users buyer ON cr.buyer_id = buyer.id
        JOIN users seller ON p.seller_id = seller.id
        LEFT JOIN (
            SELECT room_id, message, created_at
            FROM (
                SELECT room_id, message, created_at,
                       ROW_NUMBER() OVER(PARTITION BY room_id ORDER BY created_at DESC) as rn
                FROM messages
            ) tmp WHERE rn = 1
        ) AS last_msg ON cr.id = last_msg.room_id
        LEFT JOIN (
            SELECT room_id, COUNT(id) as unread_count
            FROM messages
            WHERE is_read = FALSE AND sender_id != %s
            GROUP BY room_id
        ) AS unread_counts ON cr.id = unread_counts.room_id
        WHERE cr.buyer_id = %s OR p.seller_id = %s
        ORDER BY last_msg.created_at DESC
        """, (user['id'], user['id'], user['id']))
        chat_rooms = cursor.fetchall()
        conn.close()
        
        for room in chat_rooms:
            if room['last_message_time']:
                room['last_message_time'] = room['last_message_time'].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify({'rooms': chat_rooms})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:product_id>/start_chat', methods=['GET'])
@login_required
def start_chat(product_id):
    user = get_current_user()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT seller_id FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('존재하지 않는 상품입니다.', 'error')
            return redirect(url_for('product_list'))
        if product['seller_id'] == user['id']:
            flash('자신의 상품에는 채팅할 수 없습니다.', 'error')
            return redirect(url_for('product_detail', product_id=product_id))
        
        cursor.execute("SELECT id FROM chat_rooms WHERE product_id = %s AND buyer_id = %s", (product_id, user['id']))
        room = cursor.fetchone()
        
        if room:
            room_id = room['id']
        else:
            cursor.execute("INSERT INTO chat_rooms (product_id, buyer_id) VALUES (%s, %s)", (product_id, user['id']))
            conn.commit()
            room_id = cursor.lastrowid
        conn.close()
        
        return redirect(url_for('chat_room', room_id=room_id))
    except Exception as e:
        flash(f'채팅방 입장에 실패했습니다: {str(e)}', 'error')
        return redirect(url_for('product_detail', product_id=product_id))

@app.route('/chat/room/<int:room_id>')
@login_required
def chat_room(room_id):
    user = get_current_user()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT
            cr.id, cr.product_id, cr.buyer_id,
            p.title as product_title, p.seller_id,
            buyer.nickname as buyer_nickname,
            seller.nickname as seller_nickname
        FROM chat_rooms cr
        JOIN products p ON cr.product_id = p.id
        JOIN users buyer ON cr.buyer_id = buyer.id
        JOIN users seller ON p.seller_id = seller.id
        WHERE cr.id = %s
        """, (room_id,))
        room_info = cursor.fetchone()
        
        if not room_info:
            flash('존재하지 않는 채팅방입니다.', 'error')
            return redirect(url_for('chat_list'))
        
        if user['id'] != room_info['buyer_id'] and user['id'] != room_info['seller_id']:
            flash('참여할 권한이 없는 채팅방입니다.', 'error')
            return redirect(url_for('chat_list'))
        
        if user['id'] == room_info['buyer_id']:
            other_user = {'id': room_info['seller_id'], 'nickname': room_info['seller_nickname']}
        else:
            other_user = {'id': room_info['buyer_id'], 'nickname': room_info['buyer_nickname']}
        conn.close()
        
        return render_template('chat_room.html', user=user, room=room_info, other_user=other_user)
    except Exception as e:
        flash(f'채팅방을 불러오는 중 오류가 발생했습니다: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/chat/room/<int:room_id>/messages')
@login_required
def get_room_messages(room_id):
    user = get_current_user()
    last_id = request.args.get('last_id', 0, type=int)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT p.seller_id, cr.buyer_id FROM chat_rooms cr JOIN products p ON cr.product_id = p.id WHERE cr.id = %s", (room_id,))
        room_check = cursor.fetchone()
        
        if not room_check or (user['id'] != room_check['buyer_id'] and user['id'] != room_check['seller_id']):
            return jsonify({'error': '권한이 없습니다.'}), 403
        
        cursor.execute("""
        SELECT m.id, m.sender_id, m.message, m.created_at, u.nickname as sender_nickname
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.room_id = %s AND m.id > %s
        ORDER BY m.id ASC
        """, (room_id, last_id))
        messages = cursor.fetchall()
        
        other_user_id = room_check['buyer_id'] if user['id'] == room_check['seller_id'] else room_check['seller_id']
        cursor.execute("""
        UPDATE messages SET is_read = TRUE
        WHERE room_id = %s AND sender_id = %s AND is_read = FALSE
        """, (room_id, other_user_id))
        conn.commit()
        conn.close()
        
        for msg in messages:
            msg['created_at'] = msg['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify({'messages': messages})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/room/<int:room_id>/send', methods=['POST'])
@login_required
def send_room_message(room_id):
    user = get_current_user()
    data = request.get_json()
    message_text = data.get('message')
    
    if not message_text:
        return jsonify({'error': '메시지를 입력해주세요.'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT p.seller_id, cr.buyer_id FROM chat_rooms cr JOIN products p ON cr.product_id = p.id WHERE cr.id = %s", (room_id,))
        room_check = cursor.fetchone()
        
        if not room_check or (user['id'] != room_check['buyer_id'] and user['id'] != room_check['seller_id']):
            conn.close()
            return jsonify({'error': '권한이 없습니다.'}), 403
        
        cursor.execute(
            "INSERT INTO messages (room_id, sender_id, message) VALUES (%s, %s, %s)",
            (room_id, user['id'], message_text)
        )
        cursor.execute("UPDATE chat_rooms SET updated_at = CURRENT_TIMESTAMP WHERE id = %s", (room_id,))
        conn.commit()
        message_id = cursor.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'message_id': message_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
