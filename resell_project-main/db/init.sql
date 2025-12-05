-- 데이터베이스 및 사용자는 docker-compose.yml에서 생성됨
SET NAMES utf8mb4;
-- 사용자 테이블 생성
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    nickname VARCHAR(50) NOT NULL,
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 상품(중고거래) 테이블 생성
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    price INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    location VARCHAR(100) NOT NULL,
    seller VARCHAR(50) DEFAULT '익명',
    seller_id INT,
    seller_phone VARCHAR(20),
    image_url VARCHAR(255),
    status VARCHAR(20) DEFAULT '판매중' COMMENT '판매중, 예약중, 판매완료',
    views INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at),
    INDEX idx_category (category),
    INDEX idx_location (location),
    INDEX idx_status (status),
    INDEX idx_seller_id (seller_id),
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 채팅방 테이블 생성
CREATE TABLE IF NOT EXISTS chat_rooms (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT NOT NULL,
    buyer_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_product_buyer (product_id, buyer_id),
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 채팅 메시지 테이블 생성
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    room_id INT NOT NULL,
    sender_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_room_id (room_id),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 초기 상품 데이터 삽입 (기존 데이터 유지)
INSERT INTO products (title, description, price, category, location, seller, image_url) VALUES
('아이폰 13 Pro 판매합니다', '아이폰 13 Pro 256GB 블랙\n\n- 구매일: 2022년 3월\n- 사용기간: 2년\n- 배터리 건강도: 85%\n- 박스, 충전기 포함\n- 전면 보호필름 부착\n- 작은 스크래치 1~2개 있으나 사용에는 전혀 문제 없음\n\n직거래 선호 (강남역 근처 가능)', 650000, '디지털/가전', '서울 강남구', '김철수', '/static/images/product1.jpg'),
('무선 이어폰 에어팟 프로', '에어팟 프로 2세대\n\n- 구매일: 2023년 5월\n- 사용기간: 1년\n- 박스, 케이스, 모든 액세서리 포함\n- 배터리 상태 양호\n- 노이즈 캔슬링 정상 작동\n\n흥정 가능합니다!', 180000, '디지털/가전', '서울 서초구', '이영희', '/static/images/product2.jpg'),
('책상 + 의자 세트', 'IKEA 책상과 의자 세트\n\n- 책상 크기: 120cm x 60cm\n- 의자 높이 조절 가능\n- 사용감 있지만 상태 양호\n- 이사로 인한 판매\n\n직거래만 가능 (강동구 올림픽공원 근처)', 80000, '가구/인테리어', '서울 강동구', '박민수', '/static/images/product3.jpg'),
('나이키 운동화 판매', '나이키 에어맥스 270\n\n- 사이즈: 270mm\n- 구매일: 2023년 초\n- 착용 횟수: 약 10회\n- 상태: 거의 새것\n- 박스 보관 중\n\n직거래 선호', 120000, '패션/의류', '서울 마포구', '최지은', '/static/images/product4.jpg'),
('어린이 장난감 모음', '레고 및 자동차 장난감 모음\n\n- 레고 블록 약 500개\n- 자동차 장난감 10개\n- 퍼즐 3개\n- 아이가 자라서 더 이상 안 쓰는 장난감들\n\n세트로만 판매합니다', 30000, '유아동/유아도서', '서울 송파구', '정수진', '/static/images/product5.jpg');