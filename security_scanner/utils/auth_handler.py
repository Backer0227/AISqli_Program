"""
인증 처리 모듈
로그인 및 세션 관리를 처리합니다.
"""
from typing import Dict, Any, Optional
from utils.http_client import HTTPClient
import json

class AuthHandler:
    """인증을 처리하는 클래스"""
    
    def __init__(self, http_client: HTTPClient, auth_config: Dict[str, Any]):
        """
        AuthHandler 초기화
        
        Args:
            http_client: HTTPClient 인스턴스
            auth_config: 인증 설정 딕셔너리
        """
        self.client = http_client
        self.config = auth_config
        self.session_cookies: Optional[Dict[str, str]] = None
        self.is_authenticated = False
    
    def login(self) -> bool:
        """
        로그인을 수행합니다.
        
        Returns:
            로그인 성공 여부
        """
        if not self.config.get('enabled', False):
            return False
        
        login_url = self.config.get('login_url', '/login')
        username = self.config.get('login_username', '')
        password = self.config.get('login_password', '')
        content_type = self.config.get('content_type', 'application/json')  # ⬅ config.yaml 의 content_type
        
        if not username or not password:
            return False
        
        try:
            # JSON 바디 구성 (브라우저 / PowerShell과 동일) [web:76][web:91]
            payload = {
                "username": username,
                "password": password,
            }
            
            headers = {
                "Content-Type": content_type,
                "Accept": "application/json, text/plain, */*",
            }
            
            # HTTPClient가 requests 기반이라고 가정:
            # json= 을 지원하면 json=payload, 아니면 data=json.dumps(payload) 사용 [web:79][web:88]
            response = self.client.post(
                login_url,
                json=payload,           # <-- 여기 핵심: data= 가 아니라 json=
                headers=headers,
            )
            
            # 응답 코드 확인
            if response.status_code not in (200, 201):
                return False
            
            # JSON 응답 파싱
            try:
                data = response.json()
            except Exception:
                data = {}
            
            # {"success": true, "user": {...}} 형태라고 가정
            if data.get("success"):
                self.session_cookies = self.client.get_cookies()
                self.is_authenticated = True
                return True
            
            # 혹시라도 success 필드가 없으면 예전 방식도 한 번 더 체크
            response_text = response.text.lower()
            if 'success' in response_text or 'welcome' in response_text:
                self.session_cookies = self.client.get_cookies()
                self.is_authenticated = True
                return True
            
            return False
        
        except Exception as e:
            print(f"로그인 실패: {e}")
            return False
    
    def get_auth_cookies(self) -> Optional[Dict[str, str]]:
        """인증된 세션 쿠키 반환"""
        return self.session_cookies if self.is_authenticated else None
    
    def is_auth_required(self, endpoint_config: Dict[str, Any]) -> bool:
        """엔드포인트가 requires_auth: true 인지 확인"""
        return endpoint_config.get('requires_auth', False)
    
    def ensure_authenticated(self) -> bool:
        """인증 안 되어 있으면 로그인 시도"""
        if not self.is_authenticated:
            return self.login()
        return True
