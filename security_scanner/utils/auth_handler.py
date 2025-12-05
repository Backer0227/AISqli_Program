"""
인증 처리 모듈
로그인 및 세션 관리를 처리합니다.
"""
from typing import Dict, Any, Optional
from utils.http_client import HTTPClient
import time


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
        
        if not username or not password:
            return False
        
        try:
            # 로그인 요청
            response = self.client.post(
                login_url,
                data={
                    'username': username,
                    'password': password
                }
            )
            
            # 로그인 성공 여부 확인
            # 일반적으로 200 또는 302 응답이면 성공으로 간주
            if response.status_code in [200, 302]:
                # 쿠키 저장
                self.session_cookies = self.client.get_cookies()
                self.is_authenticated = True
                return True
            
            # 응답 본문에 성공 메시지가 있는지 확인
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
        """
        인증된 세션 쿠키를 반환합니다.
        
        Returns:
            쿠키 딕셔너리 또는 None
        """
        return self.session_cookies if self.is_authenticated else None
    
    def is_auth_required(self, endpoint_config: Dict[str, Any]) -> bool:
        """
        엔드포인트가 인증이 필요한지 확인합니다.
        
        Args:
            endpoint_config: 엔드포인트 설정
            
        Returns:
            인증 필요 여부
        """
        return endpoint_config.get('requires_auth', False)
    
    def ensure_authenticated(self) -> bool:
        """
        인증 상태를 확인하고 필요시 로그인을 수행합니다.
        
        Returns:
            인증 상태
        """
        if not self.is_authenticated:
            return self.login()
        return True

