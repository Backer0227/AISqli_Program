"""
기본 스캐너 클래스
모든 스캐너의 기본 클래스입니다.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from utils.http_client import HTTPClient
from utils.auth_handler import AuthHandler


class BaseScanner(ABC):
    """모든 스캐너의 기본 클래스"""
    
    def __init__(
        self,
        http_client: HTTPClient,
        auth_handler: Optional[AuthHandler] = None
    ):
        """
        BaseScanner 초기화
        
        Args:
            http_client: HTTPClient 인스턴스
            auth_handler: AuthHandler 인스턴스 (선택사항)
        """
        self.client = http_client
        self.auth_handler = auth_handler
        self.results: List[Dict[str, Any]] = []
    
    @abstractmethod
    def scan_endpoint(
        self,
        endpoint: Dict[str, Any],
        payloads: List[str]
    ) -> List[Dict[str, Any]]:
        """
        엔드포인트를 스캔합니다.
        
        Args:
            endpoint: 엔드포인트 설정
            payloads: 테스트할 페이로드 리스트
            
        Returns:
            스캔 결과 리스트
        """
        pass
    
    def _check_auth(self, endpoint: Dict[str, Any]) -> bool:
        """
        엔드포인트에 대한 인증이 필요한지 확인하고 처리합니다.
        
        Args:
            endpoint: 엔드포인트 설정
            
        Returns:
            인증 성공 여부
        """
        if self.auth_handler and self.auth_handler.is_auth_required(endpoint):
            return self.auth_handler.ensure_authenticated()
        return True
    
    def _get_auth_cookies(self) -> Optional[Dict[str, str]]:
        """
        인증 쿠키를 반환합니다.
        
        Returns:
            쿠키 딕셔너리 또는 None
        """
        if self.auth_handler:
            return self.auth_handler.get_auth_cookies()
        return None
    
    def get_results(self) -> List[Dict[str, Any]]:
        """
        스캔 결과를 반환합니다.
        
        Returns:
            스캔 결과 리스트
        """
        return self.results
    
    def clear_results(self):
        """스캔 결과를 초기화합니다."""
        self.results = []

