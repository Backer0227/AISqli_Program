"""
HTTP 클라이언트 모듈
보안 스캔을 위한 HTTP 요청을 처리합니다.
"""
import requests
from typing import Dict, Any, Optional, Tuple
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class HTTPClient:
    """HTTP 요청을 처리하는 클라이언트 클래스"""
    
    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        verify_ssl: bool = False,
        delay: float = 0.5,
        max_retries: int = 3,
        follow_redirects: bool = True
    ):
        """
        HTTPClient 초기화
        
        Args:
            base_url: 기본 URL
            timeout: 요청 타임아웃 (초)
            verify_ssl: SSL 인증서 검증 여부
            delay: 요청 간 지연 시간 (초)
            max_retries: 최대 재시도 횟수
            follow_redirects: 리다이렉트 따라가기 여부
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.max_redirects = 10 if follow_redirects else 0
        self.last_request_time = 0
    
    def _wait_delay(self):
        """요청 간 지연을 처리합니다."""
        if self.delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()
    
    def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> requests.Response:
        """
        HTTP 요청을 수행합니다.
        
        Args:
            method: HTTP 메서드 (GET, POST, etc.)
            url: 요청 URL
            params: URL 파라미터
            data: 폼 데이터
            json: JSON 데이터
            headers: HTTP 헤더
            cookies: 쿠키
            
        Returns:
            응답 객체
        """
        self._wait_delay()
        
        # 절대 URL이 아니면 base_url과 결합
        if not url.startswith(('http://', 'https://')):
            url = urljoin(self.base_url, url.lstrip('/'))
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                    cookies=cookies,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
                return response
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(1 * (attempt + 1))  # 지수 백오프
    
    def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> requests.Response:
        """GET 요청을 수행합니다."""
        return self._make_request('GET', path, params=params, headers=headers, cookies=cookies)
    
    def post(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> requests.Response:
        """POST 요청을 수행합니다."""
        return self._make_request('POST', path, data=data, json=json, headers=headers, cookies=cookies)
    
    def put(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> requests.Response:
        """PUT 요청을 수행합니다."""
        return self._make_request('PUT', path, data=data, json=json, headers=headers, cookies=cookies)
    
    def delete(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> requests.Response:
        """DELETE 요청을 수행합니다."""
        return self._make_request('DELETE', path, headers=headers, cookies=cookies)
    
    def inject_payload(
        self,
        method: str,
        path: str,
        param_name: str,
        payload: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        path_variables: Optional[Dict[str, str]] = None
    ) -> requests.Response:
        """
        파라미터에 페이로드를 주입하여 요청을 수행합니다.
        
        Args:
            method: HTTP 메서드
            path: 요청 경로 (URL 경로 변수 포함 가능, 예: /products/{id})
            param_name: 페이로드를 주입할 파라미터 이름
            payload: 주입할 페이로드
            params: 기존 URL 파라미터 (GET 요청용)
            data: 기존 폼 데이터 (POST 요청용)
            headers: HTTP 헤더
            cookies: 쿠키
            path_variables: URL 경로 변수의 기본값 딕셔너리
            
        Returns:
            응답 객체
        """
        if params is None:
            params = {}
        if data is None:
            data = {}
        if path_variables is None:
            path_variables = {}
        
        # URL 경로 변수 처리
        processed_path = path
        
        # param_name이 URL 경로 변수인지 확인
        path_var_pattern = '{' + param_name + '}'
        if path_var_pattern in processed_path:
            # URL 경로 변수에 페이로드 주입
            processed_path = processed_path.replace(path_var_pattern, str(payload))
        else:
            # 다른 경로 변수들은 기본값으로 대체
            for var_name, var_value in path_variables.items():
                if var_name != param_name:  # 현재 테스트 중인 변수가 아니면 기본값 사용
                    processed_path = processed_path.replace('{' + var_name + '}', str(var_value))
        
        # URL 파라미터에 주입 (GET 요청)
        if method.upper() == 'GET':
            params = params.copy()
            # URL 경로 변수가 아닌 경우에만 쿼리 파라미터로 추가
            if path_var_pattern not in path:
                params[param_name] = payload
            return self.get(processed_path, params=params, headers=headers, cookies=cookies)
        
        # 폼 데이터에 주입 (POST 요청)
        else:
            data = data.copy()
            # URL 경로 변수가 아닌 경우에만 폼 데이터로 추가
            if path_var_pattern not in path:
                data[param_name] = payload
            return self.post(processed_path, data=data, headers=headers, cookies=cookies)
    
    def set_cookies(self, cookies: Dict[str, str]):
        """세션 쿠키를 설정합니다."""
        self.session.cookies.update(cookies)
    
    def get_cookies(self) -> Dict[str, str]:
        """현재 세션 쿠키를 반환합니다."""
        return dict(self.session.cookies)

