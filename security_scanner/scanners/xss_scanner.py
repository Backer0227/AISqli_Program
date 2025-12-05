"""
XSS (Cross-Site Scripting) 스캐너
XSS 취약점을 탐지합니다.
"""
import re
from typing import Dict, Any, List
from scanners.base_scanner import BaseScanner
from utils.http_client import HTTPClient
from utils.auth_handler import AuthHandler


class XSSScanner(BaseScanner):
    """XSS 취약점을 탐지하는 스캐너"""
    
    # XSS 탐지를 위한 패턴
    XSS_INDICATORS = [
        r'<script[^>]*>',
        r'</script>',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'<img[^>]*onerror',
        r'<svg[^>]*onload',
        r'<iframe[^>]*src',
        r'<body[^>]*onload',
        r'<input[^>]*onfocus',
        r'<select[^>]*onfocus',
        r'<textarea[^>]*onfocus',
        r'<video[^>]*onerror',
        r'<audio[^>]*onerror',
        r'<details[^>]*ontoggle',
        r'<marquee[^>]*onstart',
    ]
    
    def __init__(
        self,
        http_client: HTTPClient,
        auth_handler: AuthHandler = None
    ):
        """
        XSSScanner 초기화
        
        Args:
            http_client: HTTPClient 인스턴스
            auth_handler: AuthHandler 인스턴스 (선택사항)
        """
        super().__init__(http_client, auth_handler)
        self.vulnerable_endpoints: List[Dict[str, Any]] = []
    
    def scan_endpoint(
        self,
        endpoint: Dict[str, Any],
        payloads: List[str]
    ) -> List[Dict[str, Any]]:
        """
        엔드포인트에 대해 XSS 스캔을 수행합니다.
        
        Args:
            endpoint: 엔드포인트 설정
            payloads: 테스트할 XSS 페이로드 리스트
            
        Returns:
            스캔 결과 리스트
        """
        import re
        results = []
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET').upper()
        params = endpoint.get('params', [])
        path_variables = endpoint.get('path_variables', {})
        
        # URL 경로 변수 추출 (예: {product_id}, {room_id})
        path_var_names = re.findall(r'\{(\w+)\}', path)
        
        # 인증 확인
        if not self._check_auth(endpoint):
            print(f"경고: {path}에 대한 인증 실패, 스캔 건너뜀")
            return results
        
        auth_cookies = self._get_auth_cookies()
        
        print(f"\n[XSS 스캔] {method} {path}")
        print(f"테스트할 파라미터: {params}")
        if path_var_names:
            print(f"URL 경로 변수: {path_var_names}")
        
        # URL 경로 변수에 대해 페이로드 테스트
        for path_var_name in path_var_names:
            print(f"  URL 경로 변수 '{path_var_name}' 테스트 중...")
            
            # 각 페이로드 테스트
            for payload in payloads:
                try:
                    result = self._test_path_variable_payload(
                        method, path, endpoint, path_var_name, payload,
                        auth_cookies, path_variables
                    )
                    
                    if result:
                        results.append(result)
                        self.results.append(result)
                        print(f"    ⚠️  취약점 발견! 페이로드: {payload[:50]}...")
                        
                except Exception as e:
                    print(f"    오류: {e}")
                    continue
        
        # 각 파라미터에 대해 페이로드 테스트
        for param_name in params:
            print(f"  파라미터 '{param_name}' 테스트 중...")
            
            # 각 페이로드 테스트
            for payload in payloads:
                try:
                    result = self._test_payload(
                        method, path, endpoint, param_name, payload,
                        auth_cookies, path_variables
                    )
                    
                    if result:
                        results.append(result)
                        self.results.append(result)
                        print(f"    ⚠️  취약점 발견! 페이로드: {payload[:50]}...")
                        
                except Exception as e:
                    print(f"    오류: {e}")
                    continue
        
        return results
    
    def _test_payload(
        self,
        method: str,
        path: str,
        endpoint: Dict[str, Any],
        param_name: str,
        payload: str,
        auth_cookies: Dict[str, str] = None,
        path_variables: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        단일 페이로드를 테스트합니다.
        
        Returns:
            취약점이 발견되면 결과 딕셔너리, 아니면 None
        """
        if path_variables is None:
            path_variables = endpoint.get('path_variables', {})
        
        # 페이로드 주입 요청
        response = self.client.inject_payload(
            method, path, param_name, payload,
            cookies=auth_cookies,
            path_variables=path_variables
        )
        
        response_text = response.text
        
        # XSS 취약점 확인
        if self._check_xss_vulnerability(response_text, payload):
            return {
                'type': 'XSS',
                'vulnerability': 'Cross-Site Scripting',
                'endpoint': path,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'evidence': self._extract_xss_evidence(response_text, payload),
                'severity': 'High'
            }
        
        return None
    
    def _test_path_variable_payload(
        self,
        method: str,
        path: str,
        endpoint: Dict[str, Any],
        path_var_name: str,
        payload: str,
        auth_cookies: Dict[str, str] = None,
        path_variables: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        URL 경로 변수에 대한 단일 페이로드를 테스트합니다.
        
        Returns:
            취약점이 발견되면 결과 딕셔너리, 아니면 None
        """
        if path_variables is None:
            path_variables = endpoint.get('path_variables', {})
        
        # 페이로드를 URL 경로 변수에 주입
        response = self.client.inject_payload(
            method, path, path_var_name, payload,
            cookies=auth_cookies,
            path_variables=path_variables
        )
        
        response_text = response.text
        
        # XSS 취약점 확인
        if self._check_xss_vulnerability(response_text, payload):
            return {
                'type': 'XSS',
                'vulnerability': 'Cross-Site Scripting',
                'endpoint': path,
                'method': method,
                'parameter': path_var_name + ' (URL 경로 변수)',
                'payload': payload,
                'status_code': response.status_code,
                'evidence': self._extract_xss_evidence(response_text, payload),
                'severity': 'High'
            }
        
        return None
    
    def _check_xss_vulnerability(self, response_text: str, payload: str) -> bool:
        """
        응답에 XSS 취약점이 있는지 확인합니다.
        
        Args:
            response_text: 응답 본문
            payload: 주입한 페이로드
            
        Returns:
            취약점 발견 여부
        """
        # 1. 페이로드가 그대로 응답에 포함되어 있는지 확인 (인코딩되지 않음)
        if payload in response_text:
            # 하지만 HTML 엔티티로 인코딩된 경우는 안전
            if self._is_properly_encoded(payload, response_text):
                return False
            return True
        
        # 2. 페이로드의 주요 부분이 인코딩 없이 포함되어 있는지 확인
        # <script> 태그나 이벤트 핸들러가 그대로 있는지
        for indicator in self.XSS_INDICATORS:
            if re.search(indicator, response_text, re.IGNORECASE):
                # HTML 엔티티로 인코딩되어 있으면 안전
                if not self._is_properly_encoded(indicator, response_text):
                    return True
        
        # 3. 페이로드의 핵심 키워드가 인코딩 없이 포함되어 있는지
        # 예: alert('XSS') 같은 JavaScript 코드
        js_patterns = [
            r"alert\s*\(",
            r"eval\s*\(",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # HTML 엔티티로 인코딩되어 있으면 안전
                if not self._is_properly_encoded(pattern, response_text):
                    return True
        
        return False
    
    def _is_properly_encoded(self, text: str, response_text: str) -> bool:
        """
        텍스트가 HTML 엔티티로 제대로 인코딩되어 있는지 확인합니다.
        
        Args:
            text: 확인할 텍스트
            response_text: 응답 본문
            
        Returns:
            제대로 인코딩되어 있으면 True
        """
        # HTML 엔티티로 인코딩된 경우 확인
        # 예: <script> -> &lt;script&gt;
        encoded = text.replace('<', '&lt;').replace('>', '&gt;')
        encoded = encoded.replace('"', '&quot;').replace("'", '&#x27;')
        encoded = encoded.replace('&', '&amp;')
        
        # 인코딩된 버전이 응답에 있으면 안전
        if encoded in response_text:
            return True
        
        # 숫자 엔티티로 인코딩된 경우
        # 예: < -> &#60;
        numeric_encoded = text.replace('<', '&#60;').replace('>', '&#62;')
        if numeric_encoded in response_text:
            return True
        
        # 16진수 엔티티로 인코딩된 경우
        # 예: < -> &#x3C;
        hex_encoded = text.replace('<', '&#x3C;').replace('>', '&#x3E;')
        if hex_encoded in response_text:
            return True
        
        return False
    
    def _extract_xss_evidence(self, response_text: str, payload: str) -> str:
        """
        응답에서 XSS 취약점 증거를 추출합니다.
        
        Args:
            response_text: 응답 본문
            payload: 주입한 페이로드
            
        Returns:
            증거 문자열
        """
        # 페이로드가 포함된 부분 찾기
        payload_pos = response_text.find(payload)
        if payload_pos != -1:
            # 페이로드 주변 텍스트 추출
            start = max(0, payload_pos - 200)
            end = min(len(response_text), payload_pos + len(payload) + 200)
            return response_text[start:end]
        
        # 페이로드가 직접 포함되지 않았지만 XSS 패턴이 있는 경우
        for indicator in self.XSS_INDICATORS:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 200)
                end = min(len(response_text), match.end() + 200)
                return response_text[start:end]
        
        return "XSS 취약점 감지됨 (페이로드가 응답에 포함됨)"

