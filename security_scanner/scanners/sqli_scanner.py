"""
SQL Injection 스캐너
SQL Injection 취약점을 탐지합니다.
"""
import re
import time
from typing import Dict, Any, List
from scanners.base_scanner import BaseScanner
from utils.http_client import HTTPClient
from utils.auth_handler import AuthHandler


class SQLiScanner(BaseScanner):
    """SQL Injection 취약점을 탐지하는 스캐너"""
    
    # SQL 에러 패턴 (MySQL, PostgreSQL, MSSQL 등)
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*\Wmysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL.*Server",
        r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wsqlsrv_",
        r"Warning.*\Wodbc_",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"Warning.*\Woracle",
        r"Warning.*\Woci8_",
        r"Warning.*\Wodbc_",
        r"Warning.*\Wdb2_",
        r"Warning.*\Wibm_",
        r"Warning.*\Wdbase_",
        r"Warning.*\Wmsql_",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wsybase_",
        r"Warning.*\Wifx_",
        r"Warning.*\Wfbsql_",
        r"Warning.*\Wibase_",
        r"Warning.*\Wfbird_",
        r"Warning.*\Winterbase_",
        r"Warning.*\Wfirebird_",
        r"Warning.*\Wborland_",
        r"Warning.*\Wparadox_",
        r"Warning.*\Wmsaccess_",
        r"Warning.*\Wmsexcel_",
        r"Warning.*\Wmsql_",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wsybase_",
        r"Warning.*\Wifx_",
        r"Warning.*\Wfbsql_",
        r"Warning.*\Wibase_",
        r"Warning.*\Wfbird_",
        r"Warning.*\Winterbase_",
        r"Warning.*\Wfirebird_",
        r"Warning.*\Wborland_",
        r"Warning.*\Wparadox_",
        r"Warning.*\Wmsaccess_",
        r"Warning.*\Wmsexcel_",
        r"SQLException",
        r"SQLiteException",
        r"SQLite3::",
        r"Warning.*\Wsqlite_",
        r"Warning.*\Wsqlite3_",
        r"Microsoft Access.*Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"ODBC Microsoft Access",
        r"Syntax error.*in query expression",
        r"Microsoft JET Database Engine",
        r"Unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
        r"Warning.*\Woracle.*",
        r"Warning.*\Woci8_.*",
        r"Warning.*\Wodbc_.*",
        r"Warning.*\Wdb2_.*",
        r"Warning.*\Wibm_.*",
        r"Warning.*\Wdbase_.*",
        r"Warning.*\Wmsql_.*",
        r"Warning.*\Wmssql_.*",
        r"Warning.*\Wsybase_.*",
        r"Warning.*\Wifx_.*",
        r"Warning.*\Wfbsql_.*",
        r"Warning.*\Wibase_.*",
        r"Warning.*\Wfbird_.*",
        r"Warning.*\Winterbase_.*",
        r"Warning.*\Wfirebird_.*",
        r"Warning.*\Wborland_.*",
        r"Warning.*\Wparadox_.*",
        r"Warning.*\Wmsaccess_.*",
        r"Warning.*\Wmsexcel_.*",
    ]
    
    def __init__(
        self,
        http_client: HTTPClient,
        auth_handler: AuthHandler = None
    ):
        """
        SQLiScanner 초기화
        
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
        엔드포인트에 대해 SQL Injection 스캔을 수행합니다.
        
        Args:
            endpoint: 엔드포인트 설정
            payloads: 테스트할 SQLi 페이로드 리스트
            
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
        
        print(f"\n[SQLi 스캔] {method} {path}")
        print(f"테스트할 파라미터: {params}")
        if path_var_names:
            print(f"URL 경로 변수: {path_var_names}")
        
        # URL 경로 변수에 대해 페이로드 테스트
        for path_var_name in path_var_names:
            print(f"  URL 경로 변수 '{path_var_name}' 테스트 중...")
            
            # 기본 응답 (기본값으로) - 비교 기준
            try:
                baseline_response = self._make_baseline_request_with_path_var(
                    method, path, endpoint, path_var_name, path_variables
                )
                baseline_time = baseline_response.elapsed.total_seconds()
                baseline_text = baseline_response.text.lower()
            except Exception as e:
                print(f"    경고: 기준 요청 실패 - {e}")
                continue
            
            # 각 페이로드 테스트
            for payload in payloads:
                try:
                    result = self._test_path_variable_payload(
                        method, path, endpoint, path_var_name, payload,
                        baseline_response, baseline_time, baseline_text,
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
            
            # 기본 응답 (페이로드 없이) - 비교 기준
            try:
                baseline_response = self._make_baseline_request(
                    method, path, endpoint, param_name
                )
                baseline_time = baseline_response.elapsed.total_seconds()
                baseline_text = baseline_response.text.lower()
            except Exception as e:
                print(f"    경고: 기준 요청 실패 - {e}")
                continue
            
            # 각 페이로드 테스트
            for payload in payloads:
                try:
                    result = self._test_payload(
                        method, path, endpoint, param_name, payload,
                        baseline_response, baseline_time, baseline_text,
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
    
    def _make_baseline_request(
        self,
        method: str,
        path: str,
        endpoint: Dict[str, Any],
        param_name: str
    ):
        """기준 요청을 수행합니다 (페이로드 없이)."""
        auth_cookies = self._get_auth_cookies()
        path_variables = endpoint.get('path_variables', {})
        
        # URL 경로 변수 처리
        processed_path = path
        for var_name, var_value in path_variables.items():
            processed_path = processed_path.replace('{' + var_name + '}', str(var_value))
        
        if method == 'GET':
            params = {param_name: '1'}  # 기본값
            return self.client.get(processed_path, params=params, cookies=auth_cookies)
        else:
            data = {param_name: '1'}  # 기본값
            return self.client.post(processed_path, data=data, cookies=auth_cookies)
    
    def _make_baseline_request_with_path_var(
        self,
        method: str,
        path: str,
        endpoint: Dict[str, Any],
        path_var_name: str,
        path_variables: Dict[str, str]
    ):
        """URL 경로 변수에 대한 기준 요청을 수행합니다 (기본값 사용)."""
        auth_cookies = self._get_auth_cookies()
        
        # URL 경로 변수 처리 (기본값 사용)
        processed_path = path
        for var_name, var_value in path_variables.items():
            processed_path = processed_path.replace('{' + var_name + '}', str(var_value))
        
        if method == 'GET':
            return self.client.get(processed_path, cookies=auth_cookies)
        else:
            return self.client.post(processed_path, cookies=auth_cookies)
    
    def _test_payload(
        self,
        method: str,
        path: str,
        endpoint: Dict[str, Any],
        param_name: str,
        payload: str,
        baseline_response,
        baseline_time: float,
        baseline_text: str,
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
        
        response_time = response.elapsed.total_seconds()
        response_text = response.text.lower()
        
        # 1. 에러 기반 SQLi 탐지
        if self._check_sql_errors(response_text):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Error-based SQLi',
                'endpoint': path,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'evidence': self._extract_sql_error(response_text),
                'severity': 'High'
            }
        
        # 2. Time-based Blind SQLi 탐지
        if self._check_time_based(response_time, baseline_time):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Time-based Blind SQLi',
                'endpoint': path,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'evidence': f'응답 시간 지연: {baseline_time:.2f}s -> {response_time:.2f}s',
                'severity': 'High'
            }
        
        # 3. Boolean-based Blind SQLi 탐지
        if self._check_boolean_based(response_text, baseline_text):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Boolean-based Blind SQLi',
                'endpoint': path,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'evidence': '응답 내용이 기준과 다름',
                'severity': 'Medium'
            }
        
        # 4. Union-based SQLi 탐지 (응답에 추가 데이터가 있는지)
        if self._check_union_based(response_text, baseline_text):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Union-based SQLi',
                'endpoint': path,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'evidence': 'UNION 쿼리 결과가 응답에 포함됨',
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
        baseline_response,
        baseline_time: float,
        baseline_text: str,
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
        
        response_time = response.elapsed.total_seconds()
        response_text = response.text.lower()
        
        # 1. 에러 기반 SQLi 탐지
        if self._check_sql_errors(response_text):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Error-based SQLi',
                'endpoint': path,
                'method': method,
                'parameter': path_var_name + ' (URL 경로 변수)',
                'payload': payload,
                'status_code': response.status_code,
                'evidence': self._extract_sql_error(response_text),
                'severity': 'High'
            }
        
        # 2. Time-based Blind SQLi 탐지
        if self._check_time_based(response_time, baseline_time):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Time-based Blind SQLi',
                'endpoint': path,
                'method': method,
                'parameter': path_var_name + ' (URL 경로 변수)',
                'payload': payload,
                'status_code': response.status_code,
                'evidence': f'응답 시간 지연: {baseline_time:.2f}s -> {response_time:.2f}s',
                'severity': 'High'
            }
        
        # 3. Boolean-based Blind SQLi 탐지
        if self._check_boolean_based(response_text, baseline_text):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Boolean-based Blind SQLi',
                'endpoint': path,
                'method': method,
                'parameter': path_var_name + ' (URL 경로 변수)',
                'payload': payload,
                'status_code': response.status_code,
                'evidence': '응답 내용이 기준과 다름',
                'severity': 'Medium'
            }
        
        # 4. Union-based SQLi 탐지
        if self._check_union_based(response_text, baseline_text):
            return {
                'type': 'SQL Injection',
                'vulnerability': 'Union-based SQLi',
                'endpoint': path,
                'method': method,
                'parameter': path_var_name + ' (URL 경로 변수)',
                'payload': payload,
                'status_code': response.status_code,
                'evidence': 'UNION 쿼리 결과가 응답에 포함됨',
                'severity': 'High'
            }
        
        return None
    
    def _check_sql_errors(self, response_text: str) -> bool:
        """응답에 SQL 에러가 포함되어 있는지 확인합니다."""
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def _extract_sql_error(self, response_text: str) -> str:
        """응답에서 SQL 에러 메시지를 추출합니다."""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # 에러 메시지 주변 텍스트 추출
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 100)
                return response_text[start:end]
        return "SQL 에러 감지됨"
    
    def _check_time_based(self, response_time: float, baseline_time: float) -> bool:
        """Time-based Blind SQLi를 탐지합니다."""
        # 응답 시간이 기준보다 3초 이상 길면 의심
        return response_time > baseline_time + 3.0
    
    def _check_boolean_based(self, response_text: str, baseline_text: str) -> bool:
        """Boolean-based Blind SQLi를 탐지합니다."""
        # 응답 길이가 크게 다르거나 내용이 다르면 의심
        length_diff = abs(len(response_text) - len(baseline_text))
        if length_diff > len(baseline_text) * 0.1:  # 10% 이상 차이
            return True
        
        # 특정 키워드가 나타나거나 사라졌는지 확인
        true_indicators = ['true', 'success', 'found', 'exists']
        false_indicators = ['false', 'error', 'not found', 'invalid']
        
        baseline_has_true = any(ind in baseline_text for ind in true_indicators)
        baseline_has_false = any(ind in baseline_text for ind in false_indicators)
        
        response_has_true = any(ind in response_text for ind in true_indicators)
        response_has_false = any(ind in response_text for ind in false_indicators)
        
        if baseline_has_true != response_has_true or baseline_has_false != response_has_false:
            return True
        
        return False
    
    def _check_union_based(self, response_text: str, baseline_text: str) -> bool:
        """Union-based SQLi를 탐지합니다."""
        # UNION 키워드가 응답에 포함되어 있고, 응답 길이가 크게 증가했으면 의심
        if 'union' in response_text and len(response_text) > len(baseline_text) * 1.5:
            return True
        return False

