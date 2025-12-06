"""
SQL Injection 스캐너 (Improved)
SQL Injection 취약점을 탐지하며, URL 인코딩 문제를 자동으로 처리합니다.
"""

import re
import urllib.parse
from typing import Dict, Any, List
from scanners.base_scanner import BaseScanner
from utils.http_client import HTTPClient
from utils.auth_handler import AuthHandler

class SQLiScanner(BaseScanner):
    """SQL Injection 취약점을 탐지하는 스캐너"""

    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*\Wmysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"MySqlClient\.", r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_", r"valid PostgreSQL result", r"Npgsql\.",
        r"Driver.*SQL.*Server", r"OLE DB.*SQL Server", r"(\W|\A)SQL Server.*Driver",
        r"Warning.*\Wmssql_", r"Warning.*\Wsqlsrv_", r"Warning.*\Wodbc_",
        r"SQLException", r"SQLiteException", r"SQLite3::", r"Warning.*\Wsqlite_",
        r"Microsoft Access.*Driver", r"JET Database Engine", r"ORA-\d{5}",
        r"Oracle error"
    ]

    def __init__(self, http_client: HTTPClient, auth_handler: AuthHandler = None):
        super().__init__(http_client, auth_handler)
        self.vulnerable_endpoints: List[Dict[str, Any]] = []

    def _safe_list(self, value: Any) -> List[str]:
        """안전한 리스트 변환"""
        if value is None:
            return []
        if isinstance(value, str):
            return [p.strip() for p in value.split(',') if p.strip()]
        if isinstance(value, list):
            return value
        return []

    def _safe_dict(self, value: Any) -> Dict[str, str]:
        """안전한 딕셔너리 변환"""
        if value is None:
            return {}
        if isinstance(value, str):
            result = {}
            for pair in value.split(','):
                if ':' in pair:
                    k, v = pair.split(':', 1)
                    result[k.strip()] = v.strip()
            return result
        if isinstance(value, dict):
            return value
        return {}

    def _encode_payload(self, payload: str) -> str:
        """
        페이로드 내의 특수 문자(특히 주석 #)를 URL 인코딩하여
        서버에 안전하게 전달되도록 처리합니다.
        """
        if '#' in payload:
            return payload.replace('#', '%23')
        return payload

    def scan_endpoint(self, endpoint: Dict[str, Any], payloads: List[str]) -> List[Dict[str, Any]]:
        if not isinstance(endpoint, dict) or not endpoint:
            print(f"경고: 유효하지 않은 endpoint: {endpoint}")
            return []

        results = []
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET').upper()
        
        # 안전한 파라미터/경로변수 추출
        params = self._safe_list(endpoint.get('params'))
        path_variables_raw = endpoint.get('path_variables', {})
        path_variables = self._safe_dict(path_variables_raw)
        path_var_names = re.findall(r'\{(\w+)\}', path)

        print(f"\n[SQLi 스캔] {method} {path}")
        if params:
            print(f"테스트할 파라미터: {params}")
        if path_var_names:
            print(f"URL 경로 변수: {path_var_names}")

        # 인증 확인
        try:
            if not self._check_auth(endpoint):
                print(f" 경고: {path} 인증 실패, 스캔 건너뜀")
                return results
        except:
            pass

        auth_cookies = self._get_auth_cookies()

        # 1. URL 경로 변수 테스트
        for path_var_name in path_var_names:
            print(f" URL 경로 변수 '{path_var_name}' 테스트 중...")
            try:
                baseline_response = self._make_baseline_path_var_request(
                    method, path, path_variables, auth_cookies
                )
                baseline_time = baseline_response.elapsed.total_seconds()
                baseline_text = baseline_response.text.lower()

                for payload in payloads: 
                    # ✅ 개선: 페이로드 인코딩 적용
                    encoded_payload = self._encode_payload(payload)
                    
                    result = self._test_path_var_payload(
                        method, path, path_var_name, encoded_payload,
                        baseline_response, baseline_time, baseline_text,
                        auth_cookies, path_variables, original_payload=payload
                    )
                    
                    if result:
                        results.append(result)
                        self.results.append(result)
                        print(f" ⚠️ 취약점 발견: {result['vulnerability']}")
                        
            except Exception as e:
                print(f" 경고: {e}")
                continue

        # 2. 쿼리/폼 파라미터 테스트
        for param_name in params:
            print(f" 파라미터 '{param_name}' 테스트 중...")
            try:
                baseline_response = self._make_baseline_param_request(
                    method, path, param_name, path_variables, auth_cookies
                )
                baseline_time = baseline_response.elapsed.total_seconds()
                baseline_text = baseline_response.text.lower()

                for payload in payloads: 
                    # ✅ 개선: 페이로드 인코딩 적용
                    encoded_payload = self._encode_payload(payload)

                    result = self._test_param_payload(
                        method, path, param_name, encoded_payload,
                        baseline_response, baseline_time, baseline_text,
                        path_variables, auth_cookies, original_payload=payload
                    )

                    if result:
                        results.append(result)
                        self.results.append(result)
                        print(f" ⚠️ 취약점 발견: {result['vulnerability']}")

            except Exception as e:
                print(f" 경고: 기준 요청 실패 - {e}")
                continue

        return results

    def _make_baseline_param_request(self, method: str, path: str, param_name: str, 
                                   path_variables: Dict[str, str], auth_cookies: Dict):
        """파라미터 기준 요청"""
        processed_path = self._process_path(path, path_variables)
        if method == 'GET':
            return self.client.get(processed_path, params={param_name: '1'}, cookies=auth_cookies)
        else:
            return self.client.post(processed_path, data={param_name: '1'}, cookies=auth_cookies)

    def _make_baseline_path_var_request(self, method: str, path: str, 
                                      path_variables: Dict[str, str], auth_cookies: Dict):
        """경로변수 기준 요청"""
        processed_path = self._process_path(path, path_variables)
        if method == 'GET':
            return self.client.get(processed_path, cookies=auth_cookies)
        else:
            return self.client.post(processed_path, cookies=auth_cookies)

    def _process_path(self, path: str, path_variables: Dict[str, str]) -> str:
        """경로변수 치환"""
        processed = path
        for var_name, var_value in path_variables.items():
            if var_name and var_value:
                processed = processed.replace('{' + var_name + '}', str(var_value))
        return processed

    def _test_param_payload(self, method: str, path: str, param_name: str, payload: str,
                          baseline_response, baseline_time: float, baseline_text: str,
                          path_variables: Dict, auth_cookies: Dict, original_payload: str = None):
        """파라미터 페이로드 테스트"""
        try:
            # 인코딩된 페이로드가 들어오지만, 리포트에는 원본 페이로드를 보여주기 위해 저장
            report_payload = original_payload if original_payload else payload

            response = self.client.inject_payload(
                method, path, param_name, payload,
                cookies=auth_cookies, path_variables=path_variables
            )
        except:
            return None

        return self._analyze_response(response, baseline_response, baseline_time, 
                                    baseline_text, report_payload, param_name, method, path)

    def _test_path_var_payload(self, method: str, path: str, path_var_name: str, payload: str,
                             baseline_response, baseline_time: float, baseline_text: str,
                             auth_cookies: Dict, path_variables: Dict, original_payload: str = None):
        """경로변수 페이로드 테스트"""
        try:
            report_payload = original_payload if original_payload else payload
            
            response = self.client.inject_payload(
                method, path, path_var_name, payload,
                cookies=auth_cookies, path_variables=path_variables
            )
        except:
            return None

        param_label = f"{path_var_name} (URL 경로 변수)"
        return self._analyze_response(response, baseline_response, baseline_time, 
                                    baseline_text, report_payload, param_label, method, path)

    def _analyze_response(self, response, baseline_response, baseline_time: float,
                        baseline_text: str, payload: str, param_label: str,
                        method: str, path: str) -> Dict[str, Any]:
        """응답 분석"""
        response_time = response.elapsed.total_seconds()
        response_text = response.text.lower()
        payload_lower = payload.lower()

        # 1️⃣ TIME-BASED 우선 체크
        if any(time_keyword in payload_lower for time_keyword in ['sleep', 'waitfor delay', 'pgsleep', 'dbmspipe']):
            if response_time > baseline_time + 2.5:
                return {
                    'type': 'SQL Injection',
                    'vulnerability': 'Time-based Blind SQLi',
                    'endpoint': path, 'method': method, 'parameter': param_label,
                    'payload': payload, 'status_code': response.status_code,
                    'evidence': f'지연: {baseline_time:.2f}s -> {response_time:.2f}s (페이로드: {payload})',
                    'severity': 'High'
                }

        # 2️⃣ 일반 TIME-BASED 체크
        if response_time > baseline_time + 2.5:
            return {
                'type': 'SQL Injection', 'vulnerability': 'Time-based Blind SQLi',
                'endpoint': path, 'method': method, 'parameter': param_label,
                'payload': payload, 'status_code': response.status_code,
                'evidence': f'지연: {baseline_time:.2f}s -> {response_time:.2f}s',
                'severity': 'High'
            }

        # 3️⃣ ERROR-BASED 체크 (Time-based 아닌 경우만)
        if self._check_sql_errors(response_text):
            return {
                'type': 'SQL Injection', 'vulnerability': 'Error-based SQLi',
                'endpoint': path, 'method': method, 'parameter': param_label,
                'payload': payload, 'status_code': response.status_code,
                'evidence': self._extract_sql_error(response_text),
                'severity': 'High'
            }

        # 4️⃣ BOOLEAN-BASED
        if self._check_boolean_based(response_text, baseline_text):
            return {
                'type': 'SQL Injection', 'vulnerability': 'Boolean-based Blind SQLi',
                'endpoint': path, 'method': method, 'parameter': param_label,
                'payload': payload, 'status_code': response.status_code,
                'evidence': '응답 내용 변화 감지',
                'severity': 'Medium'
            }

        # 5️⃣ UNION-BASED
        if self._check_union_based(response_text, baseline_text):
            return {
                'type': 'SQL Injection', 'vulnerability': 'Union-based SQLi',
                'endpoint': path, 'method': method, 'parameter': param_label,
                'payload': payload, 'status_code': response.status_code,
                'evidence': 'UNION 데이터 노출',
                'severity': 'High'
            }

        return None

    def _check_sql_errors(self, text: str) -> bool:
        """SQL 에러 패턴 확인"""
        return any(re.search(p, text, re.IGNORECASE) for p in self.SQL_ERROR_PATTERNS)

    def _extract_sql_error(self, text: str) -> str:
        """SQL 에러 메시지 추출"""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                return text[start:end][:200]
        return "SQL 에러 감지됨"

    def _check_boolean_based(self, resp_text: str, base_text: str) -> bool:
        """Boolean-based 탐지"""
        length_diff = abs(len(resp_text) - len(base_text))
        return length_diff > len(base_text) * 0.1

    def _check_union_based(self, resp_text: str, base_text: str) -> bool:
        """Union-based 탐지"""
        return 'union' in resp_text and len(resp_text) > len(base_text) * 1.3
