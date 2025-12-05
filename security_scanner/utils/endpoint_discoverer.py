"""
엔드포인트 자동 탐지 모듈
HTML 크롤링 및 Flask 소스 코드 분석을 통해 엔드포인트를 자동으로 발견합니다.
"""
import re
from typing import Dict, Any, List, Set, Optional
from urllib.parse import urljoin, urlparse
from pathlib import Path
from utils.http_client import HTTPClient


class EndpointDiscoverer:
    """엔드포인트를 자동으로 탐지하는 클래스"""
    
    def __init__(self, http_client: HTTPClient, base_url: str):
        """
        EndpointDiscoverer 초기화
        
        Args:
            http_client: HTTPClient 인스턴스
            base_url: 기본 URL
        """
        self.client = http_client
        self.base_url = base_url.rstrip('/')
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.visited_urls: Set[str] = set()
        self.max_depth = 3  # 최대 크롤링 깊이
        self.max_pages = 50  # 최대 페이지 수
    
    def discover_all(
        self,
        enable_crawling: bool = True,
        enable_source_analysis: bool = True,
        source_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        모든 방법을 사용하여 엔드포인트를 탐지합니다.
        
        Args:
            enable_crawling: HTML 크롤링 활성화
            enable_source_analysis: 소스 코드 분석 활성화
            source_path: Flask 소스 코드 경로 (선택사항)
            
        Returns:
            발견된 엔드포인트 리스트
        """
        all_endpoints = []
        
        if enable_crawling:
            print("\n[엔드포인트 탐지] HTML 크롤링 시작...")
            crawled_endpoints = self.discover_from_crawling()
            all_endpoints.extend(crawled_endpoints)
            print(f"  ✓ HTML 크롤링으로 {len(crawled_endpoints)}개 엔드포인트 발견")
        
        if enable_source_analysis:
            print("\n[엔드포인트 탐지] Flask 소스 코드 분석 시작...")
            if source_path:
                source_endpoints = self.discover_from_source(source_path)
            else:
                # 기본 경로에서 찾기
                source_endpoints = self.discover_from_source()
            all_endpoints.extend(source_endpoints)
            print(f"  ✓ 소스 코드 분석으로 {len(source_endpoints)}개 엔드포인트 발견")
        
        # 중복 제거 및 정리
        unique_endpoints = self._deduplicate_endpoints(all_endpoints)
        self.discovered_endpoints = unique_endpoints
        
        return unique_endpoints
    
    def discover_from_crawling(self) -> List[Dict[str, Any]]:
        """
        HTML 크롤링을 통해 엔드포인트를 발견합니다.
        
        Returns:
            발견된 엔드포인트 리스트
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print("  경고: BeautifulSoup4가 설치되지 않았습니다. HTML 크롤링을 건너뜁니다.")
            print("  설치: pip install beautifulsoup4")
            return []
        
        endpoints = []
        self.visited_urls.clear()
        
        # 시작 URL에서 크롤링 시작
        start_urls = [self.base_url, f"{self.base_url}/"]
        
        for start_url in start_urls:
            if start_url not in self.visited_urls:
                self._crawl_page(start_url, endpoints, depth=0)
        
        return endpoints
    
    def _crawl_page(
        self,
        url: str,
        endpoints: List[Dict[str, Any]],
        depth: int = 0
    ):
        """
        단일 페이지를 크롤링합니다.
        
        Args:
            url: 크롤링할 URL
            endpoints: 엔드포인트 리스트 (결과 저장)
            depth: 현재 깊이
        """
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            from bs4 import BeautifulSoup
            
            # 페이지 요청
            response = self.client.get(url)
            if response.status_code != 200:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 링크 추출
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    
                    # 같은 도메인인지 확인
                    if parsed.netloc == urlparse(self.base_url).netloc or not parsed.netloc:
                        path = parsed.path
                        if path and path not in [e['path'] for e in endpoints]:
                            endpoints.append({
                                'path': path,
                                'method': 'GET',
                                'params': [],
                                'requires_auth': False,
                                'source': 'crawling'
                            })
                        
                        # 재귀적으로 크롤링
                        if depth < self.max_depth:
                            self._crawl_page(full_url, endpoints, depth + 1)
            
            # 폼 추출
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                if action:
                    full_url = urljoin(url, action)
                    parsed = urlparse(full_url)
                    
                    if parsed.netloc == urlparse(self.base_url).netloc or not parsed.netloc:
                        path = parsed.path
                        
                        # 입력 필드 추출
                        params = []
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            input_name = input_tag.get('name')
                            input_type = input_tag.get('type', 'text')
                            
                            if input_name and input_type not in ['submit', 'button', 'hidden']:
                                params.append(input_name)
                        
                        # 중복 체크
                        existing = next(
                            (e for e in endpoints if e['path'] == path and e['method'] == method),
                            None
                        )
                        
                        if not existing:
                            endpoints.append({
                                'path': path,
                                'method': method,
                                'params': params,
                                'requires_auth': False,  # 크롤링으로는 인증 여부 판단 불가
                                'source': 'crawling'
                            })
                        elif params:
                            # 기존 엔드포인트에 파라미터 추가
                            existing['params'] = list(set(existing['params'] + params))
        
        except Exception as e:
            # 크롤링 오류는 무시하고 계속 진행
            pass
    
    def discover_from_source(self, source_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Flask 소스 코드를 분석하여 엔드포인트를 발견합니다.
        
        Args:
            source_path: Flask 앱 파일 경로 (선택사항)
            
        Returns:
            발견된 엔드포인트 리스트
        """
        endpoints = []
        
        # 소스 코드 경로 찾기
        if source_path is None:
            # 기본 경로에서 찾기
            possible_paths = [
                Path("../resell_project-main/web/app.py"),
                Path("../../resell_project-main/web/app.py"),
                Path("../web/app.py"),
            ]
            
            for path in possible_paths:
                if path.exists():
                    source_path = str(path)
                    break
        
        if source_path is None or not Path(source_path).exists():
            print(f"  경고: Flask 소스 코드를 찾을 수 없습니다: {source_path}")
            return endpoints
        
        try:
            with open(source_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Flask 라우트 데코레이터 찾기
            # @app.route('/path', methods=['GET', 'POST'])
            route_pattern = r'@app\.route\([\'"]([^\'"]+)[\'"](?:,\s*methods=\[([^\]]+)\])?\)'
            
            for match in re.finditer(route_pattern, source_code):
                path = match.group(1)
                methods_str = match.group(2)
                
                # 메서드 추출
                if methods_str:
                    methods = [m.strip().strip("'\"") for m in methods_str.split(',')]
                else:
                    methods = ['GET']  # 기본값
                
                # 각 메서드에 대해 엔드포인트 생성
                for method in methods:
                    method = method.upper()
                    
                    # URL 경로 변수 추출 (예: <int:product_id>)
                    path_vars = {}
                    path_var_pattern = r'<(?:\w+:)?(\w+)>'
                    path_var_matches = re.findall(path_var_pattern, path)
                    
                    # Flask 형식을 우리 형식으로 변환
                    normalized_path = re.sub(r'<(?:\w+:)?(\w+)>', r'{\1}', path)
                    
                    # 함수 정의 찾기 (인증 데코레이터 확인)
                    func_start = source_code.find(match.group(0))
                    func_end = source_code.find('\n', func_start)
                    func_line = source_code[func_start:func_end]
                    
                    requires_auth = '@login_required' in func_line or 'login_required' in func_line
                    
                    # 파라미터 추출 (함수 시그니처에서)
                    params = []
                    if path_var_matches:
                        # URL 경로 변수가 있으면 기본값 설정
                        for var in path_var_matches:
                            path_vars[var] = "1"  # 기본값
                    
                    # 함수 본문에서 request.args.get, request.form.get 찾기
                    func_def_pattern = rf'def\s+\w+\([^)]*\):'
                    func_match = re.search(func_def_pattern, source_code[func_end:func_end+2000])
                    if func_match:
                        func_body_start = func_end + func_match.end()
                        func_body = source_code[func_body_start:func_body_start+2000]
                        
                        # GET 파라미터
                        get_params = re.findall(r'request\.args\.get\([\'"](\w+)[\'"]', func_body)
                        params.extend(get_params)
                        
                        # POST 파라미터
                        post_params = re.findall(r'request\.form\.get\([\'"](\w+)[\'"]', func_body)
                        if method == 'POST':
                            params.extend(post_params)
                    
                    endpoints.append({
                        'path': normalized_path,
                        'method': method,
                        'params': list(set(params)),  # 중복 제거
                        'path_variables': path_vars if path_vars else None,
                        'requires_auth': requires_auth,
                        'source': 'source_analysis'
                    })
        
        except Exception as e:
            print(f"  경고: 소스 코드 분석 중 오류 발생: {e}")
        
        return endpoints
    
    def _deduplicate_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        중복된 엔드포인트를 제거하고 통합합니다.
        
        Args:
            endpoints: 엔드포인트 리스트
            
        Returns:
            중복 제거된 엔드포인트 리스트
        """
        unique_endpoints = {}
        
        for endpoint in endpoints:
            key = (endpoint['path'], endpoint['method'])
            
            if key not in unique_endpoints:
                unique_endpoints[key] = endpoint
            else:
                # 기존 엔드포인트와 통합
                existing = unique_endpoints[key]
                
                # 파라미터 통합
                all_params = set(existing.get('params', []) + endpoint.get('params', []))
                existing['params'] = list(all_params)
                
                # path_variables 통합
                if endpoint.get('path_variables'):
                    if not existing.get('path_variables'):
                        existing['path_variables'] = {}
                    existing['path_variables'].update(endpoint['path_variables'])
                
                # requires_auth는 OR 연산 (하나라도 True면 True)
                existing['requires_auth'] = existing.get('requires_auth', False) or endpoint.get('requires_auth', False)
                
                # source 통합
                if 'source' in existing and 'source' in endpoint:
                    if existing['source'] != endpoint['source']:
                        existing['source'] = 'both'
        
        return list(unique_endpoints.values())
    
    def print_discovered_endpoints(self):
        """발견된 엔드포인트를 출력합니다."""
        if not self.discovered_endpoints:
            print("  발견된 엔드포인트가 없습니다.")
            return
        
        print(f"\n총 {len(self.discovered_endpoints)}개 엔드포인트 발견:")
        print("  " + "-" * 58)
        
        for endpoint in self.discovered_endpoints:
            method = endpoint['method']
            path = endpoint['path']
            params = endpoint.get('params', [])
            auth = "인증 필요" if endpoint.get('requires_auth') else "인증 불필요"
            source = endpoint.get('source', 'unknown')
            
            print(f"  ✓ {method:6} {path}")
            if params:
                print(f"      파라미터: {', '.join(params)}")
            if endpoint.get('path_variables'):
                path_vars = ', '.join(endpoint['path_variables'].keys())
                print(f"      URL 경로 변수: {path_vars}")
            print(f"      {auth} | 출처: {source}")
        
        print("  " + "-" * 58)

