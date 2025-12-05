#!/usr/bin/env python3
"""
보안 스캐너 메인 실행 스크립트
SQL Injection 및 XSS 취약점을 자동으로 진단합니다.
"""
import sys
import argparse
from pathlib import Path

# 프로젝트 루트를 Python 경로에 추가
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from utils.config_loader import ConfigLoader
from utils.http_client import HTTPClient
from utils.auth_handler import AuthHandler
from utils.payload_loader import PayloadLoader
from utils.report_generator import ReportGenerator
from utils.endpoint_discoverer import EndpointDiscoverer
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(
        description="웹 애플리케이션 보안 스캐너 - SQL Injection 및 XSS 취약점 진단"
    )
    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config/config.yaml',
        help='설정 파일 경로 (기본값: config/config.yaml)'
    )
    parser.add_argument(
        '--sqli-only',
        action='store_true',
        help='SQL Injection 스캔만 수행'
    )
    parser.add_argument(
        '--xss-only',
        action='store_true',
        help='XSS 스캔만 수행'
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("보안 스캐너 시작")
    print("="*60)
    
    # 설정 로드
    try:
        config = ConfigLoader(args.config)
        print(f"설정 파일 로드 완료: {args.config}")
    except Exception as e:
        print(f"오류: 설정 파일을 로드할 수 없습니다 - {e}")
        return 1
    
    # HTTP 클라이언트 초기화
    http_client = HTTPClient(
        base_url=config.get_target_url(),
        timeout=config.get_timeout(),
        verify_ssl=config.get("target.verify_ssl", False),
        delay=config.get("scan.delay", 0.5),
        max_retries=config.get("scan.max_retries", 3),
        follow_redirects=config.get("scan.follow_redirects", True)
    )
    
    # 인증 핸들러 초기화
    auth_config = config.get_auth_config()
    auth_handler = None
    if auth_config.get('enabled', False):
        auth_handler = AuthHandler(http_client, auth_config)
        print("\n인증 시도 중...")
        if auth_handler.login():
            print("✓ 인증 성공")
        else:
            print("⚠ 경고: 인증 실패 (인증이 필요한 엔드포인트는 스캔되지 않을 수 있습니다)")
    
    # 페이로드 로드
    payload_loader = PayloadLoader()
    
    # 엔드포인트 자동 탐지
    endpoints = []
    if config.is_auto_detect_enabled():
        print("\n" + "="*60)
        print("엔드포인트 자동 탐지 시작")
        print("="*60)
        
        discovery_config = config.get_endpoint_discovery_config()
        discoverer = EndpointDiscoverer(http_client, config.get_target_url())
        
        discovered = discoverer.discover_all(
            enable_crawling=discovery_config.get('enable_crawling', True),
            enable_source_analysis=discovery_config.get('enable_source_analysis', True),
            source_path=discovery_config.get('source_path', None)
        )
        
        discoverer.print_discovered_endpoints()
        endpoints = discovered
        
        if not endpoints:
            print("\n경고: 자동 탐지로 엔드포인트를 찾지 못했습니다.")
            print("수동 설정된 엔드포인트를 사용합니다.")
            endpoints = config.get_endpoints()
    else:
        endpoints = config.get_endpoints()
    
    if not endpoints:
        print("\n경고: 엔드포인트가 설정되지 않았습니다.")
        print("config/config.yaml 파일의 endpoints 섹션을 확인하세요.")
        return 1
    
    all_results = []
    
    # SQL Injection 스캔
    if not args.xss_only:
        print("\n" + "="*60)
        print("SQL Injection 스캔 시작")
        print("="*60)
        
        sqli_payloads = payload_loader.load_sqli_payloads()
        print(f"로드된 SQLi 페이로드: {len(sqli_payloads)}개")
        
        sqli_scanner = SQLiScanner(http_client, auth_handler)
        
        for endpoint in endpoints:
            try:
                results = sqli_scanner.scan_endpoint(endpoint, sqli_payloads)
                all_results.extend(results)
            except Exception as e:
                print(f"오류: {endpoint.get('path', 'Unknown')} 스캔 중 오류 발생 - {e}")
        
        sqli_results = sqli_scanner.get_results()
        print(f"\nSQL Injection 스캔 완료: {len(sqli_results)}개 취약점 발견")
    
    # XSS 스캔
    if not args.sqli_only:
        print("\n" + "="*60)
        print("XSS 스캔 시작")
        print("="*60)
        
        xss_payloads = payload_loader.load_xss_payloads()
        print(f"로드된 XSS 페이로드: {len(xss_payloads)}개")
        
        xss_scanner = XSSScanner(http_client, auth_handler)
        
        for endpoint in endpoints:
            try:
                results = xss_scanner.scan_endpoint(endpoint, xss_payloads)
                all_results.extend(results)
            except Exception as e:
                print(f"오류: {endpoint.get('path', 'Unknown')} 스캔 중 오류 발생 - {e}")
        
        xss_results = xss_scanner.get_results()
        print(f"\nXSS 스캔 완료: {len(xss_results)}개 취약점 발견")
    
    # 리포트 생성
    print("\n" + "="*60)
    print("리포트 생성 중...")
    print("="*60)
    
    report_config = config.get_report_config()
    report_generator = ReportGenerator(
        output_dir=report_config.get('output_dir', 'results')
    )
    
    generated_files = report_generator.generate(
        results=all_results,
        formats=report_config.get('format', ['json', 'csv']),
        include_payloads=report_config.get('include_payloads', True),
        include_evidence=report_config.get('include_evidence', True)
    )
    
    # 요약 출력
    summary = report_generator._generate_summary(all_results)
    report_generator.print_summary(summary)
    
    # 엔드포인트 통계 출력
    if config.is_auto_detect_enabled():
        print(f"\n자동 탐지된 엔드포인트: {len(endpoints)}개")
        print(f"스캔된 엔드포인트: {len(endpoints)}개")
    
    # 생성된 파일 경로 출력
    print("\n생성된 리포트 파일:")
    for format_type, file_path in generated_files.items():
        print(f"  - {format_type.upper()}: {file_path}")
    
    print("\n" + "="*60)
    print("스캔 완료")
    print("="*60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

