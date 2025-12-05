"""
페이로드 로더 모듈
SQL Injection 및 XSS 페이로드를 로드합니다.
"""
from pathlib import Path
from typing import List, Optional


class PayloadLoader:
    """페이로드를 로드하는 클래스"""
    
    def __init__(self, payloads_dir: Optional[str] = None):
        """
        PayloadLoader 초기화
        
        Args:
            payloads_dir: 페이로드 디렉토리 경로 (기본값: payloads/)
        """
        if payloads_dir is None:
            project_root = Path(__file__).parent.parent
            payloads_dir = project_root / "payloads"
        
        self.payloads_dir = Path(payloads_dir)
    
    def load_sqli_payloads(self) -> List[str]:
        """
        SQL Injection 페이로드를 로드합니다.
        
        Returns:
            페이로드 리스트
        """
        payload_file = self.payloads_dir / "sqli_payloads.txt"
        return self._load_payloads(payload_file)
    
    def load_xss_payloads(self) -> List[str]:
        """
        XSS 페이로드를 로드합니다.
        
        Returns:
            페이로드 리스트
        """
        payload_file = self.payloads_dir / "xss_payloads.txt"
        return self._load_payloads(payload_file)
    
    def _load_payloads(self, file_path: Path) -> List[str]:
        """
        페이로드 파일을 로드합니다.
        
        Args:
            file_path: 페이로드 파일 경로
            
        Returns:
            페이로드 리스트 (주석 및 빈 줄 제외)
        """
        if not file_path.exists():
            print(f"경고: 페이로드 파일을 찾을 수 없습니다: {file_path}")
            return []
        
        payloads = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # 주석이나 빈 줄은 제외
                if line and not line.startswith('#'):
                    payloads.append(line)
        
        return payloads

