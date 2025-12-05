"""
설정 파일 로더 모듈
YAML 설정 파일을 읽고 파싱합니다.
"""
import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigLoader:
    """설정 파일을 로드하고 관리하는 클래스"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        ConfigLoader 초기화
        
        Args:
            config_path: 설정 파일 경로 (기본값: config/config.yaml)
        """
        if config_path is None:
            # 프로젝트 루트 기준으로 config/config.yaml 찾기
            project_root = Path(__file__).parent.parent
            config_path = project_root / "config" / "config.yaml"
        
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load()
    
    def load(self) -> Dict[str, Any]:
        """
        설정 파일을 로드합니다.
        
        Returns:
            로드된 설정 딕셔너리
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"설정 파일을 찾을 수 없습니다: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f) or {}
        
        return self.config
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        설정 값을 가져옵니다. 점(.)으로 중첩된 키를 지원합니다.
        
        Args:
            key: 설정 키 (예: "target.base_url")
            default: 기본값
            
        Returns:
            설정 값
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def get_target_url(self) -> str:
        """대상 서버의 base URL을 반환합니다."""
        return self.get("target.base_url", "http://localhost:80")
    
    def get_timeout(self) -> int:
        """요청 타임아웃을 반환합니다."""
        return self.get("target.timeout", 10)
    
    def get_auth_config(self) -> Dict[str, Any]:
        """인증 설정을 반환합니다."""
        return self.get("auth", {})
    
    def get_scan_config(self) -> Dict[str, Any]:
        """스캔 설정을 반환합니다."""
        return self.get("scan", {})
    
    def get_report_config(self) -> Dict[str, Any]:
        """리포트 설정을 반환합니다."""
        return self.get("report", {})
    
    def get_endpoints(self) -> list:
        """엔드포인트 설정을 반환합니다."""
        return self.get("endpoints.manual", [])
    
    def is_auto_detect_enabled(self) -> bool:
        """자동 탐지가 활성화되어 있는지 확인합니다."""
        return self.get("endpoints.auto_detect", False)
    
    def get_endpoint_discovery_config(self) -> Dict[str, Any]:
        """엔드포인트 탐지 설정을 반환합니다."""
        return self.get("endpoints.discovery", {})

