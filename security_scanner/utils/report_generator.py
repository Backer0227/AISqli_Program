"""
리포트 생성 모듈
스캔 결과를 JSON, CSV 형식으로 저장합니다.
"""
import json
import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class ReportGenerator:
    """스캔 결과 리포트를 생성하는 클래스"""
    
    def __init__(self, output_dir: str = "results"):
        """
        ReportGenerator 초기화
        
        Args:
            output_dir: 출력 디렉토리 경로
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate(
        self,
        results: List[Dict[str, Any]],
        formats: List[str] = ["json", "csv"],
        include_payloads: bool = True,
        include_evidence: bool = True
    ) -> Dict[str, str]:
        """
        리포트를 생성합니다.
        
        Args:
            results: 스캔 결과 리스트
            formats: 생성할 리포트 형식 리스트
            include_payloads: 페이로드 포함 여부
            include_evidence: 증거 포함 여부
            
        Returns:
            생성된 파일 경로 딕셔너리
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generated_files = {}
        
        # 요약 정보 생성
        summary = self._generate_summary(results)
        
        if "json" in formats:
            json_path = self._generate_json(
                results, summary, timestamp, include_payloads, include_evidence
            )
            generated_files["json"] = str(json_path)
        
        if "csv" in formats:
            csv_path = self._generate_csv(
                results, timestamp, include_payloads, include_evidence
            )
            generated_files["csv"] = str(csv_path)
        
        return generated_files
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """스캔 결과 요약을 생성합니다."""
        total = len(results)
        
        by_type = {}
        by_severity = {"High": 0, "Medium": 0, "Low": 0}
        by_endpoint = {}
        
        for result in results:
            vuln_type = result.get("type", "Unknown")
            severity = result.get("severity", "Unknown")
            endpoint = result.get("endpoint", "Unknown")
            
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            if severity in by_severity:
                by_severity[severity] += 1
            
            if endpoint not in by_endpoint:
                by_endpoint[endpoint] = []
            by_endpoint[endpoint].append(result)
        
        return {
            "total_vulnerabilities": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "by_endpoint": {k: len(v) for k, v in by_endpoint.items()},
            "scan_time": datetime.now().isoformat()
        }
    
    def _generate_json(
        self,
        results: List[Dict[str, Any]],
        summary: Dict[str, Any],
        timestamp: str,
        include_payloads: bool,
        include_evidence: bool
    ) -> Path:
        """JSON 리포트를 생성합니다."""
        output_data = {
            "summary": summary,
            "vulnerabilities": []
        }
        
        for result in results:
            vuln_data = {
                "type": result.get("type"),
                "vulnerability": result.get("vulnerability"),
                "endpoint": result.get("endpoint"),
                "method": result.get("method"),
                "parameter": result.get("parameter"),
                "status_code": result.get("status_code"),
                "severity": result.get("severity")
            }
            
            if include_payloads:
                vuln_data["payload"] = result.get("payload")
            
            if include_evidence:
                vuln_data["evidence"] = result.get("evidence")
            
            output_data["vulnerabilities"].append(vuln_data)
        
        file_path = self.output_dir / f"scan_report_{timestamp}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        return file_path
    
    def _generate_csv(
        self,
        results: List[Dict[str, Any]],
        timestamp: str,
        include_payloads: bool,
        include_evidence: bool
    ) -> Path:
        """CSV 리포트를 생성합니다."""
        file_path = self.output_dir / f"scan_report_{timestamp}.csv"
        
        # CSV 헤더 정의
        headers = [
            "Type",
            "Vulnerability",
            "Endpoint",
            "Method",
            "Parameter",
            "Status Code",
            "Severity"
        ]
        
        if include_payloads:
            headers.append("Payload")
        
        if include_evidence:
            headers.append("Evidence")
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for result in results:
                row = {
                    "Type": result.get("type", ""),
                    "Vulnerability": result.get("vulnerability", ""),
                    "Endpoint": result.get("endpoint", ""),
                    "Method": result.get("method", ""),
                    "Parameter": result.get("parameter", ""),
                    "Status Code": result.get("status_code", ""),
                    "Severity": result.get("severity", "")
                }
                
                if include_payloads:
                    row["Payload"] = result.get("payload", "")
                
                if include_evidence:
                    # CSV에서는 증거를 간단히 표시
                    evidence = result.get("evidence", "")
                    if len(evidence) > 200:
                        evidence = evidence[:200] + "..."
                    row["Evidence"] = evidence.replace('\n', ' ').replace('\r', ' ')
                
                writer.writerow(row)
        
        return file_path
    
    def print_summary(self, summary: Dict[str, Any]):
        """요약 정보를 콘솔에 출력합니다."""
        print("\n" + "="*60)
        print("스캔 결과 요약")
        print("="*60)
        print(f"총 취약점 수: {summary['total_vulnerabilities']}")
        print(f"\n유형별 분류:")
        for vuln_type, count in summary['by_type'].items():
            print(f"  - {vuln_type}: {count}개")
        print(f"\n심각도별 분류:")
        for severity, count in summary['by_severity'].items():
            if count > 0:
                print(f"  - {severity}: {count}개")
        print(f"\n엔드포인트별 분류:")
        for endpoint, count in summary['by_endpoint'].items():
            print(f"  - {endpoint}: {count}개")
        print("="*60)

