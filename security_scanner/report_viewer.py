import json
import sys
import os
import webbrowser
import argparse
from collections import defaultdict


def load_json_report(json_path):
    """JSON 리포트 파일 로드 (호환성 처리 포함)"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # 호환성 처리: 리스트라면 구버전 포맷 -> dict로 감싸서 반환
        if isinstance(data, list):
            return {
                "vulnerabilities": data
            }
        return data  # 신버전 포맷 (dict)
        
    except Exception as e:
        print(f"JSON 파일 로드 실패: {e}")
        return None


def group_by_endpoint_param(vulnerabilities):
    """
    같은 엔드포인트 + 메서드 + 파라미터를 하나로 묶는다.
    key: (endpoint, method, parameter)
    value: 해당 조합에서 발견된 모든 취약점 레코드 리스트
    """
    grouped = defaultdict(list)
    for v in vulnerabilities:
        key = (v.get("endpoint"), v.get("method"), v.get("parameter"))
        grouped[key].append(v)
    return grouped


def generate_html_table_with_modals(vulnerabilities):
    """
    취약점 리스트를 HTML 테이블 + 모달로 변환
    """
    by_ep = group_by_endpoint_param(vulnerabilities)
    
    table_html = ""
    modals_html = ""
    
    for (endpoint, method, param), items in by_ep.items():
        # 모달 고유 ID 생성
        modal_id = f"modal_{abs(hash((endpoint, method, param))) % 1000000}"
        
        # 심각도 결정 (가장 높은 것)
        severities = [str(i.get("severity", "low")).lower() for i in items]
        if "critical" in severities: severity = "critical"
        elif "high" in severities: severity = "high"
        elif "medium" in severities: severity = "medium"
        else: severity = "low"
        
        severity_badge = f'<span class="badge badge-{severity}">{severity.upper()}</span>'
        
        # 테이블 행 추가
        table_html += f"""
        <tr>
            <td>{endpoint}</td>
            <td>{method}</td>
            <td>{param}</td>
            <td>{severity_badge}</td>
            <td>{len(items)}</td>
            <td>
                <button type="button" class="btn btn-primary btn-sm" data-toggle="modal" data-target="#{modal_id}">
                    보기
                </button>
            </td>
        </tr>
        """
        
        # 모달 내용 생성
        modal_list_items = ""
        for idx, item in enumerate(items, 1):
            payload = item.get('payload', '-')
            evidence = item.get('evidence', '-')
            # HTML 이스케이프 처리 (보안상 권장)
            payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            evidence = evidence.replace('<', '&lt;').replace('>', '&gt;')
            
            modal_list_items += f"""
            <li class="list-group-item">
                <h6><strong>#{idx} Payload:</strong></h6>
                <pre class="bg-light p-2"><code>{payload}</code></pre>
                <p class="mb-1"><strong>Evidence:</strong></p>
                <pre class="text-danger small">{evidence}</pre>
            </li>
            """
            
        modals_html += f"""
        <div class="modal fade" id="{modal_id}" tabindex="-1" role="dialog" aria-hidden="true">
            <div class="modal-dialog modal-lg" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Details: {endpoint} ({param})</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <ul class="list-group">
                            {modal_list_items}
                        </ul>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        """
        
    return table_html, modals_html


def save_html_report(report_data, output_filename):
    # vulnerabilities 키가 없으면 빈 리스트 사용
    vulnerabilities = report_data.get('vulnerabilities', [])
    
    table_html, modals_html = generate_html_table_with_modals(vulnerabilities)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {{ padding: 20px; background-color: #f8f9fa; }}
            .header {{ margin-bottom: 30px; border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }}
            .badge-critical {{ background-color: #721c24; color: white; }}
            .badge-high {{ background-color: #dc3545; color: white; }}
            .badge-medium {{ background-color: #ffc107; color: black; }}
            .badge-low {{ background-color: #17a2b8; color: white; }}
            pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        </style>
    </head>
    <body>
        <div class="container-fluid">
            <div class="header">
                <h1>🛡️ 취약점 스캔 리포트</h1>
            </div>
            
            <div class="card shadow-sm">
                <div class="card-header bg-white">
                    <h5 class="mb-0">SQL Injection 발견 목록 ({len(vulnerabilities)}건)</h5>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead class="thead-light">
                            <tr>
                                <th>엔드포인트</th>
                                <th>메서드</th>
                                <th>파라미터</th>
                                <th>심각도</th>
                                <th>페이로드 개수</th>
                                <th>상세보기</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Modals -->
        {modals_html}
        
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"📊 HTML 리포트 생성 완료: {output_filename}")
    return output_filename


def main():
    parser = argparse.ArgumentParser(description="JSON 리포트를 HTML로 변환")
    parser.add_argument("json_file", help="입력 JSON 파일 경로")
    args = parser.parse_args()
    
    if not os.path.exists(args.json_file):
        print(f"파일을 찾을 수 없습니다: {args.json_file}")
        return

    data = load_json_report(args.json_file)
    if not data:
        return

    # 출력 파일명 생성 (입력파일.html)
    output_file = os.path.splitext(args.json_file)[0] + ".html"
    
    save_html_report(data, output_file)
    
    # 브라우저로 열기
    try:
        webbrowser.open(f"file://{os.path.abspath(output_file)}")
    except:
        pass


if __name__ == "__main__":
    main()
