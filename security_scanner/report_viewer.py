#!/usr/bin/env python3
"""
SQLi/XSS 스캔 리포트 JSON → HTML 변환기 (엔드포인트 단위 그룹 + 모달로 Payload 전체 보기)

- 입력:  results/scan_report_*.json
- 출력:  results/scan_report_*.html
"""

import json
from pathlib import Path
import argparse

# ------------------------------------------------------
# 리포트 로딩
# ------------------------------------------------------

def load_scan_reports():
    """results/scan_report_*.json 파일들 로드"""
    reports = {}
    results_dir = Path("results")
    if not results_dir.exists():
        print("❌ results 폴더가 없습니다. 먼저 스캔을 실행하세요.")
        return reports

    for file_path in results_dir.glob("scan_report_*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            reports[file_path.name] = {
                "data": data,
                "timestamp": file_path.stat().st_mtime,
                "size": file_path.stat().st_size,
                "path": file_path,
            }
        except Exception as e:
            print(f"⚠️ {file_path.name} 로드 실패: {e}")

    reports = dict(
        sorted(reports.items(), key=lambda x: x[1]["timestamp"], reverse=True)
    )
    return reports

# ------------------------------------------------------
# 엔드포인트 단위 그룹핑 & 집계
# ------------------------------------------------------

def group_by_endpoint(vulns):
    """
    같은 endpoint + method + parameter 기준으로 그룹핑.
    - vulnerabilities: 해당 지점에서 발견된 SQLi 유형 목록 (중복 제거)
    - payloads: 사용된 모든 페이로드 모음
    - severities: 사용된 심각도 집합 (표시용)
    - 대표 status_code, evidence는 첫 항목 사용
    """
    groups = {}

    for v in vulns:
        if not isinstance(v, dict):
            continue

        key = (
            v.get("endpoint"),
            v.get("method"),
            v.get("parameter"),
        )

        if key not in groups:
            groups[key] = {
                "endpoint": v.get("endpoint"),
                "method": v.get("method"),
                "parameter": v.get("parameter"),
                "vulnerabilities": set(),
                "payloads": [],
                "severities": set(),
                "status_code": v.get("status_code") or v.get("statuscode"),
                "evidence": v.get("evidence", ""),
            }

        g = groups[key]
        if v.get("vulnerability"):
            g["vulnerabilities"].add(v.get("vulnerability"))
        if v.get("payload"):
            g["payloads"].append(v.get("payload"))
        if v.get("severity"):
            g["severities"].add(v.get("severity"))

    grouped_list = []
    for (_endpoint, _method, _param), g in groups.items():
        grouped_list.append({
            "endpoint": g["endpoint"],
            "method": g["method"],
            "parameter": g["parameter"],
            "vulnerabilities": ", ".join(sorted(g["vulnerabilities"])) or "-",
            "payloads": g["payloads"],
            "severities": ", ".join(sorted(g["severities"])) or "-",
            "statuscode": g["status_code"],
            "evidence": g["evidence"],
        })

    return grouped_list

# ------------------------------------------------------
# HTML 테이블 + 모달 생성
# ------------------------------------------------------

def generate_html_table_with_modals(grouped):
    """엔드포인트 단위 그룹 리스트 → HTML 테이블 + Payload 모달들"""
    if not grouped:
        return "<p class='text-muted'>취약점이 없습니다.</p>", ""

    table_html = """
    <table class="table table-striped table-hover table-sm align-middle">
      <thead class="table-dark">
        <tr>
          <th>Endpoint</th>
          <th>Method</th>
          <th>Parameter</th>
          <th>취약점 유형들</th>
          <th>심각도들</th>
          <th>Payload</th>
          <th>Status</th>
          <th>대표 증거</th>
        </tr>
      </thead>
      <tbody>
    """

    modals_html = []

    for idx, item in enumerate(grouped):
        modal_id = f"payloadModal{idx}"

        # 셀에는 payload 개수와 일부만 표시
        payloads = item.get("payloads", [])
        count = len(payloads)
        if count == 0:
            payload_cell = "-"
        else:
            preview = ", ".join(p[:20] + ("..." if len(p) > 20 else "") for p in payloads[:2])
            if count > 2:
                preview += f" 외 {count-2}개"
            payload_cell = f"""
            <div class="text-truncate" style="max-width: 220px;">
              <small class="text-muted">{preview}</small>
            </div>
            <button type="button" class="btn btn-sm btn-outline-primary mt-1"
                    data-bs-toggle="modal" data-bs-target="#{modal_id}">
              전체 보기
            </button>
            """

        evidence = item.get("evidence", "-")
        if isinstance(evidence, str):
            evidence = evidence[:120]

        table_html += f"""
        <tr>
          <td><code>{item.get('endpoint','-')}</code></td>
          <td><span class="badge bg-light text-dark">{item.get('method','GET')}</span></td>
          <td><strong>{item.get('parameter','-')}</strong></td>
          <td>{item.get('vulnerabilities','-')}</td>
          <td>{item.get('severities','-')}</td>
          <td>{payload_cell}</td>
          <td>{item.get('statuscode','-')}</td>
          <td class="small">{evidence}</td>
        </tr>
        """

        # 모달 HTML (해당 엔드포인트의 payload 전체 리스트)
        if count > 0:
            payload_list_items = "".join(
                f"<li><code class='text-danger'>{p}</code></li>" for p in payloads
            )
            modals_html.append(f"""
            <div class="modal fade" id="{modal_id}" tabindex="-1" aria-labelledby="{modal_id}Label" aria-hidden="true">
              <div class="modal-dialog modal-dialog-scrollable modal-lg">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="{modal_id}Label">
                      Payload 목록 - {item.get('endpoint','-')} ({item.get('parameter','-')})
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                  <div class="modal-body">
                    <p class="mb-2"><strong>취약점 유형:</strong> {item.get('vulnerabilities','-')}</p>
                    <p class="mb-3"><strong>심각도:</strong> {item.get('severities','-')}</p>
                    <ul class="small">
                      {payload_list_items}
                    </ul>
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
                  </div>
                </div>
              </div>
            </div>
            """)

    table_html += "</tbody></table>"
    all_modals_html = "\n".join(modals_html)
    return table_html, all_modals_html

# ------------------------------------------------------
# HTML 리포트 생성
# ------------------------------------------------------

def create_html_report(report_data, json_filename, output_path):
    """완전한 HTML 리포트 생성"""

    raw = report_data

    if isinstance(raw, dict):
        if "vulnerabilities" in raw:
            raw_vulns = raw["vulnerabilities"]
        elif (
            "data" in raw
            and isinstance(raw["data"], dict)
            and "vulnerabilities" in raw["data"]
        ):
            raw_vulns = raw["data"]["vulnerabilities"]
        else:
            raw_vulns = raw.get("data", [])
    elif isinstance(raw, list):
        raw_vulns = raw
    else:
        raw_vulns = []

    vulns = [v for v in raw_vulns if isinstance(v, dict)]

    high_count = sum(1 for v in vulns if v.get("severity") == "High")
    medium_count = sum(1 for v in vulns if v.get("severity") == "Medium")
    low_count = sum(1 for v in vulns if v.get("severity") == "Low")
    total_raw = len(vulns)

    grouped = group_by_endpoint(vulns)
    total_grouped = len(grouped)

    table_html, modals_html = generate_html_table_with_modals(grouped)

    html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SQLi Scan Report - {json_filename}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {{
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
    }}
    .report-card {{
      background: rgba(255,255,255,0.95);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.1);
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
    }}
    .stat-card {{
      border-radius: 12px;
      padding: 16px;
      color: white;
      text-align: center;
      font-weight: 600;
    }}
    .stat-high {{ background: linear-gradient(45deg, #dc3545, #ff6b6b); }}
    .stat-medium {{ background: linear-gradient(45deg, #ffc107, #ffed4a); color: #212529; }}
    .stat-low {{ background: linear-gradient(45deg, #17a2b8, #5bc0de); }}
    .stat-total {{ background: linear-gradient(45deg, #6f42c1, #9f7aea); }}
    .stat-grouped {{ background: linear-gradient(45deg, #198754, #20c997); }}
    .table-sm td {{ padding: 8px 12px; vertical-align: middle; }}
    .text-danger {{ color: #dc3545 !important; }}
    .text-truncate {{ max-width: 220px; }}
  </style>
</head>
<body class="py-5">
  <div class="container">
    <div class="report-card p-4">
      <h1 class="mb-3 text-center text-primary">🔍 Security Scan Report</h1>
      <p class="text-muted text-center mb-4 fs-6">
        {json_filename} (원본 {total_raw} 개 → 엔드포인트 기준 {total_grouped} 개 그룹)
      </p>

      <div class="stats-grid mb-4">
        <div class="stat-card stat-high"><h3>{high_count}</h3><small>High</small></div>
        <div class="stat-card stat-medium"><h3>{medium_count}</h3><small>Medium</small></div>
        <div class="stat-card stat-low"><h3>{low_count}</h3><small>Low</small></div>
        <div class="stat-card stat-total"><h3>{total_raw}</h3><small>Total Findings (raw)</small></div>
        <div class="stat-card stat-grouped"><h3>{total_grouped}</h3><small>Endpoint Groups</small></div>
      </div>

      <h4 class="mb-3">📋 Endpoint‑based Vulnerabilities</h4>
      {table_html}
    </div>
  </div>

  {modals_html}

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ HTML 생성: {output_path} | 원본: {total_raw}개, 그룹: {total_grouped}개")

# ------------------------------------------------------
# main
# ------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="JSON → HTML 변환")
    parser.add_argument(
        "--file",
        type=str,
        help="특정 JSON 파일 (예: scan_report_20251205_151805.json)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="results/scan_report_*.json 전체 변환",
    )
    args = parser.parse_args()

    reports = load_scan_reports()
    if not reports:
        return 1

    results_dir = Path("results")

    if args.file:
        target = Path(args.file)
        if not target.is_absolute():
            target = results_dir / target.name
        if target.exists():
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)
            json_filename = target.name
            output_path = results_dir / json_filename.replace(".json", ".html")
            create_html_report(data, json_filename, output_path)
        else:
            print(f"❌ {target} 파일이 없습니다.")
            return 1
    elif args.all:
        for json_filename, info in reports.items():
            output_path = results_dir / json_filename.replace(".json", ".html")
            create_html_report(info["data"], json_filename, output_path)
    else:
        latest_file = list(reports.keys())[0]
        info = reports[latest_file]
        output_path = results_dir / latest_file.replace(".json", ".html")
        create_html_report(info["data"], latest_file, output_path)

    return 0

if __name__ == "__main__":
    exit(main())
