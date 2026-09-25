"""PDF 审计报告生成（ReportLab + 内置中文字体 STSong-Light）。"""
import os

from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas

pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "generated", "reports")

SEVERITY_LABELS = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}


def generate_pdf(result: dict) -> str:
    """基于审计记录生成 PDF，返回文件路径。"""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"{result['id']}.pdf")

    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    y = height - 60

    def line(text: str, size: int = 11, gap: int = 18, indent: int = 60) -> None:
        nonlocal y
        if y < 60:  # 简单分页
            c.showPage()
            c.setFont("STSong-Light", size)
            y = height - 60
        c.setFont("STSong-Light", size)
        c.drawString(indent, y, text)
        y -= gap

    line("智能合约安全审计报告", 18, 30)
    line(f"文件: {result['filename']}")
    line(f"审计时间: {result['timestamp']}")
    line(f"安全评分: {result['score']} / 100 ({result.get('grade', '')})")
    line(f"评分口径: {result.get('scoringVersion', '')}", 11, 28)

    line(f"发现漏洞 ({len(result['vulnerabilities'])})", 14, 24)
    for v in result["vulnerabilities"]:
        sev = SEVERITY_LABELS.get(v["severity"], v["severity"])
        line(f"[{sev}] {v['type']} — 第 {v['line']} 行", 11, 16, indent=70)
        line(f"建议: {v['suggestion']}", 10, 20, indent=80)

    if result.get("gasIssues"):
        line(f"Gas 优化建议 ({len(result['gasIssues'])})", 14, 24)
        for g in result["gasIssues"]:
            line(f"{g['functionName']}: {g['currentGas']} → {g['optimizedGas']}", 11, 16, indent=70)
            line(f"建议: {g['suggestion']}", 10, 20, indent=80)

    c.save()
    return path
