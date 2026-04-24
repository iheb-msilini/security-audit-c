from io import BytesIO
import json

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


class ReportGenerator:
    @staticmethod
    def as_json(payload: dict) -> str:
        return json.dumps(payload, indent=2)

    @staticmethod
    def as_pdf(payload: dict) -> bytes:
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        y = 800
        c.drawString(40, y, f"Audit Report: {payload.get('audit', {}).get('name', 'N/A')}")
        y -= 24
        c.drawString(40, y, f"Score: {payload.get('audit', {}).get('score', 0)}")
        y -= 24
        c.drawString(40, y, "Findings:")
        for finding in payload.get("findings", []):
            y -= 18
            if y < 50:
                c.showPage()
                y = 800
            c.drawString(50, y, f"- {finding['check_id']} [{finding['status']}] {finding['title']}")
        c.showPage()
        c.save()
        return buffer.getvalue()
