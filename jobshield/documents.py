"""Builds send-ready letters: editable Word (.docx) drafts and final PDFs, DIN-5008-style layout."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Cm, Pt
from reportlab.lib.enums import TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def _paras(body: str) -> list[str]:
    return [p.strip() for p in body.replace("\r", "").split("\n\n") if p.strip()]


def _today(city: str) -> str:
    return f"{city}, {date.today():%d.%m.%Y}"


def build_docx(path: Path, sender: dict, recipient: dict, subject: str, body: str) -> Path:
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin, sec.bottom_margin, sec.left_margin, sec.right_margin = Cm(2), Cm(2), Cm(2.5), Cm(2)
    style = doc.styles["Normal"]
    style.font.name, style.font.size = "Calibri", Pt(11)

    p = doc.add_paragraph()
    p.add_run(sender["name"]).bold = True
    p.add_run(f"\n{sender['city']}\n{sender['email']}\n{sender['phone']}")
    doc.add_paragraph()
    doc.add_paragraph(f"{recipient['company']}\n{recipient.get('department', 'Personalabteilung')}\n{recipient['city']}")
    d = doc.add_paragraph(_today(sender["city"]))
    d.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    s = doc.add_paragraph()
    s.add_run(subject).bold = True
    for para in _paras(body):
        bp = doc.add_paragraph(para)
        bp.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        bp.paragraph_format.space_after = Pt(8)
    doc.save(path)
    return path


def _clean(t: str) -> str:
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
    return t.encode("cp1252", errors="replace").decode("cp1252")


def build_pdf(path: Path, sender: dict, recipient: dict, subject: str, body: str) -> Path:
    base = ParagraphStyle("b", fontName="Helvetica", fontSize=11, leading=15)
    just = ParagraphStyle("j", parent=base, alignment=TA_JUSTIFY, spaceAfter=8)
    right = ParagraphStyle("r", parent=base, alignment=TA_RIGHT)
    bold = ParagraphStyle("s", parent=base, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=12)
    story = [
        Paragraph(f"<b>{_clean(sender['name'])}</b><br/>{_clean(sender['city'])}<br/>{_clean(sender['email'])}<br/>{_clean(sender['phone'])}", base),
        Spacer(1, 0.8 * cm),
        Paragraph(f"{_clean(recipient['company'])}<br/>{_clean(recipient.get('department', 'Personalabteilung'))}<br/>{_clean(recipient['city'])}", base),
        Spacer(1, 0.6 * cm),
        Paragraph(_clean(_today(sender["city"])), right),
        Paragraph(_clean(subject), bold),
    ] + [Paragraph(_clean(p), just) for p in _paras(body)]
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=2.5 * cm, rightMargin=2 * cm,
                      topMargin=2 * cm, bottomMargin=2 * cm, title=subject, author=sender["name"]).build(story)
    return path
