"""Structured engagement report model with independent JSON/TXT/PDF renderers."""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.redact import redact_data, redact_text, literal_text

LABELS = {
    "en": {"brand": "KRIPTO / SECURITY ASSESSMENT", "executive": "Executive report",
           "technical": "Technical report", "target": "Target", "engagement": "Engagement",
           "client": "Client", "assessor": "Assessor", "generated": "Generated (UTC)",
           "summary": "Executive summary", "risk": "Risk distribution", "findings": "Findings",
           "limitations": "Limitations and incomplete checks", "configuration": "Scan configuration",
           "severity": "Severity", "confidence": "Verification / confidence", "status": "Lifecycle",
           "cvss": "CVSS", "mapping": "CWE / OWASP", "evidence": "Evidence",
           "recipe": "Reproduction steps", "remediation": "Remediation", "history": "History",
           "fingerprint": "SHA-256 fingerprint", "affected": "Affected endpoint",
           "none": "No reportable findings were observed. This does not establish that the target is secure.",
           "count": "Reportable findings", "decision": "Prioritize confirmed findings by severity; validate candidates before remediation decisions."},
    "ar": {"brand": "KRIPTO / تقييم أمن التطبيقات", "executive": "التقرير التنفيذي",
           "technical": "التقرير الفني", "target": "الهدف", "engagement": "مهمة التقييم",
           "client": "العميل", "assessor": "المقيّم", "generated": "وقت الإنشاء (UTC)",
           "summary": "الملخص التنفيذي", "risk": "توزيع المخاطر", "findings": "النتائج",
           "limitations": "القيود والفحوصات غير المكتملة", "configuration": "إعدادات الفحص",
           "severity": "الخطورة", "confidence": "التحقق ومستوى الثقة", "status": "حالة المتابعة",
           "cvss": "درجة CVSS", "mapping": "تصنيف CWE و OWASP", "evidence": "الأدلة",
           "recipe": "خطوات إعادة الإنتاج", "remediation": "توصيات المعالجة", "history": "سجل المتابعة",
           "fingerprint": "بصمة SHA-256", "affected": "نقطة الوصول المتأثرة",
           "none": "لم تُرصد نتائج قابلة للإبلاغ. لا تعني هذه النتيجة أن الهدف آمن.",
           "count": "عدد النتائج", "decision": "ابدأ بالنتائج المؤكدة حسب الخطورة، وتحقق من النتائج المرشحة قبل اتخاذ قرارات المعالجة."},
}


@dataclass
class ReportModel:
    target: str
    language: str
    engagement: dict
    configuration: dict
    findings: list
    limitations: list
    risk_distribution: dict
    generated_at: str
    scan_id: str = ""
    schema_version: int = 1

    @classmethod
    def build(cls, target, results, language="en", engagement=None):
        if language not in LABELS:
            raise ValueError("report language must be en or ar")
        findings = redact_data(results.get("findings") or [])
        limitations = []
        notes = results.get("module_notes") or {}
        for name, state in (results.get("module_health") or {}).items():
            if state != "OK":
                limitations.append(f"{name}: {state}. {notes.get(name, '')}")
        for group in (results.get("extended") or {}).values():
            limitations.extend(group.get("limitations") or [])
        for item in findings:
            if item.get("evidence_error"):
                limitations.append(f"{item.get('id', '')}: {item['evidence_error']}")
        if results.get("persistence_error"):
            limitations.append("Persistence: " + results["persistence_error"])
        if (results.get("runtime") or {}).get("budget_exhausted"):
            limitations.append("Run-wide request budget exhausted; remaining checks incomplete.")
        limitations.extend((results.get("recon") or {}).get("limitations") or [])
        limitations.extend(((results.get("protocol") or {}).get("websocket") or {}).get("limitations") or [])
        counts = Counter(str(item.get("severity") or "info").lower() for item in findings)
        risk = {severity: counts[severity] for severity in ("critical", "high", "medium", "low", "info")}
        return cls(redact_text(target), language, redact_data(engagement or results.get("engagement") or {}),
                   redact_data(results.get("settings") or {}), findings,
                   list(dict.fromkeys(redact_text(value) for value in limitations)), risk,
                   datetime.now(timezone.utc).isoformat(timespec="seconds"), str(results.get("scan_id") or ""))

    def sections(self, audience="technical"):
        labels = LABELS[self.language]
        title = labels[audience]
        header = [("title", title), ("text", f"{labels['target']}: {self.target}"),
                  ("text", f"{labels['generated']}: {self.generated_at}")]
        for key in ("engagement", "client", "assessor"):
            header.append(("text", f"{labels[key]}: {self.engagement.get(key, '-') }"))
        header += [("heading", labels["summary"]), ("text", f"{labels['count']}: {len(self.findings)}"),
                   ("text", labels["decision"] if self.findings else labels["none"]),
                   ("heading", labels["risk"])]
        header.extend(("text", f"{severity.upper()}: {count}") for severity, count in self.risk_distribution.items())
        if audience == "technical":
            header.append(("heading", labels["configuration"]))
            header.extend(("text", f"{key}: {json.dumps(value, ensure_ascii=False)}")
                          for key, value in self.configuration.items())
        header.append(("heading", labels["findings"]))
        for index, item in enumerate(self.findings, 1):
            header.append(("finding", f"{item.get('id', 'KRP-' + str(index))}: {item.get('title', '')}"))
            header.append(("text", f"{labels['severity']}: {item.get('severity', 'info')} | "
                                   f"{labels['confidence']}: {item.get('verification', 'POTENTIAL')} / {item.get('confidence', '-')}"))
            header.append(("text", f"{labels['affected']}: {item.get('method', 'GET')} {item.get('target', self.target)}"))
            header.append(("text", f"{labels['status']}: {item.get('status', 'candidate')}"))
            header.append(("text", f"{labels['remediation']}: {item.get('remediation') or item.get('fix') or 'Review the affected control, implement the relevant CWE guidance and retest.'}"))
            if audience == "technical":
                header.extend([("text", f"{labels['cvss']}: {item.get('cvss_score', 'unmapped')} {item.get('cvss_vector', '')}"),
                               ("text", f"{labels['mapping']}: {item.get('cwe', 'unmapped')} / {item.get('owasp', 'unmapped')}"),
                               ("text", f"{labels['fingerprint']}: {item.get('fingerprint', '')}"),
                               ("text", f"{labels['evidence']}: {item.get('evidence', '')}")])
                for reference in item.get("evidence_refs") or []:
                    header.append(("text", f"Evidence SHA-256: {reference['sha256']} / {reference['size']} bytes"))
                header.append(("heading", labels["recipe"]))
                steps = item.get("reproduction") or item.get("reproduce") or item.get("reproduction_steps") or []
                if isinstance(steps, str):
                    steps = [steps]
                header.extend(("text", step) for step in steps)
                for event in item.get("status_history") or []:
                    header.append(("text", f"{labels['history']}: {event.get('at')} {event.get('from')} -> "
                                           f"{event.get('to')} ({event.get('reason')})"))
        header.append(("heading", labels["limitations"]))
        header.extend(("text", value) for value in self.limitations)
        return header


class JsonRenderer:
    def render(self, model, path, audience=None):
        Path(path).write_text(json.dumps(asdict(model), ensure_ascii=False, indent=2), encoding="utf-8")


class TextRenderer:
    def render(self, model, path, audience="technical"):
        lines = []
        for kind, text in model.sections(audience):
            text = literal_text(text)
            if kind in {"title", "heading", "finding"}:
                lines.extend(["", text, "=" * min(78, max(10, len(text)))])
            else:
                lines.append(str(text))
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


class PdfRenderer:
    def __init__(self, font=None):
        self.font = font

    @staticmethod
    def shape(text):
        if re.search(r"[\u0600-\u06ff]", str(text)):
            import arabic_reshaper
            from bidi.algorithm import get_display
            return get_display(arabic_reshaper.reshape(str(text)))
        return str(text)

    def render(self, model, path, audience="technical"):
        try:
            from reportlab.pdfgen import canvas
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            from reportlab.lib.pagesizes import A4
        except ImportError as exc:
            raise RuntimeError("PDF reporting requires the 'reports' project extra") from exc
        candidates = [self.font, os.environ.get("KRIPTO_REPORT_FONT"),
                      "C:/Windows/Fonts/arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
        font = next((item for item in candidates if item and Path(item).is_file()), None)
        if not font:
            raise RuntimeError("No Unicode reporting font available; pass --report-font")
        font_name = "KriptoReport"
        pdfmetrics.registerFont(TTFont(font_name, font))
        
        if model.language == "ar":
            self.shape("اختبار اللغة العربية")
        width, height = A4
        output = canvas.Canvas(str(path), pagesize=A4)
        output.setTitle(LABELS[model.language][audience])
        output.setAuthor("Kripto")
        y, page = height - 94, 1
        def frame():
            output.setFillColorRGB(.07, .15, .24)
            output.rect(0, height - 58, width, 58, fill=1, stroke=0)
            output.setFillColorRGB(1, 1, 1)
            output.setFont(font_name, 12)
            output.drawString(42, height - 36, self.shape(LABELS[model.language]["brand"]))
            output.setFillColorRGB(.42, .47, .52)
            output.setFont(font_name, 8)
            output.drawString(42, 25, "KRIPTO / " + audience.upper())
            output.drawRightString(width - 42, 25, str(page))
        def new_page():
            nonlocal y, page
            output.showPage(); page += 1; y = height - 94; frame()
        def wrap(text, size):
            
            
            lines, current = [], ""
            for word in str(text).split():
                candidate = (current + " " + word).strip()
                if pdfmetrics.stringWidth(self.shape(candidate), font_name, size) <= width - 84:
                    current = candidate
                    continue
                if current:
                    lines.append(current); current = ""
                
                piece = ""
                for character in word:
                    if pdfmetrics.stringWidth(self.shape(piece + character), font_name, size) > width - 84:
                        lines.append(piece); piece = ""
                    piece += character
                current = piece
            if current:
                lines.append(current)
            return lines or [""]
        frame()
        for kind, text in model.sections(audience):
            text = literal_text(text)
            size = 19 if kind == "title" else 12 if kind in {"heading", "finding"} else 9.5
            lines = wrap(text, size)
            if kind != "text":
                y -= 12
            if y - min(len(lines), 4) * (size + 5) < 55:
                new_page()
            output.setFillColorRGB(.08, .20, .30) if kind != "text" else output.setFillColorRGB(.16, .18, .21)
            for line in lines:
                if y < 55:
                    new_page()
                output.setFont(font_name, size)
                output.setFillColorRGB(.08, .20, .30) if kind != "text" else output.setFillColorRGB(.16, .18, .21)
                visual = self.shape(line)
                if model.language == "ar" and re.search(r"[\u0600-\u06ff]", line):
                    output.drawRightString(width - 42, y, visual)
                else:
                    output.drawString(42, y, visual)
                y -= size + 5
        output.save()


class ReportService:
    def generate(self, target, results, prefix, formats=("txt", "json"), language="en", font=None, engagement=None):
        if set(formats) - {"txt", "json", "pdf"}:
            raise ValueError("unsupported report format")
        model = ReportModel.build(target, results, language, engagement)
        outputs = []
        if "json" in formats:
            path = str(prefix) + "_structured.json"
            JsonRenderer().render(model, path); outputs.append(path)
        for audience in ("executive", "technical"):
            for extension, renderer in (("txt", TextRenderer()), ("pdf", PdfRenderer(font))):
                if extension in formats:
                    path = f"{prefix}_{audience}.{extension}"
                    renderer.render(model, path, audience); outputs.append(path)
        return outputs
