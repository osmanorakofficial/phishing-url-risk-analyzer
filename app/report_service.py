from io import BytesIO
from datetime import datetime
import os
from reportlab.platypus import Image
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from report_formatter import format_report_dictionary
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def create_csv_report(url, risk_result, model_result, html_features, network_features, intelligence_features):
    data = {
        "analyzed_url": url,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "final_score": risk_result["final_score"],
        "risk_level": risk_result["risk_level"],
        "decision": risk_result["decision"],
        "confidence": risk_result["confidence"],
        "model_phishing_probability": model_result["phishing_probability"],
        "model_safe_probability": model_result["safe_probability"],
        "risk_reasons": " | ".join(risk_result.get("risk_reasons", [])),
        "safe_reasons": " | ".join(risk_result.get("safe_reasons", [])),
        **html_features,
        **network_features,
        **{
            "registered_domain": intelligence_features.get("registered_domain"),
            "domain_entropy": intelligence_features.get("domain_entropy"),
            "random_domain_risk": intelligence_features.get("random_domain_risk"),
            "suspicious_keyword_count": intelligence_features.get("suspicious_keyword_count"),
            "suspicious_tld": intelligence_features.get("suspicious_tld"),
            "brand_impersonation": intelligence_features.get("brand_impersonation"),
            "typo_squatting": intelligence_features.get("typo_squatting"),
            "matched_brand": intelligence_features.get("matched_brand"),
            "brand_similarity_score": intelligence_features.get("brand_similarity_score"),
            "intelligence_score": intelligence_features.get("intelligence_score"),
            "intelligence_reasons": " | ".join(intelligence_features.get("intelligence_reasons", [])),
            "intelligence_safe_reasons": " | ".join(intelligence_features.get("intelligence_safe_reasons", []))
        }
    }

    df = pd.DataFrame([data])
    return df.to_csv(index=False).encode("utf-8-sig")


def get_risk_color(risk_level):
    if risk_level == "Dusuk Risk":
        return colors.HexColor("#16A34A")
    if risk_level == "Orta Risk":
        return colors.HexColor("#CA8A04")
    if risk_level == "Yuksek Risk":
        return colors.HexColor("#EA580C")
    return colors.HexColor("#DC2626")


def build_key_value_table(data, normal_style):
    table_data = [
        [
            Paragraph("<b>Metric</b>", normal_style),
            Paragraph("<b>Value</b>", normal_style)
        ]
    ]

    for key, value in data.items():
        table_data.append([
            Paragraph(str(key), normal_style),
            Paragraph(str(value), normal_style)
        ])

    table = Table(table_data, colWidths=[6 * cm, 10 * cm])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    return table


def create_pdf_report(url, risk_result, model_result, html_features, network_features, intelligence_features):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=14
    )

    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155")
    )

    story = []

    risk_color = get_risk_color(risk_result["risk_level"])


    logo_path = os.path.join("assets", "logo.png")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header_left = []
    header_right = [
        Paragraph("<b>Generated by:</b> SiberTechAi", normal_style),
        Paragraph("<b>Website:</b> https://sibertechai.com", normal_style),
        Paragraph(f"<b>Analyzed URL:</b> {url}", normal_style),
        Paragraph(f"<b>Generated At:</b> {generated_at}", normal_style),
    ]

    if os.path.exists(logo_path):
        header_left.append(Image(logo_path, width=2.0 * cm, height=2.0 * cm))
    else:
        header_left.append(Paragraph("SiberTechAi", normal_style))

    header_table = Table(
        [[header_left, header_right]],
        colWidths=[10 * cm, 6 * cm]
    )

    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(header_table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Phishing URL Risk Analysis Report", title_style))
    story.append(Spacer(1, 12))

    summary_data = [
        ["Final Risk Score", "Risk Level", "Decision", "AI Confidence"],
        [
            f"{risk_result['final_score']:.2f}/100",
            risk_result["risk_level"],
            risk_result["decision"],
            f"{risk_result['confidence']}%"
        ]
    ]

    summary_table = Table(summary_data, colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
        ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Executive Summary", section_style))
    story.append(Paragraph(
        "This report summarizes the phishing risk assessment generated by combining machine learning, "
        "HTML inspection, SSL/DNS/WHOIS checks, and URL intelligence signals.",
        normal_style
    ))

    story.append(Paragraph("Risk Reasons", section_style))

    risk_reasons = risk_result.get("risk_reasons", [])
    if risk_reasons:
        for reason in risk_reasons:
            story.append(Paragraph(f"• {reason}", normal_style))
    else:
        story.append(Paragraph("No strong risk indicator was detected.", normal_style))

    story.append(Paragraph("Safe Signals", section_style))

    safe_reasons = risk_result.get("safe_reasons", [])
    if safe_reasons:
        for reason in safe_reasons:
            story.append(Paragraph(f"• {reason}", normal_style))
    else:
        story.append(Paragraph("No additional safe signal was detected.", normal_style))

    story.append(Paragraph("HTML Analysis", section_style))
    story.append(build_key_value_table(format_report_dictionary(html_features), normal_style))

    story.append(Paragraph("Network Analysis", section_style))
    story.append(build_key_value_table(format_report_dictionary(network_features), normal_style))

    intelligence_table = intelligence_features.copy()
    intelligence_table["intelligence_reasons"] = " | ".join(
        intelligence_table.get("intelligence_reasons", [])
    )
    intelligence_table["intelligence_safe_reasons"] = " | ".join(
        intelligence_table.get("intelligence_safe_reasons", [])
    )

    story.append(Paragraph("Intelligence Analysis", section_style))
    story.append(build_key_value_table(format_report_dictionary(intelligence_table), normal_style))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Disclaimer", section_style))
    story.append(Paragraph(
        "This tool provides automated risk assessment support. It does not guarantee absolute security. "
        "Suspicious URLs should also be verified using independent security sources.",
        normal_style
    ))

    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))

        footer_text = (
            "SiberTechAi | https://sibertechai.com | "
            "This report is an automated risk assessment and does not guarantee absolute security."
        )

        canvas.drawString(1.5 * cm, 1 * cm, footer_text)
        canvas.drawRightString(19.5 * cm, 1 * cm, f"Page {doc.page}")

        canvas.restoreState()


    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    buffer.seek(0)

    return buffer.getvalue()