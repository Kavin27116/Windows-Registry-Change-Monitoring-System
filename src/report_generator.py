import json
import os
import sys
from datetime import datetime

# using reportlab for PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

# Import paths from config
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)

from config import REPORTS_DIR, REPORT_PDF, REPORT_TXT

def load_session_events():
    events_file = os.path.join(REPORTS_DIR, "session_events.json")
    if not os.path.exists(events_file):
        return {}
    with open(events_file, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_text_report(session):
    events = session.get("events", [])
    lines = []
    
    lines.append("======================================================================")
    lines.append("  WINDOWS REGISTRY MONITORING SYSTEM - REPORT")
    lines.append("======================================================================")
    lines.append(f"Session Start: {session.get('session_start', '')[:19].replace('T', ' ')}")
    lines.append(f"Session End: {session.get('session_end', '')[:19].replace('T', ' ')}")
    lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("----------------------------------------------------------------------")
    lines.append(f"Total Scans: {session.get('total_scans', 0)}")
    lines.append(f"Total Changes: {session.get('total_changes', 0)}")
    lines.append(f"  New Entries: {session.get('new_entries', 0)}")
    lines.append(f"  Modified: {session.get('modified_entries', 0)}")
    lines.append(f"  Deleted: {session.get('deleted_entries', 0)}")
    lines.append(f"Malware Alerts: {session.get('malware_alerts', 0)}")
    lines.append(f"Critical Alerts: {session.get('critical_alerts', 0)}")
    lines.append("======================================================================")

    if not events:
        lines.append("\nNo changes were found during this session.")
        return "\n".join(lines)

    lines.append(f"\nEVENT LOG ({len(events)} events):")
    lines.append("----------------------------------------------------------------------")

    for i, ev in enumerate(events, 1):
        lines.append(f"\nEvent {i}:")
        lines.append(f"  Time: {ev.get('timestamp', '')[:19].replace('T', ' ')}")
        lines.append(f"  Type: {ev.get('change_type', '')}")
        lines.append(f"  Path: {ev.get('key_path', '')}")
        lines.append(f"  Name: {ev.get('value_name', '')}")
        
        if ev.get("old_value"):
            lines.append(f"  Old Value: {ev['old_value']}")
        if ev.get("new_value"):
            lines.append(f"  New Value: {ev['new_value']}")

        for pm in ev.get("patterns", []):
            lines.append(f"\n  *** MALWARE PATTERN MATCH: {pm.get('severity', '')} ***")
            lines.append(f"  Category: {pm.get('category', '')}")
            lines.append(f"  Technique: {pm.get('technique', '')} ({pm.get('technique_id', '')})")
            lines.append(f"  Description: {pm.get('description', '')}")
            lines.append(f"  Action: {pm.get('recommendation', '')}")

    lines.append("\n======================================================================")
    lines.append("END OF REPORT")
    return "\n".join(lines)


def generate_pdf_report(session, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    doc = SimpleDocTemplate(out_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("<b>Windows Registry Monitoring Report</b>", styles['Title']))
    story.append(Spacer(1, 20))

    # Summary
    start_time = session.get('session_start', '')[:19].replace('T', ' ')
    end_time = session.get('session_end', '')[:19].replace('T', ' ')
    
    story.append(Paragraph("<b>Session Summary</b>", styles['Heading2']))
    story.append(Paragraph(f"Start: {start_time}", styles['Normal']))
    story.append(Paragraph(f"End: {end_time}", styles['Normal']))
    story.append(Paragraph(f"Total Scans: {session.get('total_scans', 0)}", styles['Normal']))
    story.append(Paragraph(f"Total Changes: {session.get('total_changes', 0)}", styles['Normal']))
    story.append(Spacer(1, 10))

    events = session.get("events", [])
    
    if not events:
        story.append(Paragraph("No changes were detected in the registry.", styles['Normal']))
    else:
        story.append(Paragraph("<b>Event Log</b>", styles['Heading2']))
        
        for idx, ev in enumerate(events, 1):
            ts = ev.get('timestamp', '')[:19].replace('T', ' ')
            ctype = ev.get('change_type', '')
            path = ev.get('key_path', '')
            name = ev.get('value_name', '')
            
            story.append(Paragraph(f"<b>Event {idx} - {ctype}</b>", styles['Heading3']))
            story.append(Paragraph(f"Time: {ts}", styles['Normal']))
            story.append(Paragraph(f"Path: {path}", styles['Normal']))
            story.append(Paragraph(f"Value Name: {name}", styles['Normal']))
            
            if ev.get("old_value"):
                story.append(Paragraph(f"Old Value: {ev['old_value']}", styles['Normal']))
            if ev.get("new_value"):
                story.append(Paragraph(f"New Value: {ev['new_value']}", styles['Normal']))

            for pm in ev.get("patterns", []):
                sev = pm.get('severity', '')
                story.append(Paragraph(f"<font color='red'><b>MALWARE PATTERN: {sev}</b></font>", styles['Normal']))
                story.append(Paragraph(f"Technique: {pm.get('technique', '')}", styles['Normal']))
                story.append(Paragraph(f"Description: {pm.get('description', '')}", styles['Normal']))

            story.append(Spacer(1, 15))

    # Build PDF
    try:
        doc.build(story)
    except Exception as e:
        print(f"Failed to generate PDF: {e}")

def generate_report():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    session = load_session_events()
    
    if not session:
        print("No session data found. Making a blank report.")
        session = {
            "session_start": datetime.now().isoformat(),
            "session_end": datetime.now().isoformat(),
            "total_scans": 0, "total_changes": 0,
            "events": []
        }

    # Text report
    txt_content = generate_text_report(session)
    with open(REPORT_TXT, "w", encoding="utf-8") as f:
        f.write(txt_content)
    print(f"Generated text report at {REPORT_TXT}")

    # PDF report
    generate_pdf_report(session, REPORT_PDF)
    print(f"Generated PDF report at {REPORT_PDF}")

if __name__ == "__main__":
    generate_report()
