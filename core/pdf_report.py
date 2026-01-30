from fpdf import FPDF
from datetime import datetime
import os

def generate_pdf(report_text: str, output_dir="reports") -> str:
    """
    Generates a PDF report from LLM analysis text
    """

    os.makedirs(output_dir, exist_ok=True)

    filename = f"Phishing_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join(output_dir, filename)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", size=11)

    for line in report_text.split("\n"):
        pdf.multi_cell(0, 8, line)

    pdf.output(file_path)
    return file_path
