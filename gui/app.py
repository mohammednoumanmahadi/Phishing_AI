import sys
import os

# Add project root (Phishing_AI) to Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from core.email_analyzer import analyze_eml
from core.whois_lookup import get_whois
from core.threat_intel import reputation_score
from core.risk_engine import calculate_risk
from core.llm_report import generate_report
from core.pdf_report import generate_pdf
import os

REPORT_DIR = os.path.join(os.path.dirname(__file__), "../data/reports")
os.makedirs(REPORT_DIR, exist_ok=True)

def browse_email():
    file_path = filedialog.askopenfilename(filetypes=[("EML files", "*.eml")])
    if file_path:
        process_email(file_path)

def process_email(file_path):
    try:
        # Step 1: Analyze email
        email_result = analyze_eml(file_path)

        # Step 2: WHOIS info
        whois_result = get_whois(email_result["from_domain"])

        # Step 3: Threat intel scoring
        ip_score = reputation_score(email_result["sender_ip"])
        domain_score = reputation_score(email_result["from_domain"])
        url_scores = sum(reputation_score(u) for u in email_result["links"])
        attachment_scores = sum(reputation_score(a["sha256"]) for a in email_result["attachments"])

        total_score = ip_score + domain_score + url_scores + attachment_scores
        risk_level = calculate_risk([ip_score, domain_score, url_scores, attachment_scores])

        # Step 4: Prepare context for LLM
        context = {
            "email": email_result,
            "whois": whois_result,
            "threat_intel": {
                "ip_score": ip_score,
                "domain_score": domain_score,
                "url_scores": url_scores,
                "attachment_scores": attachment_scores,
                "risk_level": risk_level
            }
        }

        # Step 5: Generate LLM report
        llm_text = generate_report(context)

        # Step 6: Generate PDF
        pdf_file = os.path.join(REPORT_DIR, f"{email_result['file']}_report.pdf")
        generate_pdf(llm_text, pdf_file)

        # Step 7: Display in GUI
        display_result(email_result, whois_result, risk_level, llm_text, pdf_file)

        messagebox.showinfo("✅ Success", f"Report generated and saved:\n{pdf_file}")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def display_result(email_result, whois_result, risk_level, llm_text, pdf_file):
    txt_output.config(state="normal")
    txt_output.delete(1.0, tk.END)

    txt_output.insert(tk.END, f"File: {email_result['file']}\n")
    txt_output.insert(tk.END, f"Subject: {email_result['subject']}\n")
    txt_output.insert(tk.END, f"From: {email_result['from_email']}\n")
    txt_output.insert(tk.END, f"Domain: {email_result['from_domain']}\n")
    txt_output.insert(tk.END, f"Return-Path: {email_result['return_path']}\n")
    txt_output.insert(tk.END, f"Sender IP: {email_result['sender_ip']}\n")
    txt_output.insert(tk.END, f"Risk Level: {risk_level}\n\n")

    txt_output.insert(tk.END, "--- WHOIS ---\n")
    for k, v in whois_result.items():
        txt_output.insert(tk.END, f"{k}: {v}\n")

    txt_output.insert(tk.END, "\n--- Links ---\n")
    for link in email_result["links"]:
        txt_output.insert(tk.END, f"{link}\n")

    txt_output.insert(tk.END, "\n--- Attachments ---\n")
    for att in email_result["attachments"]:
        txt_output.insert(tk.END, f"{att['filename']} | SHA256: {att['sha256']}\n")

    txt_output.insert(tk.END, "\n--- Body Preview ---\n")
    txt_output.insert(tk.END, email_result["body"][:1000] + "\n")

    txt_output.insert(tk.END, "\n--- LLM Summary / Recommendations ---\n")
    txt_output.insert(tk.END, llm_text[:2000] + "\n")  # show first 2000 chars

    txt_output.insert(tk.END, f"\nFull PDF saved at:\n{pdf_file}\n")
    txt_output.config(state="disabled")

# GUI setup
root = tk.Tk()
root.title("AI Phishing Email Analyzer")

btn_browse = tk.Button(root, text="Browse EML & Analyze", command=browse_email, bg="blue", fg="white")
btn_browse.pack(pady=10)

txt_output = scrolledtext.ScrolledText(root, width=120, height=40, state="disabled")
txt_output.pack(padx=10, pady=10)

root.mainloop()
