import requests
import re
from bs4 import BeautifulSoup
import webbrowser
import tkinter as tk
from tkinter import ttk
from urllib.parse import urljoin

def scan_website(url):
    found_urls = fetch_urls(url)
    found_vulnerabilities = []

    for page_url in found_urls:
        issues = check_vulnerabilities(page_url)
        if issues:
            found_vulnerabilities.append((page_url, issues))

    return found_vulnerabilities

def fetch_urls(base_url):
    urls = []

    response = requests.get(base_url, allow_redirects=False)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a"):
            href = tag.get("href")
            if href:
                full_url = urljoin(base_url, href)
                urls.append(full_url)

    return urls

def check_vulnerabilities(url):
    issues = {}

    if check_sql_injection(url):
        issues["SQL Injection"] = "Possible SQL injection point detected"

    if check_xss(url):
        issues["XSS"] = "Possible XSS vulnerability detected"

    return issues

def check_sql_injection(url):
    test_payload = "' OR '1'='1"
    response = requests.get(url + "?id=" + test_payload, allow_redirects=False)
    if re.search(r"error|warning", response.text, re.IGNORECASE):
        return True
    return False

def check_xss(url):
    test_payload = "<script>alert('XSS')</script>"
    response = requests.get(url + "?input=" + test_payload, allow_redirects=False)
    if test_payload in response.text:
        return True
    return False

def initiate_scan():
    target_url = url_input.get()
    results_display.delete("1.0", tk.END)

    found_issues = scan_website(target_url)
    if found_issues:
        results_display.insert(tk.END, "Vulnerabilities discovered:\n")
        for page_url, issues in found_issues:
            results_display.insert(tk.END, f"\nURL: {page_url}\n")
            for issue, description in issues.items():
                results_display.insert(tk.END, f"{issue}: {description}\n")
    else:
        results_display.insert(tk.END, "No vulnerabilities found.")

app = tk.Tk()
app.title("Vulnerability Scanner")

frame = ttk.Frame(app, padding="10")
frame.grid(column=0, row=0)

url_label = ttk.Label(frame, text="Enter URL:")
url_label.grid(column=0, row=0, sticky=tk.W)

url_input = ttk.Entry(frame, width=40)
url_input.grid(column=1, row=0, sticky=tk.E)

scan_button = ttk.Button(frame, text="Start Scan", command=initiate_scan)
scan_button.grid(column=2, row=0)

results_display = tk.Text(frame, height=20, width=80, font=("Courier", 12))
results_display.grid(column=0, row=1, columnspan=3)

app.mainloop()
