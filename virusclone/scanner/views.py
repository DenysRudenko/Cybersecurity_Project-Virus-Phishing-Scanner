# Built-in & external modules
import os
import time
import hashlib
import subprocess
import requests
import json
import logging
import urllib.parse

# Django modules
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.utils import timezone

# Project-specific imports
from .forms import RegisterForm
from .models import Scan

# Path for temporary file storage
UPLOAD_DIR = os.path.join(settings.BASE_DIR, 'scanner/uploads')

# --------------------------
# User Registration View
# --------------------------
def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()  # Create user, but don’t auto-login
            return redirect("login")  # Send to login page
    else:
        form = RegisterForm()
    return render(request, "scanner/register.html", {"form": form})


# --------------------------
# Dashboard View
# --------------------------
@login_required
def dashboard(request):
    scans = Scan.objects.filter(user=request.user).order_by('-timestamp')
    total = scans.count()
    threats = scans.exclude(result='Clean').count()
    last = timezone.now() - scans.first().timestamp if total > 0 else None

    stats = {
        "total_scans": total,
        "threats_found": threats,
        "last_scan": f"{int(last.total_seconds() / 60)} mins ago" if last else "N/A",
    }

    return render(request, "scanner/dashboard.html", {
        "scan_history": scans,
        "stats": stats,
    })


# --------------------------
# Homepage
# --------------------------
def home(request):
    return render(request, 'scanner/index.html')


# --------------------------
# VirusTotal Integration
# --------------------------
def scan_with_virustotal(url):
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        # Submit the URL for scanning
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        response.raise_for_status()
        scan_id = response.json()['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

        # Wait for scan to finish
        for _ in range(10):
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()['data']
            status = analysis_data.get('attributes', {}).get('status')
            if status == 'completed':
                break
            time.sleep(2)

        stats = analysis_data['attributes']['stats']
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)

        if malicious_count > 0:
            return f"URL flagged as **malicious** by {malicious_count} engines.", True
        elif suspicious_count > 0:
            return f"URL flagged as **suspicious** by {suspicious_count} engines.", True
        else:
            return "URL appears **clean** based on VirusTotal analysis.", False

    except requests.RequestException as e:
        return f"Error contacting VirusTotal: {e}", False


# --------------------------
# URLScan.io Integration
# --------------------------
def get_urlscan_data(url):
    headers = {
        'API-Key': settings.URL_SCAN_KEY,
        'Content-Type': 'application/json'
    }
    payload = {'url': url, 'public': 'on'}

    try:
        # Send scan request to URLScan.io
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        uuid = data.get('uuid')
        time.sleep(15)  # Give time for scan to generate results
        return (
            f'https://urlscan.io/screenshots/{uuid}.png',
            f'https://urlscan.io/result/{uuid}/'
        )
    except requests.RequestException:
        return None, None


# --------------------------
# Google Safe Browsing API
# --------------------------
def check_google_safebrowsing(api_key, url):
    if not url or not isinstance(url, str):
        return False, "Invalid URL input."

    try:
        body = {
            "client": {
                "clientId": "cybersentinel",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            headers=headers,
            data=json.dumps(body)
        )
        response.raise_for_status()

        result = response.json()
        logging.debug(f"Safe Browsing raw response for {url}:\n{json.dumps(result, indent=2)}")

        if "matches" in result:
            threats = [f"{m['threatType']} on {m['platformType']}" for m in result['matches']]
            return True, "; ".join(threats)
        return False, "No threats found."

    except requests.HTTPError as e:
        return False, f"HTTP error: {e.response.status_code} - {e.response.text}"
    except requests.RequestException as e:
        return False, f"Request error: {str(e)}"
    except Exception as ex:
        return False, f"Unexpected error: {str(ex)}"


# --------------------------
# Save Scan to Database
# --------------------------
def save_scan_record(user, url, result_type):
    Scan.objects.create(
        user=user,
        type='URL',
        item=url,
        result=result_type,
        timestamp=timezone.now()
    )


# --------------------------
# URL Scanner View
# --------------------------
@login_required
def url_scanner(request):
    result = None

    if request.method == 'POST':
        scanned_url = request.POST.get('url')

        # Run VirusTotal
        vt_verdict, vt_infected = scan_with_virustotal(scanned_url)

        # Run URLScan.io
        screenshot_url, full_report_url = get_urlscan_data(scanned_url)

        # Run Google Safe Browsing
        sb_flag, sb_details = check_google_safebrowsing(settings.GOOGLE_SAFE_API, scanned_url)

        # Pick the verdict
        if vt_infected:
            result_type = 'Phishing'
        elif sb_flag:
            result_type = 'Suspicious (Google)'
        else:
            result_type = 'Clean'

        # Save result in DB
        if request.user.is_authenticated:
            save_scan_record(request.user, scanned_url, result_type)

        # Display warning if VirusTotal finds issue but Google doesn’t
        warning_message = ""
        if vt_infected and not sb_flag:
            warning_message = (
                "VirusTotal is our primary threat detection source. "
                "Please treat the URL as potentially dangerous, even if Google Safe Browsing shows no threat."
            )

        result = {
            'url': scanned_url,
            'scan_output': vt_verdict,
            'infected': vt_infected,
            'screenshot_url': screenshot_url,
            'full_report_url': full_report_url,
            'google_sb_flag': sb_flag,
            'google_sb_details': sb_details,
            'warning_message': warning_message
        }

    return render(request, 'scanner/url_scanner.html', {"result": result})


# --------------------------
# File Scanner (ClamAV)
# --------------------------
@login_required
def file_scanner(request):
    result = None

    if request.method == 'POST' and 'file' in request.FILES:
        file = request.FILES['file']
        uploaded_file_name = file.name
        file_path = os.path.join(UPLOAD_DIR, uploaded_file_name)

        # Save uploaded file to disk
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(file_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        time.sleep(0.2)  # Prevent race condition on read

        # Calculate SHA-256 hash
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # Scan file using ClamAV
        scan = subprocess.run(
            [settings.CLAMAV_PATH, uploaded_file_name],
            cwd=UPLOAD_DIR,
            capture_output=True,
            text=True
        )

        clamav_output = scan.stdout
        infected = "Infected files: 0" not in clamav_output
        result_type = 'Malware' if infected else 'Clean'

        # Save scan result to DB
        Scan.objects.create(
            user=request.user,
            type='File',
            item=uploaded_file_name,
            result=result_type,
            timestamp=timezone.now()
        )

        # Remove uploaded file after scanning
        os.remove(file_path)

        result = {
            'filename': uploaded_file_name,
            'sha256': sha256_hash,
            'scan_output': clamav_output,
            'infected': infected,
        }

    return render(request, 'scanner/file_scanner.html', {'result': result})
