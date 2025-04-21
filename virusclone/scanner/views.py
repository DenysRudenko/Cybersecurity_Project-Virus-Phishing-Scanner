from django.shortcuts import render
import os
import hashlib
import subprocess
import time
import requests
from django.conf import settings

UPLOAD_DIR = os.path.join(settings.BASE_DIR, 'scanner/uploads')

def home(request):
    result = None
    uploaded_file_name = None
    scanned_url = None

    if request.method == 'POST':
        if 'file' in request.FILES and request.FILES['file'].name:
            file = request.FILES['file']
            uploaded_file_name = file.name
            file_path = os.path.join(UPLOAD_DIR, file.name)

            os.makedirs(UPLOAD_DIR, exist_ok=True)

            # Save uploaded file
            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            time.sleep(0.2)  # Ensure OS finishes writing

            # Read file for hash
            with open(file_path, 'rb') as f:
                file_bytes = f.read()
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()

            # Scan using ClamAV
            scan = subprocess.run(
                [settings.CLAMAV_PATH, uploaded_file_name],
                cwd=UPLOAD_DIR,
                capture_output=True,
                text=True
            )

            clamav_output = scan.stdout
            infected = "Infected files: 0" not in clamav_output

            result = {
                'filename': uploaded_file_name,
                'sha256': sha256_hash,
                'scan_output': clamav_output,
                'infected': infected,
            }

        elif 'url' in request.POST:
            scanned_url = request.POST['url']
            api_key = settings.VIRUSTOTAL_API_KEY
            vt_url = "https://www.virustotal.com/api/v3/urls"
            print("📡 URL RECEIVED:", scanned_url)

            

            # Encode URL for submission
            headers = {
                "x-apikey": api_key
            }

            # Step 1: Submit the URL to VirusTotal
            scan_response = requests.post(vt_url, headers=headers, data={"url": scanned_url})
            if scan_response.status_code == 200:
                scan_id = scan_response.json()['data']['id']

                # Step 2: Retrieve analysis report
                report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
                analysis = requests.get(report_url, headers=headers).json()

                stats = analysis['data']['attributes']['stats']
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)

                if malicious_count > 0:
                    verdict = f"❌ URL flagged as **malicious** by {malicious_count} engines."
                elif suspicious_count > 0:
                    verdict = f"⚠️ URL flagged as **suspicious** by {suspicious_count} engines."
                else:
                    verdict = "✅ URL appears **clean** based on VirusTotal analysis."

                result = {
                    'url': scanned_url,
                    'scan_output': verdict,
                    'infected': malicious_count > 0
                }

            else:
                result = {
                    'url': scanned_url,
                    'scan_output': f"❌ Failed to scan URL (status {scan_response.status_code})"
                }



    return render(request, 'scanner/index.html', {
        'result': result,
    })
