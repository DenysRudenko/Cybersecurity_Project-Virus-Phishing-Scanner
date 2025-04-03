from django.shortcuts import render
import os
import hashlib
import subprocess
import time
from django.conf import settings

UPLOAD_DIR = os.path.join(settings.BASE_DIR, 'scanner/uploads')

def home(request):
    result = None
    uploaded_file_name = None
    scanned_url = None

    if request.method == 'POST':
        if 'file' in request.FILES:
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
            result = {
                'url': scanned_url,
                'scan_output': "This is a placeholder result. Real URL scanning coming soon! ✅"
            }

    return render(request, 'scanner/index.html', {
        'result': result,
    })
