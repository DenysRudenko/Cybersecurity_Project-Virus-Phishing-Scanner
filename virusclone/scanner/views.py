from django.shortcuts import render
import os
import hashlib
import subprocess
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

            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            scan = subprocess.run(
                [settings.CLAMAV_PATH, file_path],
                capture_output=True,
                text=True
            )
            clamav_output = scan.stdout

            with open(file_path, 'rb') as f:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()

            result = {
                'filename': uploaded_file_name,
                'sha256': sha256_hash,
                'scan_output': clamav_output,
            }

        elif 'url' in request.POST:
            scanned_url = request.POST['url']
            result = {
                'url': scanned_url,
                'scan_output': "This is a placeholder result. Real URL scanning coming soon! ✅"
            }

    # ✅ Always return an HttpResponse object (even for GET requests)
    return render(request, 'scanner/index.html', {
        'result': result,
    })
