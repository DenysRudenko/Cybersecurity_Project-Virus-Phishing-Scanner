from django.shortcuts import render
import os
import hashlib

def home(request):
    result = None
    uploaded_file_name = None
    scanned_url = None

    if request.method == 'POST':
        # Handle file upload
        if 'file' in request.FILES:
            file = request.FILES['file']
            uploaded_file_name = file.name
            file_path = f"scanner/uploads/{file.name}"

            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            # Generate a fake scan result (for now)
            result = f"File '{file.name}' uploaded and saved."
            result += f" SHA256: {hashlib.sha256(file.read()).hexdigest()}"

        # Handle URL input
        elif 'url' in request.POST:
            scanned_url = request.POST['url']
            # Here you'd call phishing detection APIs or tools
            result = f"Scanned URL: {scanned_url} (fake check: clean ✅)"

    return render(request, 'scanner/index.html', {
        'result': result,
        'file': uploaded_file_name,
        'url': scanned_url
    })
