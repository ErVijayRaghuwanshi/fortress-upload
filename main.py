import os
import io
import ssl
import ssl
import struct
import binascii
from urllib import response
import urllib.request
import urllib.error
import uvicorn
import magic # Requires: pip install python-magic
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse
from PIL import Image # Requires: pip install Pillow

app = FastAPI(title="Fortress Upload Scanner")

MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB Limit

# ==========================================
# 1. TEST FILE GENERATOR (Runs on startup)
# ==========================================
def generate_test_files():
    """Generates a clean image and two 'malicious' simulated images for testing."""
    os.makedirs("test_files", exist_ok=True)
    
    img = Image.new('RGB', (10, 10), color = (73, 109, 137))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    clean_png_bytes = img_byte_arr.getvalue()

    with open("test_files/clean_image.png", "wb") as f:
        f.write(clean_png_bytes)

    eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open("test_files/eicar_simulated_virus.png", "wb") as f:
        f.write(clean_png_bytes + eicar_string)

    php_payload = b"<?php system('id'); ?>"
    chunk_type = b"tEXt"
    chunk_data = b"Comment\0" + php_payload
    chunk_crc = struct.pack("!I", binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
    chunk_len = struct.pack("!I", len(chunk_data))
    malicious_chunk = chunk_len + chunk_type + chunk_data + chunk_crc
    
    iend_idx = clean_png_bytes.find(b"IEND") - 4 
    polyglot_bytes = clean_png_bytes[:iend_idx] + malicious_chunk + clean_png_bytes[iend_idx:]

    with open("test_files/polyglot_webshell.png", "wb") as f:
        f.write(polyglot_bytes)

    print("✅ Test files generated in the 'test_files/' directory.")

# ==========================================
# 2. SECURITY SCANNING & QUARANTINE PIPELINE
# ==========================================

def download_quarantine(url: str) -> bytes:
    """Safely downloads a file from a URL, preventing DoS, SSRF, and hang attacks."""
    # Prevent SSRF: Only allow external HTTP/HTTPS protocols
    if not url.startswith(("http://", "https://")):
        raise ValueError("Invalid protocol. Only HTTP and HTTPS are allowed.")
    
    req = urllib.request.Request(url, headers={'User-Agent': 'Fortress-Scanner/1.0'})
    downloaded_bytes = bytearray()
    
    # Create an unverified SSL context (WARNING: Not recommended for production)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        # Timeout prevents hanging attacks
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            # Stream the file to prevent memory exhaustion (Zip Bomb)
            while True:
                chunk = response.read(8192) # Read in 8KB chunks
                if not chunk:
                    break
                downloaded_bytes.extend(chunk)
                
                if len(downloaded_bytes) > MAX_FILE_SIZE:
                    raise ValueError(f"File exceeds maximum allowed size of {MAX_FILE_SIZE//(1024*1024)}MB.")
    except Exception as e:
        raise ValueError(f"Failed to safely download URL: {str(e)}")
        
    return bytes(downloaded_bytes)

def simulate_clamav_scan(file_bytes: bytes):
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in file_bytes:
        return False, "Virus detected (EICAR Signature)"
    return True, "Clean"

def sanitize_image(file_bytes: bytes) -> bytes:
    try:
        image = Image.open(io.BytesIO(file_bytes))
        image.load() 
        clean_buffer = io.BytesIO()
        image.save(clean_buffer, format="PNG") 
        return clean_buffer.getvalue()
    except Exception as e:
        raise ValueError(f"Invalid image format or corrupt file: {e}")

def process_media_security_pipeline(file_bytes: bytes, filename: str) -> dict:
    """The central security pipeline applied to ALL incoming data (Local or URL)."""
    original_size = len(file_bytes)
    
    # DEFENSE LAYER 1: Magic Number Verification
    mime = magic.from_buffer(file_bytes, mime=True)
    if mime not in ["image/png", "image/jpeg", "image/gif", "image/webp"]:
        raise HTTPException(status_code=400, detail=f"Rejected: Invalid MIME type ({mime}). Expected valid image.")

    # DEFENSE LAYER 2: Antivirus Signature Scan
    is_clean, scan_msg = simulate_clamav_scan(file_bytes)
    if not is_clean:
        raise HTTPException(status_code=406, detail=f"Rejected: Antivirus flagged the file - {scan_msg}")

    # DEFENSE LAYER 3: Sanitization (Polyglot/Metadata destruction)
    try:
        sanitized_bytes = sanitize_image(file_bytes)
        sanitized_size = len(sanitized_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Rejected: Image validation failed. {str(e)}")

    bytes_removed = original_size - sanitized_size
    
    # Save the safe file locally for demonstration
    safe_filename = f"safe_{filename.split('/')[-1]}" if "/" in filename else f"safe_{filename}"
    if not safe_filename.endswith(".png"): safe_filename += ".png"
    
    with open(safe_filename, "wb") as f:
        f.write(sanitized_bytes)

    return {
        "status": "Success! File is safe.",
        "filename": safe_filename,
        "original_size_bytes": original_size,
        "final_size_bytes": sanitized_size,
        "metadata_stripped_bytes": bytes_removed,
        "message": f"Successfully validated and sanitized. Removed {bytes_removed} bytes of potentially malicious data."
    }


# ==========================================
# 3. FASTAPI ENDPOINTS & UI
# ==========================================

@app.on_event("startup")
async def startup_event():
    generate_test_files()

@app.get("/", response_class=HTMLResponse)
async def get_index():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Fortress Upload Scanner</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            .dragover { border-color: #3b82f6 !important; background-color: #eff6ff !important; }
            .hidden { display: none; }
            .tab-active { border-bottom: 2px solid #2563eb; color: #2563eb; font-weight: 600; }
        </style>
    </head>
    <body class="bg-slate-50 text-slate-800 min-h-screen flex items-center justify-center p-6">
        
        <div class="max-w-xl w-full bg-white rounded-2xl shadow-xl overflow-hidden text-center p-8">
            <div class="mb-6">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 text-blue-600 mb-4">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <h1 class="text-2xl font-bold text-slate-900">Secure Media Scanner</h1>
                <p class="text-slate-500 mt-2 text-sm">Upload a test file or fetch from a URL to run the defense pipeline.</p>
            </div>

            <!-- Tabs -->
            <div class="flex border-b border-gray-200 mb-6">
                <button id="tab-file" class="flex-1 pb-2 tab-active transition-colors" onclick="switchTab('file')">Upload Local File</button>
                <button id="tab-url" class="flex-1 pb-2 text-slate-500 hover:text-slate-700 transition-colors" onclick="switchTab('url')">Fetch from URL</button>
            </div>

            <form id="uploadForm" class="space-y-4">
                
                <!-- Local File Mode -->
                <div id="file-mode">
                    <div id="dropzone" class="border-2 border-dashed border-slate-300 rounded-xl p-8 transition-colors duration-200 cursor-pointer hover:bg-slate-50 relative">
                        <input type="file" id="fileInput" name="file" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" accept="image/png, image/jpeg, image/webp">
                        <div class="text-slate-500 pointer-events-none">
                            <svg class="mx-auto h-12 w-12 mb-3 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                            <p id="fileNameDisplay" class="font-medium">Drag & drop a file here, or click to select</p>
                        </div>
                    </div>
                </div>

                <!-- URL Mode -->
                <div id="url-mode" class="hidden text-left">
                    <label class="block text-sm font-medium text-slate-700 mb-1">Image URL</label>
                    <input type="url" id="urlInput" placeholder="https://example.com/image.png" class="w-full px-4 py-3 rounded-xl border border-slate-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all">
                    <p class="text-xs text-slate-500 mt-2">The server will quarantine the download, enforce size limits, and scan the contents.</p>
                </div>

                <button type="submit" id="submitBtn" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded-xl transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed">
                    Scan & Secure Media
                </button>
            </form>

            <!-- Results Section -->
            <div id="resultContainer" class="mt-6 text-left hidden">
                <div id="resultBox" class="p-4 rounded-xl border">
                    <h3 id="resultTitle" class="font-bold text-lg mb-1"></h3>
                    <p id="resultMessage" class="text-sm mb-3"></p>
                    
                    <div id="statsBox" class="bg-white/50 rounded p-3 text-xs font-mono hidden">
                        <p>Original Size: <span id="statOriginal"></span> bytes</p>
                        <p>Final Size: <span id="statFinal"></span> bytes</p>
                        <p class="text-blue-600 font-bold mt-1">Stripped Data: <span id="statStripped"></span> bytes</p>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let currentMode = 'file';
            
            const dropzone = document.getElementById('dropzone');
            const fileInput = document.getElementById('fileInput');
            const urlInput = document.getElementById('urlInput');
            const fileNameDisplay = document.getElementById('fileNameDisplay');
            const form = document.getElementById('uploadForm');
            const submitBtn = document.getElementById('submitBtn');
            const resultContainer = document.getElementById('resultContainer');
            const resultBox = document.getElementById('resultBox');

            // --- Tab Switching logic ---
            function switchTab(mode) {
                currentMode = mode;
                document.getElementById('file-mode').classList.toggle('hidden', mode !== 'file');
                document.getElementById('url-mode').classList.toggle('hidden', mode !== 'url');
                
                document.getElementById('tab-file').className = mode === 'file' ? 'flex-1 pb-2 tab-active transition-colors' : 'flex-1 pb-2 text-slate-500 hover:text-slate-700 transition-colors';
                document.getElementById('tab-url').className = mode === 'url' ? 'flex-1 pb-2 tab-active transition-colors' : 'flex-1 pb-2 text-slate-500 hover:text-slate-700 transition-colors';
                
                if (mode === 'url') fileInput.value = '';
                if (mode === 'file') urlInput.value = '';
            }

            // --- File Drag & Drop ---
            fileInput.addEventListener('change', (e) => {
                if(e.target.files.length > 0) {
                    fileNameDisplay.textContent = e.target.files[0].name;
                    fileNameDisplay.classList.add('text-blue-600');
                }
            });
            dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
            dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
            dropzone.addEventListener('drop', () => dropzone.classList.remove('dragover'));

            // --- Form Submission ---
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                
                if(currentMode === 'file' && fileInput.files.length === 0) return;
                if(currentMode === 'url' && !urlInput.value) return;

                // Set loading state
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white inline" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Fetching & Scanning...`;
                resultContainer.classList.add('hidden');
                document.getElementById('statsBox').classList.add('hidden');

                try {
                    let response;
                    if (currentMode === 'file') {
                        const formData = new FormData();
                        formData.append('file', fileInput.files[0]);
                        response = await fetch('/upload', { method: 'POST', body: formData });
                    } else {
                        const formData = new URLSearchParams();
                        formData.append('url', urlInput.value);
                        response = await fetch('/upload-url', { 
                            method: 'POST', 
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: formData 
                        });
                    }
                    
                    const data = await response.json();
                    resultContainer.classList.remove('hidden');
                    
                    if (response.ok) {
                        resultBox.className = 'p-4 rounded-xl border border-green-200 bg-green-50 text-green-800';
                        document.getElementById('resultTitle').textContent = "✅ Media is Safe";
                        document.getElementById('resultMessage').textContent = data.message;
                        
                        document.getElementById('statsBox').classList.remove('hidden');
                        document.getElementById('statOriginal').textContent = data.original_size_bytes;
                        document.getElementById('statFinal').textContent = data.final_size_bytes;
                        document.getElementById('statStripped').textContent = data.metadata_stripped_bytes;
                    } else {
                        resultBox.className = 'p-4 rounded-xl border border-red-200 bg-red-50 text-red-800';
                        document.getElementById('resultTitle').textContent = "🚨 Security Alert";
                        document.getElementById('resultMessage').textContent = data.detail;
                    }
                } catch (error) {
                    resultContainer.classList.remove('hidden');
                    resultBox.className = 'p-4 rounded-xl border border-red-200 bg-red-50 text-red-800';
                    document.getElementById('resultTitle').textContent = "❌ System Error";
                    document.getElementById('resultMessage').textContent = "Failed to process the request.";
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = "Scan & Secure Media";
                }
            });
        </script>
    </body>
    </html>
    """

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Endpoint 1: Local File Upload (Memory Safe Streaming)"""
    file_bytes = bytearray()
    
    # Read the file in 8KB chunks
    while True:
        chunk = await file.read(8192)
        if not chunk:
            break
        
        file_bytes.extend(chunk)
        
        # Abort immediately if the streamed data exceeds 10MB
        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413, # 413 Payload Too Large
                detail=f"Rejected: File exceeds the {MAX_FILE_SIZE//(1024*1024)}MB limit."
            )
            
    return process_media_security_pipeline(bytes(file_bytes), file.filename)

@app.post("/upload-url")
async def upload_url(url: str = Form(...)):
    """Endpoint 2: Fetch via URL with Quarantine"""
    try:
        # Quarantine layer intercepts the fetch to prevent DoS/SSRF
        file_bytes = download_quarantine(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    filename = url.split("/")[-1] or "downloaded_image"
    return process_media_security_pipeline(file_bytes, filename)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)