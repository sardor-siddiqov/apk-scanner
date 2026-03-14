import os
import shutil
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from .virustotal import check_hash_virustotal, upload_file_virustotal

from .analyzer import analyze_file

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="APK Scanner MVP")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan-apk")
async def scan_apk(file: UploadFile = File(...)):
    original_ext = os.path.splitext(file.filename)[1].lower()
    file_id = f"{uuid.uuid4().hex}{original_ext}"
    file_path = os.path.join(UPLOAD_DIR, file_id)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = analyze_file(file_path)

        # Local analyzer natijasini alohida saqlab qo'yamiz
        if result:
            result["local_risk_score"] = result.get("risk_score")
            result["local_risk_level"] = result.get("risk_level")

        # Default holat: VirusTotal bo'lmasa hukm chiqarmaymiz
        if result:
            result["risk_score"] = None
            result["risk_level"] = "unknown"
            result["final_verdict_source"] = "not_available"

        # Faqat APK bo'lsa VirusTotal tekshiramiz
        if result and result.get("analysis_type") == "apk" and result.get("sha256"):
            vt_result = check_hash_virustotal(result["sha256"])

            if vt_result:
                result["virustotal"] = vt_result
                result["final_verdict_source"] = "virustotal"

                malicious = vt_result.get("malicious", 0)
                suspicious = vt_result.get("suspicious", 0)

                # Final hukm faqat VirusTotal asosida
                if malicious >= 5:
                    result["risk_level"] = "critical"
                    result["risk_score"] = 95
                elif malicious >= 1:
                    result["risk_level"] = "high"
                    result["risk_score"] = 75
                elif suspicious >= 1:
                    result["risk_level"] = "medium"
                    result["risk_score"] = 45
                else:
                    result["risk_level"] = "low"
                    result["risk_score"] = 10
            else:
                upload_file_virustotal(file_path)
                result["final_verdict_source"] = "waiting_virustotal"
                result["risk_level"] = "unknown"
                result["risk_score"] = None

        return JSONResponse(content=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Skan qilishda xatolik: {str(e)}")

    finally:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
@app.get("/about")
async def about(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})