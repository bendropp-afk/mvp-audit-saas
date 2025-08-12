from fastapi import FastAPI, HTTPException, File, UploadFile
from pydantic import BaseModel
import os

from backend.parsers.python_parser import parse_python_code
from backend.detectors.sql_injection import SQLInjectionDetector
from backend.detectors.xss_detector import XSSDetector
from backend.detectors.rce_detector import RCEDetector
from backend.reporting.vulnerability_reporter import VulnerabilityReporter

app = FastAPI(title="MVP Audit Tool", version="0.2.0")


class CodeRequest(BaseModel):
    code: str
    filename: str = "uploaded.py"


@app.get("/")
def root():
    return {"status": "up", "version": "0.2.0"}


@app.post("/analyze")
def analyze(request: CodeRequest):
    """
    Analyse le code fourni pour détecter les vulnérabilités SQL, XSS et RCE.
    """
    try:
        detectors = [
            SQLInjectionDetector(),
            XSSDetector(),
            RCEDetector()
        ]
        all_vulns = []
        for detector in detectors:
            vulns = detector.analyze(request.code)
            all_vulns.extend(vulns)

        reporter = VulnerabilityReporter()
        report = reporter.generate_report(all_vulns, {"filename": request.filename})
        return {"report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """
    Upload d’un fichier .py pour analyse.
    """
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files are accepted")
    content = await file.read()
    request = CodeRequest(code=content.decode("utf-8"), filename=file.filename)
    return analyze(request)
