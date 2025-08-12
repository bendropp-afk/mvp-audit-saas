from fastapi import FastAPI, HTTPException, File, UploadFile
from pydantic import BaseModel
import os

from backend.parsers.python_parser import parse_python_code
from backend.detectors.sql_injection import SQLInjectionDetector
from backend.reporting.vulnerability_reporter import VulnerabilityReporter

app = FastAPI(title="MVP Audit Tool", version="0.1.0")

class CodeRequest(BaseModel):
    code: str
    filename: str = "uploaded.py"

@app.get("/")
def root():
    return {"status": "up", "version": "0.1.0"}

@app.post("/analyze")
def analyze(request: CodeRequest):
    try:
        detector = SQLInjectionDetector()
        vulnerabilities = detector.analyze_sql_injection(request.code)
        reporter = VulnerabilityReporter()
        report = reporter.generate_report(vulnerabilities, {"filename": request.filename})
        return {"report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files")
    content = await file.read()
    return analyze(CodeRequest(code=content.decode(), filename=file.filename))

