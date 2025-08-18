#!/usr/bin/env python3
import os
import asyncio
import re
from datetime import datetime
from typing import List, Dict
import ssl
import socket
import logging
import pickle
import httpx
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from contextlib import asynccontextmanager

#BASE_DIR = os.path.dirname(os.path.abspath(__file__))
#MODEL_PATH = os.path.join(BASE_DIR, "..", "phishing.pkl")


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


scan_statistics = {
    "total_scanned": 0,
    "threats_detected": 0,
    "safe_sites": 0,
    "start_time": datetime.now()
}

class URLScanRequest(BaseModel):
    url: HttpUrl

class URLScanResponse(BaseModel):
    url: str
    is_threat: bool
    risk_score: int
    threats: List[str]
    analysis_details: Dict
    scan_time: float

class StatisticsResponse(BaseModel):
    total_scanned: int
    threats_detected: int
    safe_sites: int
    active_since: str

class PhishingDetector:
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=10.0)
        
        with open("phishing.pkl", "rb") as f:
            self.model = pickle.load(f)

    def normalize_url(self,url: str) -> str:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        path=parsed.path.lower()
        return domain+ path
    
    def predict_with_model(self, url: str) -> float:
            try:
                clean_url = self.normalize_url(url)
                features = [clean_url]
                pred = self.model.predict(features)[0] # returns good or bad
                print(f"Model prediction for {url}: {pred}")
                return pred.lower() == "good"  # Convert to boolean
            except Exception as e:
                logger.error(f"Model prediction error: {e}")
                return 100 

    async def close(self):
        await self.http_client.aclose()

    async def fetch_page(self, url: str) -> str:
        """Fetch page content asynchronously."""
        try:
            response = await self.http_client.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                for script in soup(["script", "style"]):
                    script.extract()
                text = soup.get_text()
                text = re.sub(r"\s+", " ", text).strip()
                return text
        except Exception as e:
            logger.warning(f"Failed to fetch page {url}: {e}")
        return ""

    async def check_ssl(self, url: str) -> bool:
        """Check if URL has a valid SSL certificate."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.settimeout(5)
                sock.connect((hostname, 443))
                cert = sock.getpeercert()
                return cert is not None
        except Exception:
            return False

    async def get_whois_info(self, domain: str):
        """Run blocking WHOIS in a separate thread."""
        try:
            result = await asyncio.to_thread(whois.whois, domain)
            def format_date(d):
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime):
                    return d.strftime("%Y-%m-%d %H:%M:%S")
                return None
            return {
                "domain": result.domain,
                "registrar": result.registrar,
                "creation_date": format_date(result.creation_date),
                "expiration_date": format_date(result.expiration_date)
            }
        except Exception:
            return {}

    async def analyze(self, url: str):
        threats = []
        analysis_details = {}
        risk_score = 0
        is_threat = False

        parsed = urlparse(url)
        domain = parsed.netloc

        # --- Quick synchronous checks ---
        if len(domain) > 100:
            threats.append("Unusually long domain")
            risk_score += 20
        if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
            threats.append("IP address used")
            risk_score += 30
        if any(short in domain for short in ["bit.ly", "tinyurl.com", "t.co"]):
            threats.append("URL shortener detected")
            risk_score += 25
        if re.search(r"[0oO]", domain):
            threats.append("Potential homograph attack")
            risk_score += 15
        if domain.count("-") > 10:
            threats.append("Excessive hyphens in domain")
            risk_score += 10

        analysis_details["domain_analysis"] = {
            "risk_score": risk_score,
            "threats": threats.copy()
        }

        # --- Run ML model prediction returning true or false ---
        prediction = self.predict_with_model(url)
        if prediction :
            return False, risk_score, threats, analysis_details
        else:
            threats.append("ML model flagged as phishing")
            risk_score += 50
            analysis_details["model_analysis"] = {"risk_score": 50, "threats": ["ml_flagged_phishing"]}

        if risk_score > 60:
            return True, risk_score, threats, analysis_details
        else:
            
            # --- Run slow network checks in parallel ---
            ssl_task = asyncio.create_task(self.check_ssl(url))
            whois_task = asyncio.create_task(self.get_whois_info(domain))
            page_task = asyncio.create_task(self.fetch_page(url))

            ssl_valid, whois_info, page_text = await asyncio.gather(
                ssl_task, whois_task, page_task
            )

            # --- SSL check ---
            if not ssl_valid:
                threats.append("ssl_invalid")
                risk_score += 20
                analysis_details["ssl_analysis"] = {"risk_score": 20, "threats": ["ssl_invalid"]}

            # --- WHOIS check ---
            if whois_info.get("creation_date"):
                creation_date = datetime.strptime(whois_info["creation_date"], "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - creation_date).days < 30:
                    threats.append("recently_registered_domain")
                    risk_score += 25
                    analysis_details["whois_analysis"] = {"risk_score": 25, "threats": ["recently_registered_domain"]}

            # --- Page content check ---
            phishing_keywords = ["password", "login", "update", "account", "bank", "verify"]
            count = sum(page_text.lower().count(k) for k in phishing_keywords)
            if count > 5:
                threats.append("suspicious_page_content")
                risk_score += 15
                analysis_details["content_analysis"] = {"risk_score": 15, "threats": ["suspicious_page_content"]}

        if risk_score > 60:
            is_threat = True

        return is_threat, risk_score, threats, analysis_details


detector = PhishingDetector() 

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PhishGuard Pro backend starting up...")
    yield
    await detector.close()
    logger.info("PhishGuard Pro backend shutting down...")

app = FastAPI(
    title="PhishGuard Pro API",
    description="Advanced phishing detection backend",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/")
async def root():
    return {"service": "PhishGuard Pro API", "version": "1.0.0", "status": "active", "endpoints": ["/api/scan", "/api/statistics", "/api/health"]}

@app.post("/api/scan", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    start_time = datetime.now()
    url_str = str(request.url)
    try:
        is_threat, risk_score, threats, analysis_details = await detector.analyze(url_str)

        # Update statistics
        scan_statistics["total_scanned"] += 1
        if is_threat:
            scan_statistics["threats_detected"] += 1
        else:
            scan_statistics["safe_sites"] += 1

        scan_time = (datetime.now() - start_time).total_seconds()

        logger.info(f"Scanned {url_str} | Threat: {is_threat} | Risk: {risk_score} | Time: {scan_time:.2f}s")

        return URLScanResponse(
            url=url_str,
            is_threat=is_threat,
            risk_score=risk_score,
            threats=threats,
            analysis_details=analysis_details,
            scan_time=scan_time
        )

    except Exception as e:
        logger.error(f"Scan error for {url_str}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/api/statistics", response_model=StatisticsResponse)
async def get_statistics():
    return StatisticsResponse(
        total_scanned=scan_statistics["total_scanned"],
        threats_detected=scan_statistics["threats_detected"],
        safe_sites=scan_statistics["safe_sites"],
        active_since=scan_statistics["start_time"].isoformat()
    )

@app.get("/api/health")
async def health_check():
    uptime = datetime.now() - scan_statistics["start_time"]
    return {"status": "healthy", "timestamp": datetime.now().isoformat(), "uptime_seconds": uptime.total_seconds(), "version": "1.0.0"}






