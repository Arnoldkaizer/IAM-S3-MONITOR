"""S3 Malware and Content Scanner."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class FileScanResult:
    """Scan results produced by S3MalwareScanner."""

    object_key: str
    is_suspicious: bool
    risk_score: float
    entropy: float
    detected_file_type: str
    threats: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)


class S3MalwareScanner:
    """In-depth file scanner detecting malware, dangerous extensions, magic-byte mismatches, and high entropy."""

    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif",
        ".jar", ".msi", ".docm", ".xlsm", ".pptm", ".sh", ".cpl", ".hta"
    }

    MAGIC_BYTES = {
        "executable": [b"MZ"],               # Windows PE
        "elf": [b"\x7fELF"],                 # Linux Executable
        "zip": [b"PK\x03\x04"],              # Zip Archive
        "pdf": [b"%PDF"],                    # PDF Document
        "png": [b"\x89PNG\r\n\x1a\n"],       # PNG Image
        "jpeg": [b"\xff\xd8\xff"],           # JPEG Image
        "gzip": [b"\x1f\x8b"],               # Gzip Compressed
    }

    SUSPICIOUS_PATTERNS = [
        (re.compile(b"(-ExecutionPolicy\\s+Bypass|DownloadString|Invoke-Expression|iex\\s*\\()", re.IGNORECASE), "Suspicious PowerShell Execution Payload"),
        (re.compile(rb"(<\?php\s+eval|system\(|passthru\(|shell_exec\()", re.IGNORECASE), "Web Shell Backdoor Payload"),
        (re.compile(b"(cmd\\.exe\\s+/c|powershell\\.exe|wscript\\.shell)", re.IGNORECASE), "Command Shell Spawning Payload"),
        (re.compile(b"([A-Za-z0-9+/]{200,}={0,2})", re.ASCII), "Large Encoded Base64 Payload"),
    ]

    def __init__(self, boto3_session: Any | None = None) -> None:
        self._boto3_session = boto3_session

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data (0.0 to 8.0 scale)."""
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    def scan_bytes(self, data: bytes, object_key: str = "unknown") -> FileScanResult:
        """Scan raw byte stream for malicious signatures, file mismatches, and entropy anomalies."""
        threats: list[str] = []
        findings: list[dict[str, Any]] = []
        risk_score = 0.0
        ext = Path(object_key).suffix.lower()

        # 1. Dangerous extension check
        if ext in self.DANGEROUS_EXTENSIONS:
            threats.append(f"Dangerous file extension: {ext}")
            risk_score += 4.0
            findings.append({
                "type": "DANGEROUS_EXTENSION",
                "severity": "HIGH",
                "message": f"File uses executable or macro-enabled extension ({ext}).",
            })

        # 2. Magic byte / Header detection
        detected_type = "unknown"
        for ftype, magic_list in self.MAGIC_BYTES.items():
            if any(data.startswith(m) for m in magic_list):
                detected_type = ftype
                break

        # Check for extension spoofing / magic byte mismatch
        if ext in {".pdf", ".txt", ".png", ".jpg"} and detected_type == "executable":
            threats.append(f"Magic byte mismatch: Windows executable disguised as {ext}")
            risk_score += 6.0
            findings.append({
                "type": "MAGIC_BYTE_MISMATCH",
                "severity": "CRITICAL",
                "message": f"File extension is {ext} but header is Windows PE Executable.",
            })

        # 3. Entropy Analysis
        entropy = self.calculate_entropy(data)
        if entropy > 7.5 and len(data) > 1024:
            threats.append(f"High Shannon entropy ({entropy}/8.0) - possible packed or encrypted malware")
            risk_score += 3.0
            findings.append({
                "type": "HIGH_ENTROPY",
                "severity": "MEDIUM",
                "message": f"High entropy ({entropy}) indicates packed or encrypted payload.",
            })

        # 4. Pattern / Signature Matching
        for pattern, threat_label in self.SUSPICIOUS_PATTERNS:
            if pattern.search(data):
                threats.append(threat_label)
                risk_score += 5.0
                findings.append({
                    "type": "SUSPICIOUS_PATTERN",
                    "severity": "HIGH",
                    "message": threat_label,
                })

        # Cap score at 10.0
        risk_score = min(round(risk_score, 1), 10.0)
        is_suspicious = len(threats) > 0 or risk_score >= 4.0

        return FileScanResult(
            object_key=object_key,
            is_suspicious=is_suspicious,
            risk_score=risk_score,
            entropy=entropy,
            detected_file_type=detected_type,
            threats=threats,
            findings=findings,
        )

    def scan_s3_object(self, bucket_name: str, object_key: str) -> FileScanResult:
        """Download and scan an object from an S3 bucket via boto3."""
        session = self._boto3_session or __import__("boto3").Session()
        s3 = session.client("s3")
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        content = response["Body"].read()
        return self.scan_bytes(content, object_key=object_key)

    def scan_bucket(self, bucket_name: str, max_objects: int = 50) -> list[FileScanResult]:
        """Scan objects across an entire S3 bucket."""
        session = self._boto3_session or __import__("boto3").Session()
        s3 = session.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        results: list[FileScanResult] = []
        scanned = 0
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                if scanned >= max_objects:
                    break
                key = obj["Key"]
                result = self.scan_s3_object(bucket_name, key)
                results.append(result)
                scanned += 1
            if scanned >= max_objects:
                break
        return results
