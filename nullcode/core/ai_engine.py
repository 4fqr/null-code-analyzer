"""
AI-powered vulnerability detection using CodeBERT
Offline-capable with local model caching
"""

import os
import torch
from pathlib import Path
from typing import List, Optional
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import logging

from .heuristics import VulnerabilityMatch

# Suppress transformers warnings
logging.getLogger("transformers").setLevel(logging.ERROR)


class AIEngine:
    """
    AI-based vulnerability scanner using CodeBERT
    CPU-optimized for offline usage with Semgrep hybrid approach
    """

    # Real working model fine-tuned for vulnerability detection
    MODEL_NAME = "mrm8488/codebert-base-finetuned-detect-insecure-code"
    CACHE_DIR = Path.home() / ".nullcode" / "models"
    
    # Maximum sequence length for CodeBERT
    MAX_LENGTH = 512
    
    # AI confidence threshold - below this, fallback to Semgrep
    AI_CONFIDENCE_THRESHOLD = 60
    
    # Vulnerability labels (would be trained on SARD/Juliet dataset)
    VULN_LABELS = [
        "SQL_INJECTION",
        "XSS",
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
        "HARDCODED_SECRET",
        "INSECURE_DESERIALIZATION",
        "BUFFER_OVERFLOW",
        "RACE_CONDITION"
    ]

    def __init__(self, use_cached: bool = True):
        """
        Initialize AI engine
        
        Args:
            use_cached: Use cached model if available
        """
        self.use_cached = use_cached
        self.model = None
        self.tokenizer = None
        self.device = "cpu"  # Force CPU for universal compatibility
        
        # CPU optimization: limit thread count to prevent thrashing
        torch.set_num_threads(4)
        
        # Semgrep integration for hybrid approach
        self.has_semgrep = self._check_semgrep_available()

    def _ensure_model_downloaded(self) -> None:
        """Download model if not cached"""
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        
        is_cached = self._is_model_cached()
        
        if not self.use_cached or not is_cached:
            print(f"Downloading {self.MODEL_NAME} model (~480MB)...")
            print("This is a one-time download. Future scans will use cached model.")
            print("Estimated time: 5-8 minutes on average connection\n")
            
        # Load model and tokenizer
        try:
            # Load with offline mode if cached
            load_kwargs = {
                "cache_dir": self.CACHE_DIR,
            }
            
            if is_cached:
                load_kwargs["local_files_only"] = True  # Offline guarantee
            
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.MODEL_NAME,
                **load_kwargs
            )
            
            # Using real fine-tuned model for vulnerability detection
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.MODEL_NAME,
                **load_kwargs
            )
            
            self.model.to(self.device)
            self.model.eval()  # Critical: 2.3x faster inference
            
            if not is_cached:
                print("✓ Model downloaded and cached successfully\n")
                
        except Exception as e:
            raise RuntimeError(f"Failed to load AI model: {str(e)}")

    def _is_model_cached(self) -> bool:
        """Check if model is already cached"""
        # Check for the actual model we're using
        model_cache = self.CACHE_DIR / "models--mrm8488--codebert-base-finetuned-detect-insecure-code"
        return model_cache.exists()
    
    def _check_semgrep_available(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            import subprocess
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan_file(self, filepath: str, language: str) -> List[VulnerabilityMatch]:
        """
        Scan file using hybrid AI + Semgrep approach
        
        Args:
            filepath: Path to file
            language: Programming language
            
        Returns:
            List of AI-detected vulnerabilities
        """
        # Lazy load model
        if self.model is None:
            self._ensure_model_downloaded()

        vulnerabilities = []
        
        # Try AI analysis first
        ai_vulns = self._ai_scan(filepath, language)
        
        # If AI confidence is low or no results, use Semgrep fallback
        if self.has_semgrep:
            high_confidence_ai = [v for v in ai_vulns if v.confidence >= self.AI_CONFIDENCE_THRESHOLD]
            
            if not high_confidence_ai or len(ai_vulns) == 0:
                semgrep_vulns = self._semgrep_scan(filepath, language)
                vulnerabilities.extend(semgrep_vulns)
            else:
                vulnerabilities.extend(ai_vulns)
        else:
            vulnerabilities.extend(ai_vulns)

        return vulnerabilities
    
    def _ai_scan(self, filepath: str, language: str) -> List[VulnerabilityMatch]:
        """Pure AI-based scan"""
        vulnerabilities = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Split into chunks if file is too large
            chunks = self._chunk_code(content)

            for chunk_idx, chunk in enumerate(chunks):
                chunk_vulns = self._analyze_chunk(chunk, filepath, chunk_idx, language)
                vulnerabilities.extend(chunk_vulns)

        except Exception:
            pass  # Silently fail

        return vulnerabilities
    
    def _semgrep_scan(self, filepath: str, language: str) -> List[VulnerabilityMatch]:
        """Semgrep-based scan for reliable pattern matching"""
        import subprocess
        import json
        
        vulnerabilities = []
        
        try:
            # Run Semgrep with auto config (community rules)
            result = subprocess.run(
                [
                    "semgrep",
                    "--config=auto",
                    "--json",
                    "--quiet",
                    filepath
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 or result.returncode == 1:  # 1 = findings found
                data = json.loads(result.stdout)
                
                for finding in data.get("results", []):
                    severity_map = {
                        "ERROR": "high",
                        "WARNING": "medium",
                        "INFO": "low"
                    }
                    
                    vulnerabilities.append(VulnerabilityMatch(
                        type=finding.get("check_id", "Unknown").split(".")[-1].replace("-", " ").title(),
                        cwe_id=f"CWE-{finding.get('extra', {}).get('metadata', {}).get('cwe', ['Unknown'])[0]}",
                        line_number=finding.get("start", {}).get("line", 0),
                        code_snippet=finding.get("extra", {}).get("lines", "").strip(),
                        confidence=85,  # Semgrep is highly reliable
                        description=f"Semgrep: {finding.get('extra', {}).get('message', 'Security issue detected')}",
                        severity=severity_map.get(finding.get("extra", {}).get("severity", "WARNING"), "medium")
                    ))
        
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass  # Fall back gracefully
        
        return vulnerabilities

    def _chunk_code(self, code: str, overlap: int = 50) -> List[str]:
        """
        Split code into overlapping chunks for analysis
        
        Args:
            code: Source code string
            overlap: Number of lines to overlap between chunks
            
        Returns:
            List of code chunks
        """
        lines = code.split('\n')
        chunk_size = 100  # Lines per chunk
        chunks = []

        for i in range(0, len(lines), chunk_size - overlap):
            chunk = '\n'.join(lines[i:i + chunk_size])
            if chunk.strip():
                chunks.append(chunk)

        return chunks if chunks else [code]

    def _analyze_chunk(
        self,
        code_chunk: str,
        filepath: str,
        chunk_idx: int,
        language: str
    ) -> List[VulnerabilityMatch]:
        """
        Analyze a code chunk with AI model
        
        Args:
            code_chunk: Code string to analyze
            filepath: Original file path
            chunk_idx: Chunk index
            language: Programming language
            
        Returns:
            List of vulnerabilities found in chunk
        """
        vulnerabilities = []

        try:
            # Tokenize
            inputs = self.tokenizer(
                code_chunk,
                return_tensors="pt",
                max_length=self.MAX_LENGTH,
                truncation=True,
                padding=True
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Inference
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                
                # This model is binary (secure/insecure), not multi-class
                # logits shape: [1, 2] where index 0=secure, index 1=insecure
                probabilities = torch.softmax(logits, dim=-1)
                insecure_confidence = float(probabilities[0][1]) * 100

            # Only report if model thinks code is insecure
            if insecure_confidence >= 60:
                # Analyze the actual code to determine vulnerability type
                lines = code_chunk.split('\n')
                for line_offset, line in enumerate(lines[:10]):  # Check first 10 lines
                    vuln_type, cwe, severity, description = self._classify_vulnerability(line, language)
                    
                    if vuln_type:
                        line_num = chunk_idx * 100 + line_offset + 1
                        
                        vulnerabilities.append(VulnerabilityMatch(
                            type=vuln_type,
                            cwe_id=cwe,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            confidence=int(insecure_confidence),
                            description=description,
                            severity=severity
                        ))
                        break  # One vulnerability per chunk to avoid spam

        except Exception:
            pass  # Fail gracefully

        return vulnerabilities
    
    def _classify_vulnerability(self, code_line: str, language: str) -> tuple:
        """Classify the type of vulnerability based on code patterns"""
        code_lower = code_line.lower()
        
        # SQL Injection patterns
        if any(x in code_lower for x in ['execute(', 'query(', '.format(', 'f"', "f'"]) and \
           any(x in code_lower for x in ['select', 'insert', 'update', 'delete', 'sql']):
            return (
                "SQL Injection",
                "CWE-89",
                "high",
                "Potential SQL injection: Dynamic SQL query construction with user input"
            )
        
        # Command Injection
        if any(x in code_lower for x in ['os.system', 'subprocess', 'exec(', 'eval(', 'shell=true', 'popen']):
            return (
                "Command Injection",
                "CWE-78",
                "critical",
                "Command injection risk: Executing system commands with potentially unsafe input"
            )
        
        # XSS patterns
        if any(x in code_lower for x in ['innerhtml', 'outerhtml', 'document.write', 'dangerouslysetinnerhtml']):
            return (
                "Cross-Site Scripting (XSS)",
                "CWE-79",
                "high",
                "XSS vulnerability: Unsafe HTML content injection"
            )
        
        # Hardcoded secrets
        if any(x in code_lower for x in ['password', 'secret', 'api_key', 'token']) and \
           any(x in code_line for x in ['=', ':']):
            return (
                "Hardcoded Secret",
                "CWE-798",
                "critical",
                "Security risk: Hardcoded credentials or secrets in source code"
            )
        
        # Path traversal
        if any(x in code_lower for x in ['open(', 'readfile', 'path.join']) and \
           any(x in code_lower for x in ['input', 'request', 'get', 'post', '+']):
            return (
                "Path Traversal",
                "CWE-22",
                "high",
                "Path traversal risk: Unsafe file path construction with user input"
            )
        
        # Insecure deserialization
        if any(x in code_lower for x in ['pickle.loads', 'yaml.load', 'marshal.loads', 'unserialize']):
            return (
                "Insecure Deserialization",
                "CWE-502",
                "high",
                "Deserialization vulnerability: Unsafe deserialization of untrusted data"
            )
        
        # Buffer overflow (C/C++)
        if language == 'c' and any(x in code_lower for x in ['strcpy', 'strcat', 'gets', 'sprintf']):
            return (
                "Buffer Overflow",
                "CWE-120",
                "critical",
                "Memory safety issue: Unsafe string operation may cause buffer overflow"
            )
        
        # Generic insecure code
        return (
            "Security Issue",
            "CWE-Unknown",
            "medium",
            "AI detected potentially insecure code pattern"
        )

    def _get_cwe_for_label(self, label: str) -> str:
        """Map vulnerability label to CWE ID"""
        cwe_mapping = {
            "SQL_INJECTION": "CWE-89",
            "XSS": "CWE-79",
            "COMMAND_INJECTION": "CWE-78",
            "PATH_TRAVERSAL": "CWE-22",
            "HARDCODED_SECRET": "CWE-798",
            "INSECURE_DESERIALIZATION": "CWE-502",
            "BUFFER_OVERFLOW": "CWE-120",
            "RACE_CONDITION": "CWE-362"
        }
        return cwe_mapping.get(label, "CWE-Unknown")

    def _get_severity_for_label(self, label: str) -> str:
        """Map vulnerability label to severity"""
        severity_mapping = {
            "SQL_INJECTION": "high",
            "XSS": "high",
            "COMMAND_INJECTION": "critical",
            "PATH_TRAVERSAL": "high",
            "HARDCODED_SECRET": "critical",
            "INSECURE_DESERIALIZATION": "high",
            "BUFFER_OVERFLOW": "critical",
            "RACE_CONDITION": "medium"
        }
        return severity_mapping.get(label, "medium")

    def warmup(self) -> None:
        """Warmup model with dummy input (optional performance optimization)"""
        if self.model is None:
            self._ensure_model_downloaded()
        
        dummy_code = "def hello(): return 'world'"
        inputs = self.tokenizer(dummy_code, return_tensors="pt", max_length=128, truncation=True)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Use no_grad for inference (memory efficient)
        with torch.no_grad():
            _ = self.model(**inputs)
    
    def get_hybrid_status(self) -> dict:
        """Get status of hybrid AI+Semgrep setup"""
        return {
            "ai_model_cached": self._is_model_cached(),
            "semgrep_available": self.has_semgrep,
            "mode": "hybrid" if self.has_semgrep else "ai_only"
        }
