"""
Scanner orchestration - manages quick/deep/hybrid scan modes
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .heuristics import HeuristicsEngine, VulnerabilityMatch


@dataclass
class ScanResult:
    """Complete scan results for a project"""
    total_files: int
    scanned_files: int
    vulnerabilities: List[VulnerabilityMatch]
    scan_mode: str
    duration: float
    skipped_files: List[str]


class Scanner:
    """Main vulnerability scanner orchestrator"""

    # Supported file extensions
    LANGUAGE_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.java': 'java',
        '.go': 'go',
        '.c': 'c',
        '.cpp': 'c',
        '.cc': 'c',
        '.h': 'c',
        '.hpp': 'c',
    }

    # Directories to skip
    SKIP_DIRS = {
        'node_modules', '.git', '__pycache__', 'venv', 'env',
        '.venv', 'dist', 'build', 'target', '.idea', '.vscode',
        'vendor', '.nullcode'
    }

    def __init__(self, mode: str = "hybrid", threshold: int = 70, max_workers: int = 4):
        """
        Initialize scanner
        
        Args:
            mode: Scan mode - 'quick', 'deep', or 'hybrid'
            threshold: Minimum confidence threshold (0-100)
            max_workers: Max parallel workers for scanning
        """
        self.mode = mode
        self.threshold = threshold
        self.max_workers = max_workers
        self.heuristics = HeuristicsEngine()
        self.ai_engine = None  # Lazy load AI engine

    def scan_project(self, project_path: str, file_patterns: Optional[List[str]] = None) -> ScanResult:
        """
        Scan entire project directory
        
        Args:
            project_path: Root path of project
            file_patterns: Optional list of file patterns to scan (e.g., ['*.py', '*.js'])
            
        Returns:
            ScanResult with all vulnerabilities found
        """
        import time
        start_time = time.time()

        # Collect files to scan
        files_to_scan = self._collect_files(project_path, file_patterns)
        total_files = len(files_to_scan)
        
        vulnerabilities = []
        skipped_files = []
        scanned_count = 0

        # Parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self._scan_single_file, filepath): filepath
                for filepath in files_to_scan
            }

            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    file_vulns = future.result()
                    vulnerabilities.extend(file_vulns)
                    scanned_count += 1
                except Exception as e:
                    skipped_files.append(f"{filepath}: {str(e)}")

        # Filter by threshold
        vulnerabilities = [v for v in vulnerabilities if v.confidence >= self.threshold]

        duration = time.time() - start_time

        return ScanResult(
            total_files=total_files,
            scanned_files=scanned_count,
            vulnerabilities=vulnerabilities,
            scan_mode=self.mode,
            duration=duration,
            skipped_files=skipped_files
        )

    def scan_file(self, filepath: str) -> List[VulnerabilityMatch]:
        """
        Scan a single file
        
        Args:
            filepath: Path to file
            
        Returns:
            List of vulnerabilities found
        """
        return self._scan_single_file(filepath)

    def _scan_single_file(self, filepath: str) -> List[VulnerabilityMatch]:
        """Internal method to scan a single file"""
        # Detect language
        language = self._detect_language(filepath)
        if not language:
            return []

        vulnerabilities = []

        # Quick mode: Use heuristics only
        if self.mode in ['quick', 'hybrid']:
            heuristic_vulns = self.heuristics.scan_file(filepath, language)
            vulnerabilities.extend(heuristic_vulns)

        # Deep mode: Use AI model
        if self.mode in ['deep', 'hybrid']:
            # Lazy load AI engine
            if self.ai_engine is None and self.mode == 'deep':
                from .ai_engine import AIEngine
                self.ai_engine = AIEngine()
            
            # Note: AI engine implementation will be added
            # For now, deep mode falls back to heuristics
            if self.ai_engine:
                try:
                    ai_vulns = self.ai_engine.scan_file(filepath, language)
                    vulnerabilities.extend(ai_vulns)
                except Exception:
                    pass  # Fall back to heuristics

        # Remove duplicates (same vulnerability on same line)
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        return vulnerabilities

    def _collect_files(self, project_path: str, file_patterns: Optional[List[str]]) -> List[str]:
        """Collect all files to scan from project directory"""
        files = []
        project_path = Path(project_path)

        for root, dirs, filenames in os.walk(project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for filename in filenames:
                filepath = Path(root) / filename
                
                # Check if file extension is supported
                if filepath.suffix in self.LANGUAGE_MAP:
                    files.append(str(filepath))

        return files

    def _detect_language(self, filepath: str) -> Optional[str]:
        """Detect programming language from file extension"""
        ext = Path(filepath).suffix.lower()
        return self.LANGUAGE_MAP.get(ext)

    def _deduplicate_vulnerabilities(self, vulns: List[VulnerabilityMatch]) -> List[VulnerabilityMatch]:
        """Remove duplicate vulnerabilities (same type, line, file)"""
        seen = set()
        unique_vulns = []

        for vuln in vulns:
            key = (vuln.type, vuln.line_number, vuln.code_snippet)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        return unique_vulns

    def get_statistics(self, vulnerabilities: List[VulnerabilityMatch]) -> Dict[str, any]:
        """Calculate statistics from scan results"""
        stats = {
            'total': len(vulnerabilities),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {},
            'avg_confidence': 0
        }

        if not vulnerabilities:
            return stats

        for vuln in vulnerabilities:
            # Count by severity
            stats['by_severity'][vuln.severity] += 1
            
            # Count by type
            vuln_type = vuln.type
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1

        # Calculate average confidence
        stats['avg_confidence'] = sum(v.confidence for v in vulnerabilities) / len(vulnerabilities)

        return stats
