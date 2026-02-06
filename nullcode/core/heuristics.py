"""
Regex-based heuristics for quick vulnerability scanning
CWE-mapped patterns for common vulnerability types
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class VulnerabilityMatch:
    """Represents a vulnerability found by heuristics"""
    type: str
    cwe_id: str
    line_number: int
    code_snippet: str
    confidence: int  # 0-100
    description: str
    severity: str  # "critical", "high", "medium", "low"


class HeuristicsEngine:
    """Fast regex-based vulnerability detection"""

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, List[Tuple[re.Pattern, str, str, int, str]]]:
        """
        Load vulnerability patterns for each language - COMPREHENSIVE COVERAGE
        Returns: Dict[language, List[(pattern, cwe_id, description, confidence, severity)]]
        """
        return {
            "python": self._python_patterns(),
            "javascript": self._javascript_patterns(),
            "typescript": self._javascript_patterns(),  # Same as JS
            "java": self._java_patterns(),
            "go": self._go_patterns(),
            "c": self._c_patterns(),
            "cpp": self._cpp_patterns(),
            "php": self._php_patterns(),
            "ruby": self._ruby_patterns(),
            "rust": self._rust_patterns(),
            "csharp": self._csharp_patterns(),
            "kotlin": self._kotlin_patterns(),
            "swift": self._swift_patterns(),
        }

    def _python_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """Python vulnerability patterns - OWASP Top 10 + CWE Top 25"""
        return [
            # SQL Injection (CWE-89)
            (
                re.compile(r'execute\([^)]*%s[^)]*\)|cursor\.execute\([^)]*\+|'
                          r'\.format\([^)]*sql|f".*{.*}.*".*execute|'
                          r'raw\([^)]*\+|\.execute\([^)]*%\s*\(', re.IGNORECASE),
                "CWE-89",
                "SQL Injection|User input concatenated into SQL query without parameterization",
                85,
                "critical"
            ),
            # Command Injection (CWE-78)
            (
                re.compile(r'os\.system\(|subprocess\.call\(|subprocess\.run\(|'
                          r'subprocess\.Popen\(|eval\(|exec\(|compile\(|'
                          r'__import__\(|popen\(|commands\.', re.IGNORECASE),
                "CWE-78",
                "Command Injection|Direct execution of system commands with user input",
                90,
                "critical"
            ),
            # Hardcoded Secrets (CWE-798)
            (
                re.compile(r'(password|passwd|pwd|secret|api_key|apikey|token|auth|private_key)'
                          r'\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
                "CWE-798",
                "Hardcoded Secret|Credentials embedded directly in source code",
                95,
                "critical"
            ),
            # Path Traversal (CWE-22)
            (
                re.compile(r'open\([^)]*\+|os\.path\.join\([^)]*request|'
                          r'file\([^)]*input\(|Path\([^)]*\+', re.IGNORECASE),
                "CWE-22",
                "Path Traversal|Unsafe file path construction allowing directory traversal",
                80,
                "high"
            ),
            # Insecure Deserialization (CWE-502)
            (
                re.compile(r'pickle\.loads\(|yaml\.load\((?!.*safe)|'
                          r'marshal\.loads\(|shelve\.open\(', re.IGNORECASE),
                "CWE-502",
                "Insecure Deserialization|Unsafe deserialization of untrusted data",
                90,
                "critical"
            ),
            # XSS (CWE-79)
            (
                re.compile(r'\|safe|safe_filter|mark_safe\(|escape\s*=\s*False|'
                          r'autoescape\s*=\s*False', re.IGNORECASE),
                "CWE-79",
                "Cross-Site Scripting|Unescaped user input in HTML templates",
                75,
                "high"
            ),
            # Weak Crypto (CWE-327)
            (
                re.compile(r'md5\(|sha1\(|DES|RC4|ECB|'
                          r'Random\(\)|Crypto\.Random\.random\('),
                "CWE-327",
                "Weak Cryptography|Use of broken/weak cryptographic algorithms",
                85,
                "high"
            ),
            # SSRF (CWE-918)
            (
                re.compile(r'requests\.get\([^)]*request\.|urllib\.request\.urlopen\([^)]*input|'
                          r'httplib\.request\([^)]*user', re.IGNORECASE),
                "CWE-918",
                "Server-Side Request Forgery|User-controlled URL in HTTP request",
                80,
                "high"
            ),
            # XXE (CWE-611)
            (
                re.compile(r'etree\.parse\(|etree\.fromstring\(|'
                          r'xml\.dom\.minidom\.parse|xml\.sax\.parse', re.IGNORECASE),
                "CWE-611",
                "XML External Entity|Unsafe XML parsing allowing XXE attacks",
                75,
                "high"
            ),
            # LDAP Injection (CWE-90)
            (
                re.compile(r'search_s\([^)]*\+|search\([^)]*%', re.IGNORECASE),
                "CWE-90",
                "LDAP Injection|User input in LDAP queries without sanitization",
                80,
                "high"
            ),
            # Code Injection (CWE-94)
            (
                re.compile(r'eval\(|exec\(|compile\(|execfile\(', re.IGNORECASE),
                "CWE-94",
                "Code Injection|Dynamic code execution with user input",
                95,
                "critical"
            ),
            # Mass Assignment (CWE-915)
            (
                re.compile(r'Model\([^)]*\*\*request|from_dict\([^)]*request|'
                          r'update\([^)]*request\.', re.IGNORECASE),
                "CWE-915",
                "Mass Assignment|Uncontrolled mass property assignment from user input",
                70,
                "medium"
            ),
            # Race Condition (CWE-362)
            (
                re.compile(r'os\.access\([^)]*R_OK.*open\(|'
                          r'os\.path\.exists\([^)]*\).*open\(', re.IGNORECASE),
                "CWE-362",
                "Race Condition|TOCTOU vulnerability in file operations",
                65,
                "medium"
            ),
            # Insecure Random (CWE-338)
            (
                re.compile(r'random\.random\(|random\.randint\(|random\.choice\(', re.IGNORECASE),
                "CWE-338",
                "Insecure Randomness|Use of weak random number generator for security",
                70,
                "medium"
            ),
            # Information Disclosure (CWE-200)
            (
                re.compile(r'DEBUG\s*=\s*True|print\([^)]*password|'
                          r'print\([^)]*secret|logging\.debug\([^)]*token', re.IGNORECASE),
                "CWE-200",
                "Information Disclosure|Sensitive data exposed in logs or output",
                65,
                "medium"
            ),
            # Regex DoS (CWE-1333)
            (
                re.compile(r're\.compile\([^)]*\(.*\*.*\)\+'),
                "CWE-1333",
                "ReDoS|Regular expression vulnerable to denial of service",
                60,
                "medium"
            ),
            # Unvalidated Redirect (CWE-601)
            (
                re.compile(r'redirect\([^)]*request\.|HttpResponseRedirect\([^)]*request', re.IGNORECASE),
                "CWE-601",
                "Open Redirect|Unvalidated redirect to user-controlled URL",
                75,
                "medium"
            ),
            # Missing Authentication (CWE-306)
            (
                re.compile(r'@app\.route\([^)]*\)(?!.*@login_required)', re.IGNORECASE),
                "CWE-306",
                "Missing Authentication|Route without authentication decorator",
                50,
                "medium"
            ),
            # SQL Injection via ORM (CWE-89)
            (
                re.compile(r'\.raw\([^)]*%|\.extra\([^)]*where.*%', re.IGNORECASE),
                "CWE-89",
                "SQL Injection in ORM|Raw SQL with string concatenation",
                80,
                "high"
            ),
            # Sensitive Cookie Without HttpOnly (CWE-1004)
            (
                re.compile(r'set_cookie\([^)]*httponly\s*=\s*False', re.IGNORECASE),
                "CWE-1004",
                "Insecure Cookie|Sensitive cookie without HttpOnly flag",
                65,
                "medium"
            ),
            # Sensitive Cookie Without Secure (CWE-614)
            (
                re.compile(r'set_cookie\([^)]*secure\s*=\s*False', re.IGNORECASE),
                "CWE-614",
                "Insecure Cookie|Sensitive cookie without Secure flag",
                65,
                "medium"
            ),
        ]

    def _javascript_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """JavaScript/TypeScript vulnerability patterns - Comprehensive"""
        return [
            # XSS (CWE-79)
            (
                re.compile(r'innerHTML\s*=|outerHTML\s*=|document\.write\(|'
                          r'\.html\([^)]*\+|dangerouslySetInnerHTML|'
                          r'insertAdjacentHTML\(|execScript\(', re.IGNORECASE),
                "CWE-79",
                "Cross-Site Scripting|Unsafe HTML injection without sanitization",
                85,
                "critical"
            ),
            # SQL Injection (CWE-89)
            (
                re.compile(r'query\([^)]*\+|execute\([^)]*`\$\{|'
                          r'raw\([^)]*\$\{|knex\.raw\([^)]*\+', re.IGNORECASE),
                "CWE-89",
                "SQL Injection|User input concatenated in SQL query",
                85,
                "critical"
            ),
            # Command Injection (CWE-78)
            (
                re.compile(r'exec\(|execSync\(|spawn\(|eval\(|'
                          r'Function\([^)]*\+|child_process\.|vm\.runInNewContext', re.IGNORECASE),
                "CWE-78",
                "Command Injection|Dynamic code/command execution with user input",
                90,
                "critical"
            ),
            # Hardcoded Secrets (CWE-798)
            (
                re.compile(r'(password|secret|apiKey|token|auth|privateKey)\s*[:=]\s*["\'][^"\']{8,}["\']',
                          re.IGNORECASE),
                "CWE-798",
                "Hardcoded Secret|Credentials embedded directly in source code",
                95,
                "critical"
            ),
            # Path Traversal (CWE-22)
            (
                re.compile(r'readFile\([^)]*\+|createReadStream\([^)]*req\.|'
                          r'resolve\([^)]*params|fs\.readFileSync\([^)]*\+', re.IGNORECASE),
                "CWE-22",
                "Path Traversal|Unsafe file path construction allowing directory traversal",
                80,
                "high"
            ),
            # Prototype Pollution (CWE-1321)
            (
                re.compile(r'__proto__|constructor\[.*\]|Object\.assign\([^)]*req\.|'
                          r'merge\([^)]*req\.|extend\([^)]*\$\{'),
                "CWE-1321",
                "Prototype Pollution|Unsafe object property assignment",
                80,
                "high"
            ),
            # NoSQL Injection (CWE-943)
            (
                re.compile(r'find\([^)]*req\.|findOne\([^)]*\$where|'
                          r'aggregate\([^)]*\$\{', re.IGNORECASE),
                "CWE-943",
                "NoSQL Injection|User input in NoSQL query without validation",
                80,
                "high"
            ),
            # SSRF (CWE-918)
            (
                re.compile(r'fetch\([^)]*req\.|axios\.get\([^)]*params|'
                          r'request\([^)]*query', re.IGNORECASE),
                "CWE-918",
                "Server-Side Request Forgery|User-controlled URL in HTTP request",
                80,
                "high"
            ),
            # Insecure Random (CWE-338)
            (
                re.compile(r'Math\.random\(\).*token|Math\.random\(\).*password|'
                          r'Math\.random\(\).*secret', re.IGNORECASE),
                "CWE-338",
                "Insecure Randomness|Weak PRNG used for security-sensitive values",
                75,
                "medium"
            ),
            # Open Redirect (CWE-601)
            (
                re.compile(r'location\.href\s*=\s*req\.|window\.location\s*=\s*params|'
                          r'response\.redirect\([^)]*query', re.IGNORECASE),
                "CWE-601",
                "Open Redirect|Unvalidated redirect to user-controlled URL",
                75,
                "medium"
            ),
            # JWT Weak Secret (CWE-326)
            (
                re.compile(r'jwt\.sign\([^)]*["\'][^"\']{1,8}["\']|'
                          r'jwt\.verify\([^)]*["\']secret["\']', re.IGNORECASE),
                "CWE-326",
                "Weak JWT Secret|JWT signed with weak or hardcoded secret",
                85,
                "high"
            ),
            # Regex DoS (CWE-1333)
            (
                re.compile(r'new RegExp\([^)]*req\.|test\([^)]*\$\{.*\(.*\*.*\)\+'),
                "CWE-1333",
                "ReDoS|Regular expression vulnerable to denial of service",
                65,
                "medium"
            ),
            # XXE (CWE-611)
            (
                re.compile(r'parseString\(|parseXml\(|DOMParser\(', re.IGNORECASE),
                "CWE-611",
                "XML External Entity|Unsafe XML parsing allowing XXE attacks",
                70,
                "high"
            ),
        ]

    def _java_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """Java vulnerability patterns - Comprehensive"""
        return [
            # SQL Injection (CWE-89)
            (
                re.compile(r'executeQuery\([^)]*\+|Statement\.execute\([^)]*\+|'
                          r'createQuery\([^)]*\+|prepareStatement\([^)]*\+', re.IGNORECASE),
                "CWE-89",
                "SQL Injection|Concatenated SQL queries without parameterization",
                85,
                "critical"
            ),
            # Command Injection (CWE-78)
            (
                re.compile(r'Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\([^)]*\+|'
                          r'\.exec\([^)]*\+', re.IGNORECASE),
                "CWE-78",
                "Command Injection|Dynamic command execution with user input",
                90,
                "critical"
            ),
            # XXE (CWE-611)
            (
                re.compile(r'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|'
                          r'TransformerFactory|SchemaFactory', re.IGNORECASE),
                "CWE-611",
                "XML External Entity|Unsafe XML parsing without disabling external entities",
                75,
                "high"
            ),
            # Insecure Deserialization (CWE-502)
            (
                re.compile(r'ObjectInputStream\(|readObject\(|XMLDecoder\(|'
                          r'XStream\(|readUnshared\(', re.IGNORECASE),
                "CWE-502",
                "Insecure Deserialization|Unsafe object deserialization from untrusted data",
                85,
                "critical"
            ),
            # Path Traversal (CWE-22)
            (
                re.compile(r'new File\([^)]*\+|FileInputStream\([^)]*\+|'
                          r'FileReader\([^)]*\+|getResource\([^)]*\+', re.IGNORECASE),
                "CWE-22",
                "Path Traversal|Unsafe file path construction allowing directory traversal",
                80,
                "high"
            ),
            # Hardcoded Secrets (CWE-798)
            (
                re.compile(r'(password|secret|apiKey|token)\s*=\s*"[^"]{8,}"|'
                          r'(PASSWORD|SECRET|API_KEY)\s*=\s*"[^"]{8,}"', re.IGNORECASE),
                "CWE-798",
                "Hardcoded Secret|Credentials embedded directly in source code",
                95,
                "critical"
            ),
            # Weak Crypto (CWE-327)
            (
                re.compile(r'MD5|SHA1|DES|getInstance\("DES"|getInstance\("RC4"|'
                          r'ECB', re.IGNORECASE),
                "CWE-327",
                "Weak Cryptography|Use of broken/weak cryptographic algorithms",
                85,
                "high"
            ),
            # LDAP Injection (CWE-90)
            (
                re.compile(r'new InitialDirContext|search\([^)]*\+|'
                          r'SearchControls\([^)]*\+', re.IGNORECASE),
                "CWE-90",
                "LDAP Injection|User input in LDAP queries without sanitization",
                80,
                "high"
            ),
            # SSRF (CWE-918)
            (
                re.compile(r'URL\([^)]*request|HttpURLConnection\([^)]*param|'
                          r'openConnection\([^)]*user', re.IGNORECASE),
                "CWE-918",
                "Server-Side Request Forgery|User-controlled URL in HTTP request",
                80,
                "high"
            ),
            # Insecure Random (CWE-338)
            (
                re.compile(r'new Random\(\)|Math\.random\(', re.IGNORECASE),
                "CWE-338",
                "Insecure Randomness|Weak PRNG used for security-sensitive values",
                70,
                "medium"
            ),
        ]

    def _go_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """Go vulnerability patterns - Comprehensive"""
        return [
            # Command Injection (CWE-78)
            (
                re.compile(r'exec\.Command\([^)]*\+|cmd\.Run\(|os\.system|'\n                          r'syscall\.Exec\([^)]*\+', re.IGNORECASE),
                "CWE-78",
                "Command Injection|Dynamic command execution with user input",
                85,
                "critical"
            ),
            # SQL Injection (CWE-89)
            (
                re.compile(r'db\.Query\([^)]*\+|Exec\([^)]*fmt\.Sprintf|'\n                          r'QueryRow\([^)]*\+', re.IGNORECASE),
                "CWE-89",
                "SQL Injection|String concatenation in SQL queries without parameterization",
                85,
                "critical"
            ),
            # Path Traversal (CWE-22)
            (
                re.compile(r'ioutil\.ReadFile\([^)]*\+|os\.Open\([^)]*\+|'\n                          r'filepath\.Join\([^)]*input', re.IGNORECASE),
                "CWE-22",
                "Path Traversal|Unsafe file path construction allowing directory traversal",
                80,
                "high"
            ),
            # SSRF (CWE-918)
            (
                re.compile(r'http\.Get\([^)]*request|http\.Post\([^)]*params', re.IGNORECASE),
                "CWE-918",
                "Server-Side Request Forgery|User-controlled URL in HTTP request",
                80,
                "high"
            ),
            # Hardcoded Secrets (CWE-798)
            (
                re.compile(r'(password|secret|apiKey|token)\s*[:=]\s*"[^"]{8,}"', re.IGNORECASE),
                "CWE-798",
                "Hardcoded Secret|Credentials embedded directly in source code",
                95,
                "critical"
            ),
            # Insecure Random (CWE-338)
            (
                re.compile(r'rand\.Int\(|rand\.Intn\(|math/rand', re.IGNORECASE),
                "CWE-338",
                "Insecure Randomness|Weak PRNG used for security-sensitive values",
                70,
                "medium"
            ),
        ]

    def _c_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """C vulnerability patterns - Comprehensive"""
        return [
            # Buffer Overflow (CWE-120)
            (
                re.compile(r'strcpy\(|strcat\(|gets\(|sprintf\(|vsprintf\(|'\n                          r'scanf\(|fscanf\(|sscanf\(|strncpy\([^,)]*,[^,)]*\)', re.IGNORECASE),
                "CWE-120",
                "Buffer Overflow|Unsafe string operations without bounds checking",
                95,
                "critical"
            ),
            # Format String (CWE-134)
            (
                re.compile(r'printf\([^,)]*\)|fprintf\([^,)]*,[^,)]*\)|'\n                          r'sprintf\([^,)]*,[^,)]*\)', re.IGNORECASE),
                "CWE-134",
                "Format String Vulnerability|Uncontrolled format string parameter",
                90,
                "critical"
            ),
            # Command Injection (CWE-78)
            (
                re.compile(r'system\(|popen\(|exec[lv][pe]?\(', re.IGNORECASE),
                "CWE-78",
                "Command Injection|Direct command execution without sanitization",
                90,
                "critical"
            ),
            # Integer Overflow (CWE-190)
            (
                re.compile(r'malloc\([^)]*\*|calloc\([^)]*\*|realloc\([^)]*\*', re.IGNORECASE),
                "CWE-190",
                "Integer Overflow|Multiplication in memory allocation size calculation",
                75,
                "high"
            ),
            # Use After Free (CWE-416)
            (
                re.compile(r'free\([^)]*\);[^{]*[^}]*\1', re.IGNORECASE),
                "CWE-416",
                "Use After Free|Memory accessed after being freed",
                80,
                "critical"
            ),
            # Null Pointer Dereference (CWE-476)
            (
                re.compile(r'malloc\([^)]*\)[^;]*\*[^=]|calloc\([^)]*\)[^;]*\*[^=]', re.IGNORECASE),
                "CWE-476",
                "Null Pointer Dereference|Pointer dereferenced without null check",
                70,
                "high"
            ),
            # Race Condition (CWE-362)
            (
                re.compile(r'access\([^)]*\).*open\(|stat\([^)]*\).*open\(', re.IGNORECASE),
                "CWE-362",
                "Race Condition|TOCTOU vulnerability in file operations",
                70,
                "medium"
            ),
        ]

    def _cpp_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """C++ vulnerability patterns - Extended from C"""
        c_patterns = self._c_patterns()
        cpp_specific = [
            # Use After Free with delete (CWE-416)
            (
                re.compile(r'delete\s+[^;]+;.*\1', re.IGNORECASE),
                "CWE-416",
                "Use After Free|Object accessed after delete",
                85,
                "critical"
            ),
            # Memory Leak (CWE-401)
            (
                re.compile(r'new\s+\w+(?!.*delete)', re.IGNORECASE),
                "CWE-401",
                "Memory Leak|Dynamic memory allocated without corresponding delete",
                60,
                "medium"
            ),
            # Integer Overflow in new (CWE-190)
            (
                re.compile(r'new\s+\w+\[[^\]]*\*[^\]]*\]', re.IGNORECASE),
                "CWE-190",
                "Integer Overflow|Multiplication in array allocation size",
                75,
                "high"
            ),
        ]
        return c_patterns + cpp_specific

    def _php_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:
        """PHP vulnerability patterns - Comprehensive"""
        return [
            # SQL Injection (CWE-89)
            (
                re.compile(r'mysql_query\([^)]*\$|mysqli_query\([^)]*\$|'\n                          r'query\([^)]*\$|exec\([^)]*\$', re.IGNORECASE),
                "CWE-89",
                "SQL Injection|User input concatenated in SQL query without parameterization",
                85,
                "critical"
            ),
            # Command Injection (CWE-78)
            (
                re.compile(r'exec\(|shell_exec\(|system\(|passthru\(|'\n                          r'popen\(|proc_open\(|eval\(|assert\(', re.IGNORECASE),
                "CWE-78",
                "Command Injection|Direct command execution with user input",
                90,
                "critical"
            ),
            # XSS (CWE-79)
            (
                re.compile(r'echo\s+\$_(GET|POST|REQUEST)|print\s+\$_(GET|POST|REQUEST)|'\n                          r'<\?=\s*\$_(GET|POST|REQUEST)', re.IGNORECASE),
                "CWE-79",
                "Cross-Site Scripting|Unescaped user input in HTML output",
                85,
                "high"
            ),
            # Path Traversal (CWE-22)
            (
                re.compile(r'include\([^)]*\$|require\([^)]*\$|file_get_contents\([^)]*\$|'\n                          r'fopen\([^)]*\$|readfile\([^)]*\$', re.IGNORECASE),
                "CWE-22",
                "Path Traversal|Unsafe file inclusion/reading with user input",
                85,
                "critical"
            ),
            # Code Injection (CWE-94)
            (
                re.compile(r'eval\(|assert\(|preg_replace\([^)]*\/e|'\n                          r'create_function\(', re.IGNORECASE),
                "CWE-94",
                "Code Injection|Dynamic code execution with user input",
                95,
                "critical"
            ),
            # Insecure Deserialization (CWE-502)
            (
                re.compile(r'unserialize\([^)]*\$_(GET|POST|REQUEST)|'\n                          r'unserialize\([^)]*\$_COOKIE', re.IGNORECASE),
                "CWE-502",
                "Insecure Deserialization|Unsafe deserialization of untrusted data",
                90,
                "critical"
            ),
            # SSRF (CWE-918)
            (
                re.compile(r'file_get_contents\([^)]*\$|curl_exec\([^)]*\$|'\n                          r'fopen\([^)]*http', re.IGNORECASE),\n                "CWE-918",\n                "Server-Side Request Forgery|User-controlled URL in HTTP request",\n                80,\n                "high"\n            ),\n            # Hardcoded Secrets (CWE-798)\n            (\n                re.compile(r'\$(password|passwd|pwd|secret|api_key|apikey)\\s*=\\s*["\'][^"\']{8,}["\']', re.IGNORECASE),\n                "CWE-798",\n                "Hardcoded Secret|Credentials embedded directly in source code",\n                95,\n                "critical"\n            ),\n            # XXE (CWE-611)\n            (\n                re.compile(r'simplexml_load_string\(|simplexml_load_file\(|'\n                          r'DOMDocument.*load', re.IGNORECASE),\n                "CWE-611",\n                "XML External Entity|Unsafe XML parsing allowing XXE attacks",\n                75,\n                "high"\n            ),\n            # Weak Crypto (CWE-327)\n            (\n                re.compile(r'md5\(|sha1\(|crypt\(', re.IGNORECASE),\n                "CWE-327",\n                "Weak Cryptography|Use of broken/weak cryptographic algorithms",\n                80,\n                "high"\n            ),\n        ]\n\n    def _ruby_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:\n        \"\"\"Ruby vulnerability patterns - Comprehensive\"\"\"\n        return [\n            # SQL Injection (CWE-89)\n            (\n                re.compile(r'find_by_sql\([^)]*#\{|execute\([^)]*#\{|'\n                          r'where\([^)]*#\{|select\([^)]*#\{', re.IGNORECASE),\n                "CWE-89",\n                "SQL Injection|User input interpolated in SQL query without sanitization",\n                85,\n                "critical"\n            ),\n            # Command Injection (CWE-78)\n            (\n                re.compile(r'system\(|exec\(|`[^`]*#\{|%x\{|'\n                          r'Kernel\.system\(|IO\.popen\(|eval\(', re.IGNORECASE),\n                "CWE-78",\n                "Command Injection|Direct command execution with user input",\n                90,\n                "critical"\n            ),\n            # Code Injection (CWE-94)\n            (\n                re.compile(r'eval\(|instance_eval\(|class_eval\(|module_eval\(|'\n                          r'send\([^)]*params', re.IGNORECASE),\n                "CWE-94",\n                "Code Injection|Dynamic code execution with user input",\n                95,\n                "critical"\n            ),\n            # Path Traversal (CWE-22)\n            (\n                re.compile(r'File\.read\([^)]*params|File\.open\([^)]*params|'\n                          r'IO\.read\([^)]*params', re.IGNORECASE),\n                "CWE-22",\n                "Path Traversal|Unsafe file path construction allowing directory traversal",\n                80,\n                "high"\n            ),\n            # XSS (CWE-79)\n            (\n                re.compile(r'html_safe|raw\(|content_tag\([^)]*params', re.IGNORECASE),\n                "CWE-79",\n                "Cross-Site Scripting|Unescaped user input in HTML output",\n                75,\n                "high"\n            ),\n            # Insecure Deserialization (CWE-502)\n            (\n                re.compile(r'Marshal\.load\(|YAML\.load\((?!.*safe)|'\n                          r'Oj\.load\(', re.IGNORECASE),\n                "CWE-502",\n                "Insecure Deserialization|Unsafe deserialization of untrusted data",\n                90,\n                "critical"\n            ),\n            # SSRF (CWE-918)\n            (\n                re.compile(r'open\([^)]*params|Net::HTTP\.get\([^)]*params', re.IGNORECASE),\n                "CWE-918",\n                "Server-Side Request Forgery|User-controlled URL in HTTP request",\n                80,\n                "high"\n            ),\n            # Hardcoded Secrets (CWE-798)\n            (\n                re.compile(r'(password|secret|api_key|token)\\s*=\\s*["\'][^"\']{8,}["\']', re.IGNORECASE),\n                "CWE-798",\n                "Hardcoded Secret|Credentials embedded directly in source code",\n                95,\n                "critical"\n            ),\n        ]\n\n    def _rust_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:\n        \"\"\"Rust vulnerability patterns - Memory safety focused\"\"\"\n        return [\n            # Unsafe Block (CWE-119)\n            (\n                re.compile(r'unsafe\\s*\\{', re.IGNORECASE),\n                "CWE-119",\n                "Unsafe Code Block|Manual memory management bypassing Rust safety guarantees",\n                70,\n                "medium"\n            ),\n            # Command Injection (CWE-78)\n            (\n                re.compile(r'Command::new\([^)]*format!|process::Command.*arg\([^)]*&', re.IGNORECASE),\n                "CWE-78",\n                "Command Injection|User input in command execution",\n                85,\n                "critical"\n            ),\n            # SQL Injection (CWE-89)\n            (\n                re.compile(r'query\([^)]*format!|execute\([^)]*&', re.IGNORECASE),\n                "CWE-89",\n                "SQL Injection|String formatting in SQL query without parameterization",\n                80,\n                "high"\n            ),\n            # Path Traversal (CWE-22)\n            (\n                re.compile(r'File::open\([^)]*format!|read_to_string\([^)]*&', re.IGNORECASE),\n                "CWE-22",\n                "Path Traversal|Unsafe file path construction allowing directory traversal",\n                75,\n                "high"\n            ),\n            # Hardcoded Secrets (CWE-798)\n            (\n                re.compile(r'(password|secret|api_key|token):\\s*String\\s*=\\s*String::from\\("[^"]{8,}"\\)', re.IGNORECASE),\n                "CWE-798",\n                "Hardcoded Secret|Credentials embedded directly in source code",\n                95,\n                "critical"\n            ),\n            # Insecure Deserialization (CWE-502)\n            (\n                re.compile(r'serde_json::from_str|bincode::deserialize', re.IGNORECASE),\n                "CWE-502",\n                "Insecure Deserialization|Deserialization without validation",\n                70,\n                "medium"\n            ),\n        ]\n\n    def _csharp_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:\n        \"\"\"C# vulnerability patterns - Comprehensive\"\"\"\n        return [\n            # SQL Injection (CWE-89)\n            (\n                re.compile(r'ExecuteNonQuery\([^)]*\\+|ExecuteReader\([^)]*\\+|'\n                          r'SqlCommand\([^)]*\\+|CommandText\\s*=.*\\+', re.IGNORECASE),\n                "CWE-89",\n                "SQL Injection|User input concatenated in SQL query without parameterization",\n                85,\n                "critical"\n            ),\n            # Command Injection (CWE-78)\n            (\n                re.compile(r'Process\\.Start\([^)]*\\+|ProcessStartInfo.*Arguments\\s*=.*\\+', re.IGNORECASE),\n                "CWE-78",\n                "Command Injection|Dynamic command execution with user input",\n                90,\n                "critical"\n            ),\n            # Path Traversal (CWE-22)\n            (\n                re.compile(r'File\\.ReadAllText\([^)]*\\+|FileStream\([^)]*\\+|'\n                          r'Path\\.Combine\([^)]*Request', re.IGNORECASE),\n                "CWE-22",\n                "Path Traversal|Unsafe file path construction allowing directory traversal",\n                80,\n                "high"\n            ),\n            # XSS (CWE-79)\n            (\n                re.compile(r'Response\\.Write\([^)]*Request|Html\\.Raw\(|'\n                          r'@Html\\.Raw\([^)]*Model', re.IGNORECASE),\n                "CWE-79",\n                "Cross-Site Scripting|Unencoded user input in HTML output",\n                85,\n                "high"\n            ),\n            # Insecure Deserialization (CWE-502)\n            (\n                re.compile(r'BinaryFormatter|NetDataContractSerializer|'\n                          r'JavaScriptSerializer\\.Deserialize', re.IGNORECASE),\n                "CWE-502",\n                "Insecure Deserialization|Unsafe deserialization of untrusted data",\n                90,\n                "critical"\n            ),\n            # XXE (CWE-611)\n            (\n                re.compile(r'XmlDocument|XmlTextReader|XPathNavigator', re.IGNORECASE),\n                "CWE-611",\n                "XML External Entity|Unsafe XML parsing allowing XXE attacks",\n                75,\n                "high"\n            ),\n            # Hardcoded Secrets (CWE-798)\n            (\n                re.compile(r'(password|secret|apiKey|token)\\s*=\\s*"[^"]{8,}"', re.IGNORECASE),\n                "CWE-798",\n                "Hardcoded Secret|Credentials embedded directly in source code",\n                95,\n                "critical"\n            ),\n            # LDAP Injection (CWE-90)\n            (\n                re.compile(r'DirectorySearcher.*Filter\\s*=.*\\+', re.IGNORECASE),\n                "CWE-90",\n                "LDAP Injection|User input in LDAP queries without sanitization",\n                80,\n                "high"\n            ),\n            # Weak Crypto (CWE-327)\n            (\n                re.compile(r'MD5|SHA1|DES|RC2', re.IGNORECASE),\n                "CWE-327",\n                "Weak Cryptography|Use of broken/weak cryptographic algorithms",\n                85,\n                "high"\n            ),\n        ]\n\n    def _kotlin_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:\n        \"\"\"Kotlin vulnerability patterns - Android/JVM focused\"\"\"\n        java_patterns = self._java_patterns()\n        kotlin_specific = [\n            # SQL Injection (CWE-89)\n            (\n                re.compile(r'rawQuery\([^)]*\\$|execSQL\([^)]*\\$', re.IGNORECASE),\n                "CWE-89",\n                "SQL Injection|String interpolation in SQL query without parameterization",\n                85,\n                "critical"\n            ),\n            # Hardcoded Secrets (CWE-798)\n            (\n                re.compile(r'val\\s+(password|secret|apiKey|token)\\s*=\\s*"[^"]{8,}"', re.IGNORECASE),\n                "CWE-798",\n                "Hardcoded Secret|Credentials embedded directly in source code",\n                95,\n                "critical"\n            ),\n            # WebView XSS (CWE-79)\n            (\n                re.compile(r'loadUrl\([^)]*javascript:|loadDataWithBaseURL\([^)]*<script', re.IGNORECASE),\n                "CWE-79",\n                "Cross-Site Scripting|JavaScript injection in WebView",\n                85,\n                "high"\n            ),\n        ]\n        return java_patterns + kotlin_specific\n\n    def _swift_patterns(self) -> List[Tuple[re.Pattern, str, str, int, str]]:\n        \"\"\"Swift vulnerability patterns - iOS/macOS focused\"\"\"\n        return [\n            # SQL Injection (CWE-89)\n            (\n                re.compile(r'executeQuery\([^)]*\\\\\\(|executeUpdate\([^)]*\\\\\\(', re.IGNORECASE),\n                "CWE-89",\n                "SQL Injection|String interpolation in SQL query without parameterization",\n                85,\n                "critical"\n            ),\n            # Command Injection (CWE-78)\n            (\n                re.compile(r'Process\(\\)|system\([^)]*\\\\\\(', re.IGNORECASE),\n                "CWE-78",\n                "Command Injection|Dynamic command execution with user input",\n                90,\n                "critical"\n            ),\n            # Path Traversal (CWE-22)\n            (\n                re.compile(r'String\(contentsOfFile:\\s*\\\\\\(|FileManager.*url.*\\\\\\(', re.IGNORECASE),\n                "CWE-22",\n                "Path Traversal|Unsafe file path construction allowing directory traversal",\n                80,\n                "high"\n            ),\n            # Hardcoded Secrets (CWE-798)\n            (\n                re.compile(r'let\\s+(password|secret|apiKey|token)\\s*=\\s*"[^"]{8,}"', re.IGNORECASE),\n                "CWE-798",\n                "Hardcoded Secret|Credentials embedded directly in source code",\n                95,\n                "critical"\n            ),\n            # Insecure Deserialization (CWE-502)\n            (\n                re.compile(r'NSKeyedUnarchiver.*unarchiveObject|JSONDecoder\(\)\.decode', re.IGNORECASE),\n                "CWE-502",\n                "Insecure Deserialization|Deserialization without validation",\n                75,\n                "high"\n            ),\n            # Weak Crypto (CWE-327)\n            (\n                re.compile(r'CC_MD5|CC_SHA1|kCCAlgorithmDES', re.IGNORECASE),\n                "CWE-327",\n                "Weak Cryptography|Use of broken/weak cryptographic algorithms",\n                85,\n                "high"\n            ),\n            # Insecure Random (CWE-338)\n            (\n                re.compile(r'arc4random\(\)|random\(\)', re.IGNORECASE),\n                "CWE-338",\n                "Insecure Randomness|Weak PRNG used for security-sensitive values",\n                70,\n                "medium"\n            ),\n        ]

    def scan_file(self, filepath: str, language: str) -> List[VulnerabilityMatch]:
        """
        Scan a single file using regex heuristics
        
        Args:
            filepath: Path to file to scan
            language: Programming language (python, javascript, java, go, c)
            
        Returns:
            List of vulnerability matches
        """
        vulnerabilities = []
        
        if language not in self.patterns:
            return vulnerabilities

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            patterns = self.patterns[language]
            
            for line_num, line in enumerate(lines, start=1):
                for pattern, cwe_id, description, confidence, severity in patterns:
                    if pattern.search(line):
                        vulnerabilities.append(VulnerabilityMatch(
                            type=description.split(':')[0],
                            cwe_id=cwe_id,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            confidence=confidence,
                            description=description,
                            severity=severity
                        ))

        except Exception as e:
            # Silently skip files we can't read
            pass

        return vulnerabilities

    def scan_code_snippet(self, code: str, language: str) -> List[VulnerabilityMatch]:
        """
        Scan a code snippet (for testing/validation)
        
        Args:
            code: Code string to scan
            language: Programming language
            
        Returns:
            List of vulnerability matches
        """
        vulnerabilities = []
        
        if language not in self.patterns:
            return vulnerabilities

        patterns = self.patterns[language]
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for pattern, cwe_id, description, confidence, severity in patterns:
                if pattern.search(line):
                    vulnerabilities.append(VulnerabilityMatch(
                        type=description.split(':')[0],
                        cwe_id=cwe_id,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        confidence=confidence,
                        description=description,
                        severity=severity
                    ))

        return vulnerabilities
