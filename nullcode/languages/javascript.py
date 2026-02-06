"""
JavaScript/TypeScript language-specific parsing
Basic analysis without tree-sitter (optional enhancement)
"""

import re
from typing import List, Dict


class JavaScriptParser:
    """JavaScript/TypeScript code analysis"""

    def extract_functions(self, code: str) -> List[Dict[str, any]]:
        """Extract function definitions (basic regex-based)"""
        functions = []
        
        # Match function declarations and arrow functions
        patterns = [
            r'function\s+(\w+)\s*\(',  # function name()
            r'const\s+(\w+)\s*=\s*function',  # const name = function
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>',  # const name = () =>
            r'(\w+)\s*:\s*function',  # name: function (object method)
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                functions.append({
                    'name': match.group(1),
                    'line': code[:match.start()].count('\n') + 1
                })
        
        return functions

    def find_imports(self, code: str) -> List[str]:
        """Extract imports and requires"""
        imports = []
        
        # Match various import styles
        patterns = [
            r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',  # import x from 'y'
            r'require\(["\']([^"\']+)["\']\)',  # require('x')
            r'import\(["\']([^"\']+)["\']\)',  # dynamic import('x')
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                imports.append(match.group(1))
        
        return imports

    def analyze_security_context(self, filepath: str) -> Dict[str, any]:
        """Analyze file for security-relevant context"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except:
            return {}

        context = {
            'uses_eval': False,
            'uses_exec': False,
            'uses_innerhtml': False,
            'uses_dangerously': False,
            'dangerous_imports': []
        }

        # Check for dangerous patterns
        if re.search(r'\beval\s*\(', code):
            context['uses_eval'] = True
        if re.search(r'\bexec\s*\(|execSync\s*\(', code):
            context['uses_exec'] = True
        if re.search(r'\.innerHTML\s*=|\.outerHTML\s*=', code):
            context['uses_innerhtml'] = True
        if re.search(r'dangerouslySetInnerHTML', code):
            context['uses_dangerously'] = True

        # Check imports
        imports = self.find_imports(code)
        dangerous_modules = {'child_process', 'vm', 'eval'}
        context['dangerous_imports'] = [m for m in imports if m in dangerous_modules]

        return context
