"""
Python language-specific parsing and analysis
Uses AST for deeper code analysis
"""

import ast
from typing import List, Dict, Optional
from pathlib import Path


class PythonParser:
    """Python-specific code analysis"""

    def parse_file(self, filepath: str) -> Optional[ast.Module]:
        """
        Parse Python file into AST
        
        Args:
            filepath: Path to Python file
            
        Returns:
            AST module or None if parsing fails
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return ast.parse(content, filepath)
        except (SyntaxError, UnicodeDecodeError):
            return None

    def extract_functions(self, tree: ast.Module) -> List[Dict[str, any]]:
        """Extract all function definitions"""
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'line': node.lineno,
                    'args': [arg.arg for arg in node.args.args],
                    'decorators': [d.id if isinstance(d, ast.Name) else str(d) 
                                  for d in node.decorator_list]
                })
        
        return functions

    def find_imports(self, tree: ast.Module) -> List[str]:
        """Extract all imported modules"""
        imports = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
        
        return imports

    def analyze_security_context(self, filepath: str) -> Dict[str, any]:
        """
        Analyze file for security-relevant context
        
        Returns:
            Dict with security-relevant information
        """
        tree = self.parse_file(filepath)
        if not tree:
            return {}

        context = {
            'uses_eval': False,
            'uses_exec': False,
            'uses_subprocess': False,
            'uses_pickle': False,
            'uses_yaml': False,
            'uses_sql': False,
            'dangerous_imports': []
        }

        # Check imports
        imports = self.find_imports(tree)
        dangerous_modules = {
            'pickle', 'subprocess', 'os', 'eval', 'exec',
            'yaml', 'sqlite3', 'MySQLdb', 'psycopg2'
        }
        
        context['dangerous_imports'] = [m for m in imports if m in dangerous_modules]
        context['uses_subprocess'] = 'subprocess' in imports
        context['uses_pickle'] = 'pickle' in imports
        context['uses_yaml'] = 'yaml' in imports
        context['uses_sql'] = any(m in imports for m in ['sqlite3', 'MySQLdb', 'psycopg2'])

        # Check for eval/exec calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'eval':
                        context['uses_eval'] = True
                    elif node.func.id == 'exec':
                        context['uses_exec'] = True

        return context
