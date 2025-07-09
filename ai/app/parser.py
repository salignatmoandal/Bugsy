import os
import ast
import re
from typing import List, Dict, Any

# 1. Supported file extensions for analysis
SUPPORTED_EXTENSIONS = {
    '.py': 'python',
    '.go': 'go',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.java': 'java',
    '.cpp': 'cpp',
    '.c': 'c',
    '.rs': 'rust',
    '.php': 'php',
    '.rb': 'ruby'
}

# 2. Directory patterns to ignore during codebase traversal
IGNORE_PATTERNS = [
    '__pycache__', 'node_modules', '.git', '.venv', 'venv', 'vendor', 'target', 'build', 'dist'
]

def is_supported_file(filename: str) -> bool:
    """
    Check if the file has a supported extension.
    """
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUPPORTED_EXTENSIONS

def should_ignore_dir(dirname: str) -> bool:
    """
    Check if the directory should be ignored during traversal.
    """
    return any(pattern in dirname for pattern in IGNORE_PATTERNS)

def walk_codebase(repo_path: str) -> List[str]:
    """
    Recursively walk through the repo directory and return a list of files to analyze.
    """
    code_files = []
    for root, dirs, files in os.walk(repo_path):
        # Filter out ignored directories
        dirs[:] = [d for d in dirs if not should_ignore_dir(d)]
        for file in files:
            if is_supported_file(file):
                code_files.append(os.path.join(root, file))
    return code_files

def parse_python_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze a Python file: structure, functions, classes, complexity.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return {
            'path': file_path,
            'language': 'python',
            'syntax_error': str(e),
            'lines': len(content.splitlines()),
            'functions': [],
            'classes': [],
            'complexity': 0
        }
    # Extract functions and classes
    functions = extract_functions(tree)
    classes = extract_classes(tree)
    # Compute cyclomatic complexity
    complexity = calculate_cyclomatic_complexity(tree)
    return {
        'path': file_path,
        'language': 'python',
        'lines': len(content.splitlines()),
        'functions': functions,
        'classes': classes,
        'complexity': complexity
    }

def extract_functions(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Extract functions from Python code using the AST.
    """
    functions = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append({
                'name': node.name,
                'line_start': node.lineno,
                'line_end': getattr(node, 'end_lineno', node.lineno),
                'lines': getattr(node, 'end_lineno', node.lineno) - node.lineno + 1
            })
    return functions

def extract_classes(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Extract classes from Python code using the AST.
    """
    classes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes.append({
                'name': node.name,
                'line_start': node.lineno,
                'line_end': getattr(node, 'end_lineno', node.lineno),
                'lines': getattr(node, 'end_lineno', node.lineno) - node.lineno + 1
            })
    return classes

def calculate_cyclomatic_complexity(tree: ast.AST) -> int:
    """
    Calculate the cyclomatic complexity of a Python file using the AST.
    """
    complexity = 1  # Base complexity
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler)):
            complexity += 1
    return complexity

def parse_generic_file(file_path: str, language: str) -> Dict[str, Any]:
    """
    Basic analysis for other languages: count lines, detect functions using regex.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    lines = content.splitlines()
    # Simple heuristics to detect functions (example for Go, JS, etc.)
    function_patterns = {
        'go': r'func\s+\w+\s*\(',
        'javascript': r'function\s+\w+\s*\(',
        'typescript': r'function\s+\w+\s*\(',
        'java': r'(public|private|protected)?\s+\w+\s+\w+\s*\(',
        'cpp': r'\w+\s+\w+\s*\(',
        'c': r'\w+\s+\w+\s*\(',
        'php': r'function\s+\w+\s*\(',
        'ruby': r'def\s+\w+'
    }
    pattern = function_patterns.get(language)
    functions = []
    if pattern:
        for match in re.finditer(pattern, content):
            # Estimate start line
            line_start = content[:match.start()].count('\n') + 1
            functions.append({'name': match.group(0), 'line_start': line_start})
    return {
        'path': file_path,
        'language': language,
        'lines': len(lines),
        'functions': functions,
        'classes': [],
        'complexity': len(functions)  # Very simplified complexity
    }

def analyze_codebase(repo_path: str) -> Dict[str, Any]:
    """
    Main function: analyze all files in the repo and aggregate the results.
    """
    files = walk_codebase(repo_path)
    results = []
    for file_path in files:
        ext = os.path.splitext(file_path)[1].lower()
        language = SUPPORTED_EXTENSIONS.get(ext, 'unknown')
        if language == 'python':
            result = parse_python_file(file_path)
        else:
            result = parse_generic_file(file_path, language)
        results.append(result)
    return {
        'files': results,
        'total_files': len(results),
        'languages': list(set(r['language'] for r in results))
    }

# Example usage:
if __name__ == "__main__":
    repo = "/path/to/your/repo"
    analysis = analyze_codebase(repo)
    from pprint import pprint
    pprint(analysis)
