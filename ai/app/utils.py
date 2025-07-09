import os
import re

def detect_language(file_path):
    """
    Detect the programming language of a file based on its extension and content.
    Returns a string like 'python', 'typescript', 'javascript', 'go', etc.
    """
    # Mapping of extensions to languages
    EXTENSION_LANG_MAP = {
        '.py': 'python',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.go': 'go',
        '.java': 'java',
        '.rb': 'ruby',
        '.php': 'php',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cs': 'csharp',
        '.rs': 'rust',
        '.sh': 'shell',
        '.html': 'html',
        '.css': 'css',
        '.json': 'json',
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.md': 'markdown',
    }

    ext = os.path.splitext(file_path)[1].lower()
    language = EXTENSION_LANG_MAP.get(ext)
    if language:
        return language

    # Heuristic: check file content for language-specific patterns
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1000)  # Read only the first 1000 chars for speed
    except Exception:
        return "unknown"

    # Python
    if re.search(r'^\s*def\s+\w+\s*\(', content, re.MULTILINE):
        return 'python'
    # JavaScript/TypeScript
    if re.search(r'^\s*function\s+\w+\s*\(', content, re.MULTILINE):
        return 'javascript'
    if re.search(r'^\s*import\s+.*from\s+["\']', content, re.MULTILINE):
        return 'typescript'
    # Go
    if re.search(r'^\s*func\s+\w+\s*\(', content, re.MULTILINE):
        return 'go'
    # Java
    if re.search(r'^\s*public\s+class\s+\w+', content, re.MULTILINE):
        return 'java'
    # C/C++
    if re.search(r'^\s*#include\s+<', content, re.MULTILINE):
        return 'c'
    # Shell
    if content.startswith('#!') and 'bash' in content:
        return 'shell'

    return "unknown"
