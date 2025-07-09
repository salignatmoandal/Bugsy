

import re
from typing import List, Dict, Any
from pathlib import Path

from utils import detect_language  # ✅ Vrai import ici



class CodebaseAnalyzer:
    """
    Unified codebase analyzer for Bugsy - analyzes all languages with a single approach.
    """
    
    def __init__(self):
        # Directories to ignore during analysis
        self.ignore_dirs = {
            '__pycache__', 'node_modules', '.git', '.venv', 'venv', 
            'vendor', 'target', 'build', 'dist', '.next', 'coverage',
            'bin', 'obj', '.pytest_cache', '.mypy_cache'
        }
        
        # File patterns to ignore
        self.ignore_files = {
            '.min.js', '.min.css', '.bundle.js', '.map', '.lock',
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'
        }
        
        # Maximum file size to analyze (1MB)
        self.max_file_size = 1024 * 1024

    def should_ignore_path(self, path: str) -> bool:
        """Check if a file or directory should be ignored."""
        path_lower = path.lower()
        
        # Check directory patterns
        for ignore_dir in self.ignore_dirs:
            if ignore_dir in path_lower:
                return True
        
        # Check file patterns
        for ignore_file in self.ignore_files:
            if ignore_file in path_lower:
                return True
        
        return False

    def collect_source_files(self, repo_path: str) -> List[str]:
        """
        Collect all source files from the repository, filtering intelligently.
        """
        source_files = []
        repo_path = Path(repo_path)
        
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file():
                # Skip ignored paths
                if self.should_ignore_path(str(file_path)):
                    continue
                
                # Check file size
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        continue
                except OSError:
                    continue
                
                # Detect language
                language = detect_language(str(file_path))
                if language != "unknown":
                    source_files.append(str(file_path))
        
        return source_files

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Unified analysis for ALL languages - single method approach.
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                return self._create_empty_analysis(file_path, 'unknown')
            
            # Detect language
            language = detect_language(file_path)
            
            # Language-specific patterns for function detection
            function_patterns = {
                'python': r'^\s*def\s+(\w+)\s*\(',
                'javascript': r'(?:function|const|let|var)\s+(\w+)\s*[=\(]',
                'typescript': r'(?:function|const|let|var)\s+(\w+)\s*[=\(]',
                'go': r'func\s+(\w+)\s*\(',
                'java': r'(?:public|private|protected)?\s+\w+\s+(\w+)\s*\(',
                'rust': r'fn\s+(\w+)\s*\(',
                'php': r'function\s+(\w+)\s*\(',
                'ruby': r'def\s+(\w+)',
                'shell': r'(\w+)\s*\(\)\s*\{',
                'c': r'(\w+)\s*\(',
                'cpp': r'(\w+)\s*\(',
                'csharp': r'(?:public|private|protected)?\s+\w+\s+(\w+)\s*\(',
            }
            
            # Class patterns
            class_patterns = {
                'python': r'^\s*class\s+(\w+)',
                'javascript': r'class\s+(\w+)',
                'typescript': r'class\s+(\w+)',
                'java': r'class\s+(\w+)',
                'csharp': r'class\s+(\w+)',
                'php': r'class\s+(\w+)',
                'ruby': r'class\s+(\w+)',
            }
            
            # Get patterns for this language
            func_pattern = function_patterns.get(language, r'(\w+)\s*\(')
            class_pattern = class_patterns.get(language, r'')
            
            # Extract functions
            functions = []
            for match in re.finditer(func_pattern, content, re.MULTILINE):
                line_start = content[:match.start()].count('\n') + 1
                functions.append({
                    'name': match.group(1) if match.groups() else match.group(0),
                    'line_start': line_start,
                    'pattern': match.group(0)
                })
            
            # Extract classes
            classes = []
            if class_pattern:
                for match in re.finditer(class_pattern, content, re.MULTILINE):
                    line_start = content[:match.start()].count('\n') + 1
                    classes.append({
                        'name': match.group(1),
                        'line_start': line_start,
                        'pattern': match.group(0)
                    })
            
            # Calculate complexity (simplified for all languages)
            complexity = self._calculate_complexity(content, language)
            
            # Detect issues
            issues = self._detect_issues(content, language, functions, classes)
            
            return {
                'path': file_path,
                'language': language,
                'lines': len(content.splitlines()),
                'characters': len(content),
                'functions': functions,
                'classes': classes,
                'complexity': complexity,
                'issues': issues,
                'content_preview': content[:500] + "..." if len(content) > 500 else content
            }
            
        except Exception as e:
            return self._create_error_analysis(file_path, str(e))

    def _calculate_complexity(self, content: str, language: str) -> int:
        """Calculate complexity for any language using common patterns."""
        complexity = 1  # Base complexity
        
        # Common complexity indicators
        complexity_patterns = [
            r'\bif\b', r'\bfor\b', r'\bwhile\b', r'\bswitch\b', r'\bcase\b',
            r'\bcatch\b', r'\bexcept\b', r'\belse\b', r'\belseif\b',
            r'\|\|', r'&&', r'\band\b', r'\bor\b'
        ]
        
        for pattern in complexity_patterns:
            complexity += len(re.findall(pattern, content, re.IGNORECASE))
        
        return complexity

    def _detect_issues(self, content: str, language: str, functions: List[Dict], classes: List[Dict]) -> List[str]:
        """Detect issues in any language."""
        issues = []
        
        # TODO/FIXME comments
        comment_patterns = {
            'python': r'#\s*(TODO|FIXME|HACK|XXX)',
            'javascript': r'//\s*(TODO|FIXME|HACK|XXX)',
            'typescript': r'//\s*(TODO|FIXME|HACK|XXX)',
            'go': r'//\s*(TODO|FIXME|HACK|XXX)',
            'java': r'//\s*(TODO|FIXME|HACK|XXX)',
            'rust': r'//\s*(TODO|FIXME|HACK|XXX)',
            'php': r'//\s*(TODO|FIXME|HACK|XXX)',
            'ruby': r'#\s*(TODO|FIXME|HACK|XXX)',
            'shell': r'#\s*(TODO|FIXME|HACK|XXX)',
            'c': r'//\s*(TODO|FIXME|HACK|XXX)',
            'cpp': r'//\s*(TODO|FIXME|HACK|XXX)',
            'csharp': r'//\s*(TODO|FIXME|HACK|XXX)',
        }
        
        pattern = comment_patterns.get(language, r'(TODO|FIXME|HACK|XXX)')
        todo_count = len(re.findall(pattern, content, re.IGNORECASE))
        if todo_count > 0:
            issues.append(f"Found {todo_count} TODO/FIXME comments")
        
        # Long functions (estimate based on function count vs lines)
        lines = len(content.splitlines())
        if functions and lines > 0:
            avg_lines_per_func = lines / len(functions)
            if avg_lines_per_func > 30:
                issues.append(f"Functions are quite long (avg {avg_lines_per_func:.1f} lines)")
        
        # Long files
        if lines > 500:
            issues.append(f"File is very long ({lines} lines)")
        
        # Empty files
        if lines == 0:
            issues.append("File is empty")
        
        # Potential hardcoded values
        hardcoded_patterns = [
            r'\b\d{4,}\b',  # Large numbers
            r'"[^"]{50,}"',  # Long strings
            r"'[^']{50,}'",  # Long strings
        ]
        
        for pattern in hardcoded_patterns:
            if len(re.findall(pattern, content)) > 5:
                issues.append("Many hardcoded values detected")
                break
        
        return issues

    def _create_empty_analysis(self, file_path: str, language: str) -> Dict[str, Any]:
        """Create analysis result for empty files."""
        return {
            'path': file_path,
            'language': language,
            'lines': 0,
            'characters': 0,
            'functions': [],
            'classes': [],
            'complexity': 0,
            'issues': ['File is empty'],
            'content_preview': ''
        }

    def _create_error_analysis(self, file_path: str, error: str) -> Dict[str, Any]:
        """Create analysis result for files with errors."""
        return {
            'path': file_path,
            'language': 'unknown',
            'lines': 0,
            'characters': 0,
            'functions': [],
            'classes': [],
            'complexity': 0,
            'issues': [f'Error analyzing file: {error}'],
            'content_preview': ''
        }

    def analyze_codebase(self, repo_path: str) -> Dict[str, Any]:
        """
        Main function: analyze entire codebase with unified approach.
        """
        print(f" Analyzing codebase: {repo_path}")
        
        # Collect source files
        source_files = self.collect_source_files(repo_path)
        print(f"📁 Found {len(source_files)} source files")
        
        # Analyze each file with unified method
        results = []
        language_stats = {}
        
        for file_path in source_files:
            result = self.analyze_file(file_path)  # Single method for all languages
            results.append(result)
            
            # Update language statistics
            language = result['language']
            if language not in language_stats:
                language_stats[language] = {'count': 0, 'lines': 0, 'issues': 0}
            language_stats[language]['count'] += 1
            language_stats[language]['lines'] += result['lines']
            language_stats[language]['issues'] += len(result['issues'])
        
        # Generate summary
        total_issues = sum(len(r['issues']) for r in results)
        total_lines = sum(r['lines'] for r in results)
        
        summary = {
            'repository': repo_path,
            'total_files': len(results),
            'total_lines': total_lines,
            'total_issues': total_issues,
            'languages': language_stats,
            'files': results
        }
        
        print(f"✅ Analysis complete: {len(results)} files, {total_lines} lines, {total_issues} issues")
        return summary


# Convenience function for backward compatibility
def analyze_codebase(repo_path: str) -> Dict[str, Any]:
    """Backward compatibility function."""
    analyzer = CodebaseAnalyzer()
    return analyzer.analyze_codebase(repo_path)


if __name__ == "__main__":
    # Test the parser
    import sys
    
    if len(sys.argv) > 1:
        repo_path = sys.argv[1]
    else:
        repo_path = "."  # Current directory
    
    analyzer = CodebaseAnalyzer()
    results = analyzer.analyze_codebase(repo_path)
    
    # Print summary
    print("\n" + "="*50)
    print("📊 UNIFIED ANALYSIS SUMMARY")
    print("="*50)
    print(f"Repository: {results['repository']}")
    print(f"Total files: {results['total_files']}")
    print(f"Total lines: {results['total_lines']}")
    print(f"Total issues: {results['total_issues']}")
    
    print("\n Language breakdown:")
    for lang, stats in results['languages'].items():
        print(f"  {lang}: {stats['count']} files, {stats['lines']} lines, {stats['issues']} issues")
    
    print("\n🚨 Top issues:")
    all_issues = []
    for file_result in results['files']:
        for issue in file_result['issues']:
            all_issues.append(f"{file_result['path']}: {issue}")
    
    for issue in all_issues[:10]:  # Show top 10 issues
        print(f"  - {issue}")

