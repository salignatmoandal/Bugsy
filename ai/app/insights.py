"""
insights.py
-----------
Advanced code analysis module for Bugsy that detects bugs, TODOs, and code smells
using regex patterns and heuristics across multiple programming languages.
"""

import re
import ast
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

class IssueType(Enum):
    """Types of issues that can be detected"""
    BUG = "bug"
    TODO = "todo"
    SMELL = "smell"
    SECURITY = "security"
    PERFORMANCE = "performance"

@dataclass
class CodeIssue:
    """Represents a detected code issue"""
    type: IssueType
    category: str
    line: int
    column: int
    message: str
    code: str
    context: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    confidence: float  # 0.0 to 1.0

class CodeInsights:
    """
    Advanced code analysis engine that detects bugs, TODOs, and code smells
    using regex patterns and heuristics.
    """
    
    def __init__(self):
        # Initialize pattern dictionaries
        self.bug_patterns = self._init_bug_patterns()
        self.todo_patterns = self._init_todo_patterns()
        self.smell_patterns = self._init_smell_patterns()
        self.security_patterns = self._init_security_patterns()
        self.performance_patterns = self._init_performance_patterns()
        
        # Language-specific patterns
        self.language_patterns = self._init_language_patterns()
        
        # Error handling patterns
        self.error_handling_patterns = self._init_error_handling_patterns()
    
    def _init_bug_patterns(self) -> Dict[str, str]:
        """Initialize patterns for bug detection"""
        return {
            # Null pointer dereference
            'null_pointer': r'\b\w+\s*\.\s*\w+\s*\([^)]*\)',
            
            # Unhandled exceptions
            'unhandled_exception': r'try\s*:\s*\n(?!\s*except)',
            
            # Potential infinite loops
            'infinite_loop': r'while\s+True\s*:',
            
            # Division by zero potential
            'division_by_zero': r'/\s*\w+',
            
            # Array access without bounds checking
            'array_bounds': r'\w+\[\s*\w+\s*\]',
            
            # Uninitialized variables
            'uninitialized_var': r'(\w+)\s*=\s*(\1)',
            
            # Dead code (unreachable)
            'dead_code': r'return\s+[^;]*;\s*\n\s*\w+',
            
            # Missing return statement
            'missing_return': r'def\s+\w+[^:]*:\s*\n(?!\s*return)',
        }
    
    def _init_todo_patterns(self) -> Dict[str, str]:
        """Initialize patterns for TODO detection"""
        return {
            'todo': r'(?i)TODO[:\s]*([^\n]*)',
            'fixme': r'(?i)FIXME[:\s]*([^\n]*)',
            'hack': r'(?i)HACK[:\s]*([^\n]*)',
            'note': r'(?i)NOTE[:\s]*([^\n]*)',
            'xxx': r'(?i)XXX[:\s]*([^\n]*)',
            'bug': r'(?i)BUG[:\s]*([^\n]*)',
            'improve': r'(?i)IMPROVE[:\s]*([^\n]*)',
            'optimize': r'(?i)OPTIMIZE[:\s]*([^\n]*)',
        }
    
    def _init_smell_patterns(self) -> Dict[str, str]:
        """Initialize patterns for code smell detection"""
        return {
            # Long functions (>50 lines)
            'long_function': r'def\s+\w+[^:]*:\s*\n(?:[^\n]*\n){50,}',
            
            # Magic numbers
            'magic_number': r'\b\d{3,}\b',
            
            # Deep nesting
            'deep_nesting': r'(?:if|for|while|try)\s*[^:]*:\s*\n(?:[^\n]*\n)*?(?:if|for|while|try)\s*[^:]*:\s*\n(?:[^\n]*\n)*?(?:if|for|while|try)\s*[^:]*:',
            
            # Large classes
            'large_class': r'class\s+\w+[^}]*\n(?:[^}]*\n){100,}',
            
            # Duplicate code (simplified)
            'duplicate_code': r'(\w+\([^)]*\)[^;]*;?\s*){3,}',
            
            # Long parameter lists
            'long_params': r'def\s+\w+\s*\([^)]{100,}\)',
            
            # Commented code
            'commented_code': r'#\s*(?:def|class|if|for|while)\s+',
            
            # Hardcoded strings
            'hardcoded_strings': r'[\'"][^\'"]{50,}[\'"]',
        }
    
    def _init_security_patterns(self) -> Dict[str, str]:
        """Initialize patterns for security issues"""
        return {
            # SQL injection
            'sql_injection': r'execute\s*\(\s*[\'"]\s*\+\s*\w+',
            
            # Command injection
            'command_injection': r'(?:os\.system|subprocess\.call)\s*\(\s*\w+',
            
            # Hardcoded credentials
            'hardcoded_creds': r'(?i)(?:password|secret|key|token)\s*=\s*[\'"][^\'"]+[\'"]',
            
            # Weak encryption
            'weak_encryption': r'(?i)md5|sha1',
            
            # Debug information exposure
            'debug_exposure': r'(?i)console\.log|print\s*\(|debug\s*\(|dump\s*\(',
        }
    
    def _init_performance_patterns(self) -> Dict[str, str]:
        """Initialize patterns for performance issues"""
        return {
            # N+1 queries
            'n_plus_one': r'for\s+\w+\s+in\s+\w+:\s*\n\s*\w+\.query\(',
            
            # Inefficient loops
            'inefficient_loop': r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(',
            
            # Memory leaks
            'memory_leak': r'new\s+\w+\(\s*\)',
            
            # Unused imports
            'unused_import': r'import\s+\w+',
            
            # Large data structures
            'large_data': r'\[\s*[^\]]{1000,}\s*\]',
        }
    
    def _init_language_patterns(self) -> Dict[str, Dict[str, str]]:
        """Initialize language-specific patterns"""
        return {
            'python': {
                'indentation_error': r'^\s*\w+\s*:',
                'unused_variable': r'_\w+\s*=',
                'missing_docstring': r'def\s+\w+[^:]*:\s*\n(?!\s*[\'"])',
            },
            'javascript': {
                'var_hoisting': r'var\s+\w+',
                'undefined_check': r'==\s*undefined',
                'eval_usage': r'eval\s*\(',
            },
            'go': {
                'unused_import': r'import\s+_\s+[\'"][^\'"]+[\'"]',
                'error_ignored': r'_\s*=\s*\w+\.\w+\(',
            }
        }
    
    def _init_error_handling_patterns(self) -> Dict[str, str]:
        """Initialize patterns for error handling analysis"""
        return {
            # Empty or poor error handling
            'empty_catch': r'try\s*{[^}]*}\s*catch\s*\([^)]*\)\s*{\s*}',
            'catch_all': r'catch\s*\(\s*Exception\s*\)',
            'swallowed_exception': r'catch\s*\([^)]*\)\s*{\s*//\s*ignore|catch\s*\([^)]*\)\s*{\s*pass',
            
            # Missing error handling
            'missing_error_handling': r'(\w+\([^)]*\)[^;]*;)(?!\s*try)',
            'unchecked_operation': r'(\w+\.\w+\([^)]*\)[^;]*;)(?!\s*try)',
            
            # Poor error messages
            'poor_error_messages': r'throw\s+new\s+\w+Exception\s*\(\s*[\'"]\w+[\'"]\s*\)',
            'generic_error': r'throw\s+new\s+Exception\s*\(\s*[\'"]error[\'"]\s*\)',
            
            # Resource management
            'resource_leak': r'new\s+\w+\([^)]*\)(?!\s*try)',
            'unclosed_resource': r'FileInputStream|FileOutputStream|BufferedReader',
            
            # Exception handling patterns
            'unchecked_exception': r'throws\s+\w+Exception',
            'silent_failure': r'catch\s*\([^)]*\)\s*{\s*return\s+null\s*;',
            'error_ignored': r'catch\s*\([^)]*\)\s*{\s*_\s*=\s*\w+',
        }
    
    def analyze_file(self, file_path: str, content: str, language: str = None) -> List[CodeIssue]:
        """
        Analyze a single file and return all detected issues.
        
        Args:
            file_path: Path to the file being analyzed
            content: File content as string
            language: Programming language (auto-detected if None)
            
        Returns:
            List of CodeIssue objects
        """
        if language is None:
            language = self._detect_language(file_path)
        
        issues = []
        
        # Analyze all pattern categories
        pattern_categories = [
            (IssueType.BUG, self.bug_patterns),
            (IssueType.TODO, self.todo_patterns),
            (IssueType.SMELL, self.smell_patterns),
            (IssueType.SECURITY, self.security_patterns),
            (IssueType.PERFORMANCE, self.performance_patterns),
        ]
        
        for issue_type, patterns in pattern_categories:
            for category, pattern in patterns.items():
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    issue = self._create_issue(
                        issue_type=issue_type,
                        category=category,
                        match=match,
                        content=content,
                        file_path=file_path,
                        language=language
                    )
                    if issue:
                        issues.append(issue)
        
        # Add language-specific analysis
        if language in self.language_patterns:
            for category, pattern in self.language_patterns[language].items():
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    issue = self._create_issue(
                        issue_type=IssueType.SMELL,
                        category=f"{language}_{category}",
                        match=match,
                        content=content,
                        file_path=file_path,
                        language=language
                    )
                    if issue:
                        issues.append(issue)
        
        return issues
    
    def _create_issue(self, issue_type: IssueType, category: str, match: re.Match, 
                     content: str, file_path: str, language: str) -> Optional[CodeIssue]:
        """Create a CodeIssue object from a regex match"""
        try:
            line_num = content[:match.start()].count('\n') + 1
            column_num = match.start() - content.rfind('\n', 0, match.start())
            
            # Get context (3 lines before and after)
            lines = content.split('\n')
            start_line = max(0, line_num - 4)
            end_line = min(len(lines), line_num + 2)
            context = '\n'.join(lines[start_line:end_line])
            
            # Determine severity and confidence
            severity, confidence = self._assess_severity(issue_type, category, match.group())
            
            return CodeIssue(
                type=issue_type,
                category=category,
                line=line_num,
                column=column_num,
                message=self._generate_message(issue_type, category, match.group()),
                code=match.group(),
                context=context,
                severity=severity,
                confidence=confidence
            )
        except Exception as e:
            print(f"Error creating issue: {e}")
            return None
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = Path(file_path).suffix.lower()
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.go': 'go',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby',
        }
        return language_map.get(ext, 'unknown')
    
    def _assess_severity(self, issue_type: IssueType, category: str, code: str) -> tuple:
        """Assess the severity and confidence of an issue"""
        # Base severity mapping
        severity_map = {
            IssueType.SECURITY: 'high',
            IssueType.BUG: 'medium',
            IssueType.PERFORMANCE: 'medium',
            IssueType.SMELL: 'low',
            IssueType.TODO: 'low',
        }
        
        # Adjust based on specific patterns
        if 'sql_injection' in category or 'command_injection' in category:
            return 'critical', 0.9
        elif 'infinite_loop' in category:
            return 'high', 0.8
        elif 'null_pointer' in category:
            return 'high', 0.7
        
        base_severity = severity_map.get(issue_type, 'low')
        confidence = 0.6  # Default confidence
        
        return base_severity, confidence
    
    def _generate_message(self, issue_type: IssueType, category: str, code: str) -> str:
        """Generate a human-readable message for the issue"""
        messages = {
            'null_pointer': 'Potential null pointer dereference',
            'unhandled_exception': 'Unhandled exception in try block',
            'infinite_loop': 'Potential infinite loop detected',
            'division_by_zero': 'Potential division by zero',
            'array_bounds': 'Array access without bounds checking',
            'sql_injection': 'Potential SQL injection vulnerability',
            'command_injection': 'Potential command injection vulnerability',
            'hardcoded_creds': 'Hardcoded credentials detected',
            'long_function': 'Function is too long (consider breaking it down)',
            'magic_number': 'Magic number detected (consider using a named constant)',
            'deep_nesting': 'Deep nesting detected (consider refactoring)',
            'todo': 'TODO item found',
            'fixme': 'FIXME item found',
        }
        
        return messages.get(category, f'{issue_type.value.title()}: {category}')
    
    def analyze_codebase(self, root_path: str) -> Dict[str, Any]:
        """
        Analyze an entire codebase and return comprehensive insights including error handling.
        """
        results = {
            "summary": {
                "total_files": 0,
                "total_issues": 0,
                "issues_by_type": {},
                "issues_by_severity": {},
                "files_with_issues": 0,
            },
            "files": {},
            "critical_issues": [],
            "recommendations": []
        }
        
        # Walk through all files
        for file_path in Path(root_path).rglob('*'):
            if file_path.is_file() and self._should_analyze_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    issues = self.analyze_file(file_path, content)
                    
                    if issues:
                        results["files"][str(file_path)] = {
                            "issues": [self._issue_to_dict(issue) for issue in issues],
                            "issue_count": len(issues)
                        }
                        results["summary"]["files_with_issues"] += 1
                        
                        # Update summary statistics
                        for issue in issues:
                            results["summary"]["total_issues"] += 1
                            results["summary"]["issues_by_type"][issue.type.value] = \
                                results["summary"]["issues_by_type"].get(issue.type.value, 0) + 1
                            results["summary"]["issues_by_severity"][issue.severity] = \
                                results["summary"]["issues_by_severity"].get(issue.severity, 0) + 1
                            
                            if issue.severity == 'critical':
                                results["critical_issues"].append(self._issue_to_dict(issue))
                
                    results["summary"]["total_files"] += 1
                    
                except Exception as e:
                    print(f"Error analyzing {file_path}: {e}")
        
        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results)
        
        # Add error handling analysis
        print("🔍 Analyzing error handling patterns...")
        results['error_handling'] = self.analyze_error_handling(root_path)
        
        return results
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed"""
        # Skip binary files and build artifacts
        skip_patterns = [
            '__pycache__', 'node_modules', '.git', '.venv', 'venv',
            'vendor', 'target', 'build', 'dist', '.next', 'coverage',
            '.min.js', '.min.css', '.map', '.pyc', '.o', '.so', '.dll'
        ]
        
        for pattern in skip_patterns:
            if pattern in str(file_path):
                return False
        
        # Only analyze source code files
        source_extensions = {'.py', '.js', '.ts', '.go', '.java', '.cpp', '.c', '.rs', '.php', '.rb'}
        return file_path.suffix.lower() in source_extensions
    
    def _issue_to_dict(self, issue: CodeIssue) -> Dict[str, Any]:
        """Convert CodeIssue to dictionary for JSON serialization"""
        return {
            'type': issue.type.value,
            'category': issue.category,
            'line': issue.line,
            'column': issue.column,
            'message': issue.message,
            'code': issue.code,
            'context': issue.context,
            'severity': issue.severity,
            'confidence': issue.confidence
        }
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis results"""
        recommendations = []
        
        summary = results['summary']
        
        if summary['issues_by_severity'].get('critical', 0) > 0:
            recommendations.append("🔴 CRITICAL: Address security vulnerabilities immediately")
        
        if summary['issues_by_severity'].get('high', 0) > 5:
            recommendations.append("🟠 HIGH: Multiple high-severity issues detected - review code quality")
        
        if summary['issues_by_type'].get('security', 0) > 0:
            recommendations.append("�� SECURITY: Security issues found - conduct security review")
        
        if summary['issues_by_type'].get('performance', 0) > 3:
            recommendations.append("⚡ PERFORMANCE: Performance issues detected - optimize critical paths")
        
        if summary['issues_by_type'].get('todo', 0) > 10:
            recommendations.append("📝 TODO: Many TODO items - consider task prioritization")
        
        return recommendations
    
    def analyze_error_handling(self, codebase_path: str) -> Dict[str, Any]:
        """
        Analyze error handling patterns in the codebase
        """
        error_analysis = {
            "error_handlers": [],
            "try_catch_blocks": [],
            "error_patterns": [],
            "recommendations": [],
            "summary": {
                "total_issues": 0,
                "files_with_issues": 0,
                "critical_issues": 0,
                "categories": {}
            }
        }
        
        category_counts = {}
        
        for file_path in Path(codebase_path).rglob('*'):
            if file_path.is_file() and self._should_analyze_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    file_issues = []
                    
                    # Analyze error handling patterns
                    for pattern_name, pattern in self.error_handling_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            column_num = match.start() - content.rfind('\n', 0, match.start())
                            
                            # Get context
                            lines = content.split('\n')
                            start_line = max(0, line_num - 2)
                            end_line = min(len(lines), line_num + 2)
                            context = '\n'.join(lines[start_line:end_line])
                            
                            issue = {
                                'type': pattern_name,
                                'line': line_num,
                                'column': column_num,
                                'code': match.group(),
                                'context': context,
                                'message': self._get_error_handling_message(pattern_name),
                                'severity': self._get_error_handling_severity(pattern_name),
                                'suggestions': self._get_error_handling_suggestions(pattern_name)
                            }
                            
                            file_issues.append(issue)
                            
                            # Update category counts
                            category = self._get_error_category(pattern_name)
                            category_counts[category] = category_counts.get(category, 0) + 1
                    
                    if file_issues:
                        error_analysis["error_handlers"].append({
                            "file": str(file_path),
                            "issues": file_issues,
                            "issue_count": len(file_issues)
                        })
                        error_analysis["summary"]["files_with_issues"] += 1
                        error_analysis["summary"]["total_issues"] += len(file_issues)
                        
                except Exception as e:
                    print(f"Error analyzing {file_path}: {e}")
        
        # Update summary
        error_analysis["summary"]["categories"] = category_counts
        error_analysis["summary"]["critical_issues"] = sum(
            1 for file_info in error_analysis["error_handlers"]
            for issue in file_info["issues"]
            if issue["severity"] == "critical"
        )
        
        # Generate recommendations
        error_analysis["recommendations"] = self._generate_error_handling_recommendations(error_analysis)
        
        return error_analysis
    
    def _get_error_handling_message(self, pattern_type: str) -> str:
        """Get message for error handling pattern"""
        messages = {
            'empty_catch': 'Empty catch block - add proper error handling',
            'catch_all': 'Catching all exceptions - be more specific',
            'swallowed_exception': 'Exception is being swallowed - log or handle properly',
            'missing_error_handling': 'Missing error handling for operation',
            'unchecked_operation': 'Unchecked operation without error handling',
            'poor_error_messages': 'Generic error message - provide more context',
            'generic_error': 'Generic exception thrown - use specific exception types',
            'resource_leak': 'Potential resource leak - use try-with-resources',
            'unclosed_resource': 'Resource may not be properly closed',
            'unchecked_exception': 'Unchecked exception - consider checked exception',
            'silent_failure': 'Silent failure - add proper error handling',
            'error_ignored': 'Error is being ignored - handle or log the error'
        }
        return messages.get(pattern_type, f'Error handling issue: {pattern_type}')
    
    def _get_error_handling_severity(self, pattern_type: str) -> str:
        """Get severity for error handling pattern"""
        severity_map = {
            'empty_catch': 'high',
            'catch_all': 'medium',
            'swallowed_exception': 'high',
            'missing_error_handling': 'medium',
            'unchecked_operation': 'medium',
            'poor_error_messages': 'low',
            'generic_error': 'medium',
            'resource_leak': 'critical',
            'unclosed_resource': 'high',
            'unchecked_exception': 'low',
            'silent_failure': 'high',
            'error_ignored': 'medium'
        }
        return severity_map.get(pattern_type, 'medium')
    
    def _get_error_category(self, pattern_type: str) -> str:
        """Get category for error handling pattern"""
        category_map = {
            'empty_catch': 'poor_handling',
            'catch_all': 'poor_handling',
            'swallowed_exception': 'poor_handling',
            'missing_error_handling': 'missing_handling',
            'unchecked_operation': 'missing_handling',
            'poor_error_messages': 'poor_messages',
            'generic_error': 'poor_messages',
            'resource_leak': 'resource_management',
            'unclosed_resource': 'resource_management',
            'unchecked_exception': 'exception_design',
            'silent_failure': 'poor_handling',
            'error_ignored': 'poor_handling'
        }
        return category_map.get(pattern_type, 'other')
    
    def _get_error_handling_suggestions(self, pattern_type: str) -> List[str]:
        """Get suggestions for error handling pattern"""
        suggestions = {
            'empty_catch': [
                'Add proper error handling logic',
                'Log the exception for debugging',
                'Consider if the exception should be re-thrown'
            ],
            'catch_all': [
                'Catch specific exception types instead of Exception',
                'Handle different exception types differently',
                'Add logging for unexpected exceptions'
            ],
            'swallowed_exception': [
                'Log the exception before ignoring',
                'Consider if the exception should be handled',
                'Add a comment explaining why the exception is ignored'
            ],
            'missing_error_handling': [
                'Wrap the operation in a try-catch block',
                'Add error handling for potential failures',
                'Consider using defensive programming'
            ],
            'resource_leak': [
                'Use try-with-resources (Java) or context managers (Python)',
                'Ensure resources are properly closed in finally blocks',
                'Consider using resource management libraries'
            ],
            'poor_error_messages': [
                'Provide specific error messages',
                'Include relevant context in error messages',
                'Use error codes for programmatic handling'
            ]
        }
        return suggestions.get(pattern_type, ['Review error handling best practices'])
    
    def _generate_error_handling_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations for error handling"""
        recommendations = []
        
        summary = analysis["summary"]
        total_issues = summary["total_issues"]
        critical_issues = summary["critical_issues"]
        categories = summary["categories"]
        
        if critical_issues > 0:
            recommendations.append(f"🚨 CRITICAL: {critical_issues} critical error handling issues - immediate attention required")
        
        if total_issues > 20:
            recommendations.append(f"⚠️  ERROR HANDLING: {total_issues} error handling issues - conduct comprehensive review")
        
        if categories.get('resource_management', 0) > 3:
            recommendations.append("💧 RESOURCES: Multiple resource management issues - implement proper cleanup")
        
        if categories.get('poor_handling', 0) > 10:
            recommendations.append("🛠️  HANDLING: Many poor error handling patterns - improve error handling practices")
        
        if categories.get('missing_handling', 0) > 5:
            recommendations.append("❌ MISSING: Missing error handling in multiple places - add proper error handling")
        
        return recommendations

class AdvancedCodeInsights(CodeInsights):
    """
    Enhanced code insights with comprehensive refactoring detection
    """
    
    def __init__(self):
        super().__init__()
        self.refactoring_patterns = self._init_refactoring_patterns()
        self.solid_patterns = self._init_solid_patterns()
        self.architecture_patterns = self._init_architecture_patterns()
        self.legacy_patterns = self._init_legacy_patterns()
    
    def _init_refactoring_patterns(self) -> Dict[str, str]:
        """Patterns for refactoring opportunities"""
        return {
            # Extract Method opportunities
            'extract_method': r'(\w+\s*\([^)]*\)\s*{[^}]{100,})',
            
            # Extract Class opportunities
            'extract_class': r'class\s+\w+\s*{[^}]{200,}',
            
            # Replace Magic Numbers
            'magic_numbers': r'\b\d{2,}\b(?!\s*[;,)])',
            
            # Replace Conditional with Polymorphism
            'conditional_polymorphism': r'if\s*\(\w+\s*instanceof\s+\w+\)',
            
            # Introduce Parameter Object
            'parameter_object': r'def\s+\w+\s*\([^)]{50,}\)',
            
            # Replace Array with Object
            'array_to_object': r'\w+\[\d+\]\s*=\s*\w+',
            
            # Duplicate Code
            'duplicate_code': r'(\w+\([^)]*\)[^;]*;?\s*){3,}',
            
            # Long Parameter List
            'long_parameters': r'\([^)]{80,}\)',
            
            # Data Clumps
            'data_clumps': r'(\w+,\s*\w+,\s*\w+){3,}',
            
            # Primitive Obsession
            'primitive_obsession': r'String\s+\w+\s*=\s*[\'"][^\'"]+[\'"]',
            
            # Switch Statements
            'switch_statement': r'switch\s*\([^)]*\)\s*{[^}]{100,}',
            
            # Temporary Field
            'temporary_field': r'private\s+\w+\s+\w+\s*;\s*\n\s*//\s*temp',
            
            # Refused Bequest
            'refused_bequest': r'class\s+\w+\s+extends\s+\w+\s*{\s*//\s*empty',
            
            # Alternative Classes with Different Interfaces
            'alternative_classes': r'class\s+\w+\s*{\s*public\s+void\s+get\w+',
            
            # Incomplete Library Class
            'incomplete_library': r'//\s*TODO:\s*extend\s+\w+',
            
            # Data Class
            'data_class': r'class\s+\w+\s*{\s*(private\s+\w+\s+\w+;\s*\n\s*){3,}',
            
            # Comments
            'comment_code': r'//\s*(TODO|FIXME|HACK|XXX)',
            
            # Feature Envy
            'feature_envy': r'\w+\.\w+\(\)\.\w+\(\)\.\w+\(\)',
            
            # Inappropriate Intimacy
            'inappropriate_intimacy': r'private\s+\w+\s+\w+;\s*\n\s*public\s+void\s+set\w+',
            
            # Message Chains
            'message_chains': r'\w+\.\w+\(\)\.\w+\(\)\.\w+\(\)\.\w+\(\)',
            
            # Middle Man
            'middle_man': r'public\s+\w+\s+\w+\([^)]*\)\s*{\s*return\s+\w+\.\w+\([^)]*\);\s*}',
            
            # Parallel Inheritance Hierarchies
            'parallel_inheritance': r'class\s+\w+\s+extends\s+\w+\s*{\s*private\s+\w+\s+\w+;',
            
            # Lazy Class
            'lazy_class': r'class\s+\w+\s*{\s*//\s*empty\s*class',
            
            # Speculative Generality
            'speculative_generality': r'interface\s+\w+<T>\s*{\s*//\s*unused',
            
            # Temporary Field
            'temporary_field': r'private\s+\w+\s+\w+;\s*\n\s*//\s*temporary',
            
            # Comments
            'comments': r'//\s*[^\n]{50,}',
        }
    
    def _init_solid_patterns(self) -> Dict[str, str]:
        """Patterns for SOLID principle violations"""
        return {
            # Single Responsibility Principle
            'srp_violation': r'class\s+\w+\s*{\s*(public\s+void\s+\w+[^}]{100,}){3,}',
            
            # Open/Closed Principle
            'ocp_violation': r'if\s*\(\w+\s+instanceof\s+\w+\)\s*{\s*\w+\.\w+\(\)',
            
            # Liskov Substitution Principle
            'lsp_violation': r'@Override\s+public\s+\w+\s+\w+\([^)]*\)\s*{\s*throw\s+new\s+UnsupportedOperationException',
            
            # Interface Segregation Principle
            'isp_violation': r'interface\s+\w+\s*{\s*(void\s+\w+\([^)]*\);\s*){5,}',
            
            # Dependency Inversion Principle
            'dip_violation': r'new\s+\w+\([^)]*\)',
        }
    
    def _init_architecture_patterns(self) -> Dict[str, str]:
        """Patterns for architectural issues"""
        return {
            # Circular Dependencies
            'circular_dependency': r'import\s+\w+\.\w+\.\w+;\s*\n\s*import\s+\w+\.\w+\.\w+;',
            
            # God Classes
            'god_class': r'class\s+\w+\s*{\s*(private\s+\w+\s+\w+;\s*\n\s*){10,}',
            
            # Feature Envy
            'feature_envy': r'\w+\.\w+\(\)\.\w+\(\)\.\w+\(\)',
            
            # Data Clumps
            'data_clumps': r'(\w+,\s*\w+,\s*\w+){3,}',
            
            # Primitive Obsession
            'primitive_obsession': r'String\s+\w+\s*=\s*[\'"][^\'"]+[\'"]',
            
            # Switch Statements
            'switch_statement': r'switch\s*\([^)]*\)\s*{[^}]{100,}',
            
            # Lazy Class
            'lazy_class': r'class\s+\w+\s*{\s*//\s*empty\s*class',
            
            # Speculative Generality
            'speculative_generality': r'interface\s+\w+<T>\s*{\s*//\s*unused',
            
            # Temporary Field
            'temporary_field': r'private\s+\w+\s+\w+;\s*\n\s*//\s*temporary',
            
            # Comments
            'comments': r'//\s*[^\n]{50,}',
        }
    
    def _init_legacy_patterns(self) -> Dict[str, str]:
        """Patterns for legacy code and technical debt"""
        return {
            # Deprecated APIs
            'deprecated_api': r'@Deprecated|@deprecated',
            
            # Commented Code
            'commented_code': r'//\s*(?:public|private|protected|class|interface|enum)\s+\w+',
            
            # Unused Variables
            'unused_variable': r'private\s+\w+\s+\w+;\s*\n\s*//\s*unused',
            
            # Unused Imports
            'unused_import': r'import\s+\w+;\s*\n\s*//\s*unused',
            
            # Dead Code
            'dead_code': r'private\s+\w+\s+\w+\([^)]*\)\s*{\s*//\s*never\s+called',
            
            # Hardcoded Values
            'hardcoded_values': r'[\'"][^\'"]{20,}[\'"]',
            
            # Magic Numbers
            'magic_numbers': r'\b\d{2,}\b(?!\s*[;,)])',
            
            # TODO Comments
            'todo_comments': r'//\s*TODO[:\s]*([^\n]*)',
            
            # FIXME Comments
            'fixme_comments': r'//\s*FIXME[:\s]*([^\n]*)',
            
            # HACK Comments
            'hack_comments': r'//\s*HACK[:\s]*([^\n]*)',
            
            # XXX Comments
            'xxx_comments': r'//\s*XXX[:\s]*([^\n]*)',
        }

# Example usage and testing
if __name__ == "__main__":
    insights = CodeInsights()
    
    # Test with a sample codebase
    test_code = """
def process_data(data):
    # TODO: Add validation
    result = data / divisor  # Potential division by zero
    return result

class VeryLongClass:
    def __init__(self):
        pass
    # ... 100+ lines of code ...
    
# FIXME: This is too slow
for i in range(len(items)):
    process(items[i])
"""
    
    issues = insights.analyze_file("test.py", test_code, "python")
    
    print("🔍 Code Analysis Results:")
    print("=" * 50)
    
    for issue in issues:
        print(f"�� {issue.type.value.upper()}: {issue.message}")
        print(f"   �� Line {issue.line}: {issue.code}")
        print(f"   ⚠️  Severity: {issue.severity} (confidence: {issue.confidence:.1f})")
        print(f"   📝 Context: {issue.context.strip()}")
        print("-" * 30)