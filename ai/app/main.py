"""
main.py
-------
FastAPI server for Bugsy AI backend that communicates with the Go CLI.
Provides comprehensive code analysis, summarization, insights, and error handling analysis.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(env_path)

# Debug: Vérifie que la clé est chargée
api_key = os.getenv("COHERE_API_KEY")
if api_key:
    print(f"✅ COHERE_API_KEY loaded: {api_key[:10]}...")
else:
    print("❌ COHERE_API_KEY not found!")

import asyncio
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import tempfile
import shutil
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import our modules
from github import clone_repository, cleanup_repository
from parser import CodebaseAnalyzer
from summarizer import CodeSummarizer
from insights import CodeInsights
from utils import detect_language

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Bugsy AI Backend",
    description="AI-powered code analysis backend for Bugsy CLI - Comprehensive code analysis, insights, and error handling detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize our analysis components
analyzer = CodebaseAnalyzer()
summarizer = CodeSummarizer(use_cohere=True, cohere_api_key=os.getenv("COHERE_API_KEY"))  # Configure with your API key
insights = CodeInsights()

# Pydantic models for request/response
class AnalysisRequest(BaseModel):
    """Request model for code analysis"""
    repo_url: Optional[str] = Field(None, description="GitHub repository URL")
    local_path: Optional[str] = Field(None, description="Local path to codebase")
    analysis_types: List[str] = Field(
        default=["structure", "insights", "summary", "error_handling"],
        description="Types of analysis to perform: structure, insights, summary, error_handling"
    )
    languages: Optional[List[str]] = Field(None, description="Specific languages to analyze")
    max_files: Optional[int] = Field(1000, description="Maximum number of files to analyze")
    include_summaries: Optional[bool] = Field(True, description="Include AI-generated summaries")

class AnalysisResponse(BaseModel):
    """Response model for analysis results"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str
    request_id: Optional[str] = None

class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = False
    error: Dict[str, Any]
    timestamp: str
    request_id: Optional[str] = None

# Global storage for analysis results (in production, use Redis or database)
analysis_cache = {}

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Bugsy AI Backend",
        "version": "1.0.0",
        "description": "AI-powered code analysis for bug detection and quality assessment",
        "endpoints": [
            "/analyze - Complete codebase analysis",
            "/analyze/github - GitHub repository analysis",
            "/analyze/local - Local codebase analysis",
            "/analyze/errors - Error handling analysis only",
            "/health - Detailed health check",
            "/docs - API documentation"
        ],
        "features": [
            "Multi-language code analysis",
            "AI-powered code summarization",
            "Bug and code smell detection",
            "Error handling pattern analysis",
            "Architecture insights",
            "Performance recommendations"
        ]
    }

@app.get("/health")
async def health_check():
    """Detailed health check with component status"""
    try:
        # Test component availability
        components_status = {
            "parser": "ready",
            "summarizer": "ready" if summarizer else "error",
            "insights": "ready",
            "github": "ready"
        }
        
        # Test basic functionality
        test_analysis = analyzer.analyze_codebase(".")
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": components_status,
            "test_analysis": {
                "files_analyzed": test_analysis.get("total_files", 0),
                "languages_detected": len(test_analysis.get("languages", []))
            },
            "memory_usage": "normal",
            "uptime": "active"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_codebase(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    Main analysis endpoint - analyzes either GitHub repo or local path
    """
    request_id = f"req_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        logger.info(f"Starting analysis request {request_id}")
        
        # Validate request
        if request.repo_url and request.local_path:
            raise HTTPException(
                status_code=400, 
                detail="Provide either repo_url OR local_path, not both"
            )
        
        if not request.repo_url and not request.local_path:
            raise HTTPException(
                status_code=400, 
                detail="Provide either repo_url or local_path"
            )
        
        # Determine analysis path
        if request.repo_url:
            logger.info(f"Cloning repository: {request.repo_url}")
            analysis_path = await clone_repository(request.repo_url)
            is_temp = True
        else:
            analysis_path = request.local_path
            is_temp = False
        
        # Perform comprehensive analysis
        logger.info(f"Performing analysis on: {analysis_path}")
        results = await perform_comprehensive_analysis(
            analysis_path, 
            request.analysis_types, 
            request.languages,
            request.max_files,
            request.include_summaries
        )
        
        # Cache results
        analysis_cache[request_id] = {
            "results": results,
            "timestamp": datetime.now().isoformat(),
            "path": analysis_path
        }
        
        # Cleanup temporary repository if needed
        if is_temp:
            background_tasks.add_task(cleanup_repository, analysis_path)
        
        logger.info(f"Analysis completed successfully for request {request_id}")
        
        return AnalysisResponse(
            success=True,
            message="Analysis completed successfully",
            data=results,
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"Analysis failed for request {request_id}: {e}")
        return AnalysisResponse(
            success=False,
            message="Analysis failed",
            error=str(e),
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )

@app.post("/analyze/github", response_model=AnalysisResponse)
async def analyze_github_repo(
    repo_url: str,
    analysis_types: List[str] = ["structure", "insights", "summary", "error_handling"],
    languages: Optional[List[str]] = None,
    max_files: int = 1000,
    include_summaries: bool = True,
    background_tasks: BackgroundTasks = None
):
    """
    Analyze a GitHub repository
    """
    request_id = f"github_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        logger.info(f"Starting GitHub analysis: {repo_url}")
        
        # Clone the repository
        repo_path = await clone_repository(repo_url)
        
        # Perform analysis
        results = await perform_comprehensive_analysis(
            repo_path, 
            analysis_types, 
            languages, 
            max_files,
            include_summaries
        )
        
        # Cache results
        analysis_cache[request_id] = {
            "results": results,
            "timestamp": datetime.now().isoformat(),
            "repo_url": repo_url
        }
        
        # Cleanup in background
        if background_tasks:
            background_tasks.add_task(cleanup_repository, repo_path)
        
        logger.info(f"GitHub analysis completed: {repo_url}")
        
        return AnalysisResponse(
            success=True,
            message=f"Analysis completed for {repo_url}",
            data=results,
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"GitHub analysis failed: {e}")
        return AnalysisResponse(
            success=False,
            message="GitHub analysis failed",
            error=str(e),
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )

@app.post("/analyze/local", response_model=AnalysisResponse)
async def analyze_local_path(
    local_path: str,
    analysis_types: List[str] = ["structure", "insights", "summary", "error_handling"],
    languages: Optional[List[str]] = None,
    max_files: int = 1000,
    include_summaries: bool = True
):
    """
    Analyze a local codebase
    """
    request_id = f"local_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        logger.info(f"Starting local analysis: {local_path}")
        
        if not os.path.exists(local_path):
            raise HTTPException(status_code=404, detail="Local path not found")
        
        # Perform analysis
        results = await perform_comprehensive_analysis(
            local_path, 
            analysis_types, 
            languages, 
            max_files,
            include_summaries
        )
        
        # Cache results
        analysis_cache[request_id] = {
            "results": results,
            "timestamp": datetime.now().isoformat(),
            "local_path": local_path
        }
        
        logger.info(f"Local analysis completed: {local_path}")
        
        return AnalysisResponse(
            success=True,
            message=f"Analysis completed for {local_path}",
            data=results,
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"Local analysis failed: {e}")
        return AnalysisResponse(
            success=False,
            message="Local analysis failed",
            error=str(e),
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )

@app.get("/analyze/errors")
async def analyze_error_handling_only(codebase_path: str):
    """
    Analyze only error handling patterns in the codebase
    """
    request_id = f"errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        logger.info(f"Starting error handling analysis: {codebase_path}")
        
        if not os.path.exists(codebase_path):
            raise HTTPException(status_code=404, detail="Codebase path not found")
        
        # Perform error handling analysis only
        error_analysis = insights.analyze_error_handling(codebase_path)
        
        logger.info(f"Error handling analysis completed: {codebase_path}")
        
        return AnalysisResponse(
            success=True,
            message="Error handling analysis completed",
            data={"error_handling": error_analysis},
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"Error handling analysis failed: {e}")
        return AnalysisResponse(
            success=False,
            message="Error handling analysis failed",
            error=str(e),
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        )

@app.get("/analyze/{analysis_id}")
async def get_analysis_result(analysis_id: str):
    """
    Retrieve cached analysis results
    """
    if analysis_id not in analysis_cache:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    cached_result = analysis_cache[analysis_id]
    
    return {
        "success": True,
        "data": cached_result["results"],
        "timestamp": cached_result["timestamp"],
        "request_id": analysis_id
    }

@app.get("/cache/clear")
async def clear_analysis_cache():
    """
    Clear the analysis cache
    """
    global analysis_cache
    cache_size = len(analysis_cache)
    analysis_cache.clear()
    
    return {
        "success": True,
        "message": f"Cache cleared. Removed {cache_size} entries.",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/cache/status")
async def get_cache_status():
    """
    Get cache status and statistics
    """
    return {
        "cache_size": len(analysis_cache),
        "cache_entries": list(analysis_cache.keys()),
        "timestamp": datetime.now().isoformat()
    }

async def perform_comprehensive_analysis(
    codebase_path: str,
    analysis_types: List[str],
    languages: Optional[List[str]] = None,
    max_files: int = 1000,
    include_summaries: bool = True
) -> Dict[str, Any]:
    """
    Perform comprehensive code analysis
    """
    results = {
        "codebase_path": codebase_path,
        "analysis_types": analysis_types,
        "timestamp": datetime.now().isoformat(),
        "summary": {},
        "structure": {},
        "insights": {},
        "error_handling": {},
        "summaries": {},
        "files": {},
        "recommendations": []
    }
    
    try:
        # 1. Structure Analysis
        if "structure" in analysis_types:
            logger.info("🔍 Performing structure analysis...")
            structure_analysis = analyzer.analyze_codebase(codebase_path)
            results["structure"] = structure_analysis
            results["summary"]["total_files"] = structure_analysis.get("total_files", 0)
            results["summary"]["languages"] = structure_analysis.get("languages", {})
        
        # 2. Insights Analysis (Bugs, TODOs, Smells)
        if "insights" in analysis_types:
            logger.info(" Performing insights analysis...")
            insights_analysis = insights.analyze_codebase(codebase_path)
            results["insights"] = insights_analysis
            results["summary"]["total_issues"] = insights_analysis.get("summary", {}).get("total_issues", 0)
            results["summary"]["critical_issues"] = len(insights_analysis.get("critical_issues", []))
        
        # 3. Error Handling Analysis
        if "error_handling" in analysis_types:
            logger.info("🚨 Performing error handling analysis...")
            error_analysis = insights.analyze_error_handling(codebase_path)
            results["error_handling"] = error_analysis
            results["summary"]["error_handling_issues"] = error_analysis.get("summary", {}).get("total_issues", 0)
        
        # 4. Summary Analysis (AI-generated)
        if "summary" in analysis_types and include_summaries:
            logger.info("📝 Generating AI summaries...")
            summary_results = await generate_summaries(codebase_path, max_files)
            results["summaries"] = summary_results
        
        # 5. File-level Analysis
        if "files" in analysis_types:
            logger.info("📄 Performing file-level analysis...")
            file_analysis = await analyze_individual_files(codebase_path, languages, max_files)
            results["files"] = file_analysis
        
        # 6. Generate overall recommendations
        results["recommendations"] = generate_overall_recommendations(results)
        
        logger.info("✅ Comprehensive analysis completed successfully")
        return results
        
    except Exception as e:
        logger.error(f"❌ Error during comprehensive analysis: {e}")
        raise e

async def generate_summaries(codebase_path: str, max_files: int) -> Dict[str, str]:
    """
    Generate summaries for key files in the codebase
    """
    summaries = {}
    
    try:
        # Get important files (main files, README, etc.)
        important_files = [
            "README.md", "README.txt", "main.py", "app.py", "index.js",
            "main.go", "main.rs", "package.json", "Cargo.toml", "go.mod",
            "requirements.txt", "Dockerfile", "docker-compose.yml"
        ]
        
        for filename in important_files:
            file_path = os.path.join(codebase_path, filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if len(content.strip()) > 0:
                        language = detect_language(file_path)
                        summary = summarizer.summarize_file(content, language)
                        summaries[filename] = summary
                        
                        if len(summaries) >= max_files:
                            break
                            
                except Exception as e:
                    logger.warning(f"⚠️  Error summarizing {filename}: {e}")
        
        return summaries
        
    except Exception as e:
        logger.error(f"❌ Error generating summaries: {e}")
        return {}

async def analyze_individual_files(
    codebase_path: str,
    languages: Optional[List[str]] = None,
    max_files: int = 1000
) -> Dict[str, Dict[str, Any]]:
    """
    Analyze individual files in the codebase
    """
    file_analyses = {}
    
    try:
        file_count = 0
        
        for root, dirs, files in os.walk(codebase_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in analyzer.ignore_dirs]
            
            for file in files:
                if file_count >= max_files:
                    break
                
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, codebase_path)
                
                # Check if we should analyze this file
                if not analyzer._should_analyze_file(Path(file_path)):
                    continue
                
                # Check language filter
                if languages:
                    file_language = detect_language(file_path)
                    if file_language not in languages:
                        continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Analyze file
                    language = detect_language(file_path)
                    file_analysis = analyzer.analyze_file(file_path, content, language)
                    insights_analysis = insights.analyze_file(file_path, content, language)
                    
                    # Generate summary if content is substantial
                    summary = None
                    if len(content.strip()) > 100:
                        try:
                            summary = summarizer.summarize_file(content, language)
                        except Exception as e:
                            logger.warning(f"⚠️  Error summarizing {relative_path}: {e}")
                    
                    file_analyses[relative_path] = {
                        "path": relative_path,
                        "language": language,
                        "lines": len(content.split('\n')),
                        "complexity": file_analysis.get("complexity", 0),
                        "functions": file_analysis.get("functions", []),
                        "classes": file_analysis.get("classes", []),
                        "issues": [insight.__dict__ for insight in insights_analysis],
                        "summary": summary
                    }
                    
                    file_count += 1
                    
                except Exception as e:
                    logger.warning(f"⚠️  Error analyzing {relative_path}: {e}")
        
        return file_analyses
        
    except Exception as e:
        logger.error(f"❌ Error analyzing individual files: {e}")
        return {}

def generate_overall_recommendations(results: Dict[str, Any]) -> List[str]:
    """
    Generate overall recommendations based on analysis results
    """
    recommendations = []
    
    # Get insights from analysis
    insights_data = results.get("insights", {})
    error_handling_data = results.get("error_handling", {})
    summary_data = results.get("summary", {})
    
    # Critical issues
    critical_count = summary_data.get("critical_issues", 0)
    if critical_count > 0:
        recommendations.append(f"🔴 CRITICAL: {critical_count} critical issues found - immediate attention required")
    
    # Security issues
    security_issues = insights_data.get("summary", {}).get("issues_by_type", {}).get("security", 0)
    if security_issues > 0:
        recommendations.append(f"🛡️  SECURITY: {security_issues} security issues detected - conduct security review")
    
    # Performance issues
    performance_issues = insights_data.get("summary", {}).get("issues_by_type", {}).get("performance", 0)
    if performance_issues > 3:
        recommendations.append(f"⚡ PERFORMANCE: {performance_issues} performance issues - optimize critical paths")
    
    # Error handling issues
    error_handling_issues = summary_data.get("error_handling_issues", 0)
    if error_handling_issues > 10:
        recommendations.append(f"🚨 ERROR HANDLING: {error_handling_issues} error handling issues - improve error management")
    
    # Code quality
    total_issues = summary_data.get("total_issues", 0)
    total_files = summary_data.get("total_files", 1)
    issue_density = total_issues / total_files
    
    if issue_density > 2:
        recommendations.append(f"📊 QUALITY: High issue density ({issue_density:.1f} issues/file) - consider refactoring")
    
    # TODO items
    todo_count = insights_data.get("summary", {}).get("issues_by_type", {}).get("todo", 0)
    if todo_count > 10:
        recommendations.append(f" TODO: {todo_count} TODO items - prioritize and address technical debt")
    
    # File structure
    languages = summary_data.get("languages", {})
    if len(languages) > 5:
        recommendations.append(f" COMPLEXITY: {len(languages)} languages detected - consider simplifying tech stack")
    
    return recommendations

# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with detailed error information"""
    request_id = f"error_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Log the error
    logger.error(f"Unhandled exception in request {request_id}: {exc}")
    logger.error(f"Request path: {request.url.path}")
    logger.error(f"Request method: {request.method}")
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error={
                "type": type(exc).__name__,
                "message": str(exc),
                "request_id": request_id,
                "path": str(request.url.path),
                "method": request.method
            },
            timestamp=datetime.now().isoformat(),
            request_id=request_id
        ).dict()
    )

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    logger.info("🚀 Bugsy AI Backend starting up...")
    logger.info("✅ All components initialized")
    logger.info("📚 API Documentation available at /docs")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Bugsy AI Backend shutting down...")
    # Clear cache
    analysis_cache.clear()

# Run the server
if __name__ == "__main__":
    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    logger.info(f"🌐 Starting Bugsy AI Backend on {host}:{port}")
    logger.info(f" API Documentation: http://{host}:{port}/docs")
    logger.info(f"❤️  Health Check: http://{host}:{port}/health")
    logger.info(f" Debug mode: {debug}")
    
    # Start the server
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
