import sys
import os
import asyncio
import tempfile


# Add the app directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app')))

from github import clone_repository, extract_repo_name, cleanup_repository, get_repo_info

async def test_extract_repo_name():
    """Test the extract_repo_name function"""
    print("🚀 Testing extract_repo_name...")
    
    test_cases = [
        ("https://github.com/username/repo", "username/repo"),
        ("https://github.com/username/repo.git", "username/repo"),
        ("https://github.com/username/repo/", "username/repo"),
        ("git@github.com:username/repo.git", "username/repo"),
        ("git@github.com:username/repo", "username/repo"),
    ]
    
    for url, expected in test_cases:
        try:
            result = extract_repo_name(url)
            if result == expected:
                print(f"✅ {url} -> {result}")
            else:
                print(f"❌ {url} -> {result} (expected: {expected})")
        except Exception as e:
            print(f"❌ Error for {url}: {e}")
    
    print()

async def test_clone_repository():
    """Test the clone_repository function"""
    print("🧪 Testing clone_repository...")
    
    # Public test repositories (small and stable)
    test_repos = [
        "https://github.com/cohere-ai/tokenizers",  # GitHub test repository
        "https://github.com/PostHog/mcp",  # Microsoft repository
    ]
    
    for repo_url in test_repos:
        print(f"\n📥 Testing clone: {repo_url}")
        repo_path = None
        
        try:
            # Clone the repository
            repo_path = await clone_repository(repo_url)
            
            # Check if the directory exists
            if os.path.exists(repo_path):
                print(f"✅ Repository successfully cloned to: {repo_path}")
                
                # Get repository information
                info = get_repo_info(repo_path)
                print(f"📊 Repository information:")
                print(f"   - Name: {info.get('name', 'N/A')}")
                print(f"   - Branch: {info.get('branch', 'N/A')}")
                print(f"   - Commit count: {info.get('commit_count', 'N/A')}")
                print(f"   - File count: {info.get('file_count', 'N/A')}")
                print(f"   - Last commit: {info.get('last_commit', {}).get('message', 'N/A')[:50]}...")
                
                # List some files
                files = list_files_recursive(repo_path, max_files=5)
                print(f"   - Files found: {', '.join(files)}")
                
            else:
                print(f"❌ Cloned directory does not exist: {repo_path}")
                
        except Exception as e:
            print(f"❌ Error during cloning: {e}")
            
        finally:
            # Cleanup
            if repo_path and os.path.exists(repo_path):
                cleanup_repository(repo_path)
                print(f"🧹 Repository cleaned: {repo_path}")

def list_files_recursive(directory: str, max_files: int = 5) -> list:
    """List files in a directory recursively"""
    files = []
    for root, dirs, filenames in os.walk(directory):
        # Ignore .git
        if '.git' in dirs:
            dirs.remove('.git')
        
        for filename in filenames:
            if len(files) >= max_files:
                break
            rel_path = os.path.relpath(os.path.join(root, filename), directory)
            files.append(rel_path)
    
    return files

async def test_error_handling():
    """Test error handling"""
    print("\n⚠️ Testing error handling...")
    
    # Invalid URLs
    invalid_urls = [
        "https://github.com/nonexistent/repo",
        "https://invalid-url.com/repo",
        "not-a-url",
    ]
    
    for url in invalid_urls:
        print(f"\n📥 Testing with invalid URL: {url}")
        try:
            repo_path = await clone_repository(url)
            print(f"❌ Cloning should have failed for: {url}")
        except Exception as e:
            print(f"✅ Error properly handled: {e}")

async def test_cleanup():
    """Test the cleanup function"""
    print("\n🧹 Testing cleanup...")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="test_cleanup_")
    test_file = os.path.join(temp_dir, "test.txt")
    
    try:
        # Create a test file
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        print(f"📁 Temporary directory created: {temp_dir}")
        print(f"✅ Test file created: {test_file}")
        
        # Check if directory exists
        if os.path.exists(temp_dir):
            print("✅ Directory exists before cleanup")
        
        # Cleanup
        cleanup_repository(temp_dir)
        
        # Check if directory was deleted
        if not os.path.exists(temp_dir):
            print("✅ Directory properly deleted")
        else:
            print("❌ Directory was not deleted")
            
    except Exception as e:
        print(f"❌ Error during cleanup test: {e}")

async def main():
    """Main test function"""
    print("🚀 Starting tests for github.py")
    print("=" * 50)
    
    # Check dependencies
    try:
        import git
        print("✅ GitPython installed")
    except ImportError:
        print("❌ GitPython not installed. Install it with: pip install gitpython")
        return
    
    # Run tests
    await test_extract_repo_name()
    await test_clone_repository()
    await test_error_handling()
    await test_cleanup()
    
    print("\n" + "=" * 50)
    print("🎉 Tests completed!")

if __name__ == "__main__":
    # Run tests
    asyncio.run(main()) 