import git
import os 
import tempfile
import shutil
import re 

async def clone_repository(repo_url: str) -> str:
    """
    Clone a GitHub repository to a temporary directory.
    Args:
        repo_url: The URL of the GitHub repository to clone.
    Returns:
        The path to the cloned repository.
    """
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="bugsy_")

    try:
        # Extract the repository name from the URL
        repo_name = extract_repo_name(repo_url)
        # Clone the repository
        print(f"Cloning repository {repo_name} to {temp_dir}")
        git.Repo.clone_from(repo_url, temp_dir)
        return temp_dir
    except Exception as e:
        print(f"Error cloning repository: {e}")
        # Clean up the temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise Exception(f"Failed to clone repository {repo_url}: {e}")
    
def extract_repo_name(repo_url: str) -> str:
    """
    Extract the repository name from the URL.
    Args:
        repo_url: The URL of the GitHub repository.
    Returns:
        The repository name.
    """
    # Handle different Github URL formats
    patterns = [
        r'https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$',
        r'git@github\.com:([^/]+/[^/]+?)(?:\.git)?/?$'

    ]

    for pattern in patterns:
        match = re.match(pattern, repo_url)
        if match:
            return match.group(1)
        
    raise ValueError(f"Invalid GitHub repository URL: {repo_url}")


def cleanup_repository(repo_path: str):
    """
    Clean up a repository by removing the temporary directory.
    Args:
        repo_path: The path to the repository.
    """
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)
        print(f"Cleaned up repository {repo_path}")
        
def get_repo_info(repo_path: str) -> dict:
    """
    Get basic information about a cloned repository.
    
    Args:
        repo_path: Path to the cloned repository
        
    Returns:
        Dictionary with repository information
    """
    try:
        import git
        repo = git.Repo(repo_path)
        
        return {
            'name': os.path.basename(repo_path),
            'branch': repo.active_branch.name,
            'commit_count': len(list(repo.iter_commits())),
            'last_commit': {
                'hash': repo.head.commit.hexsha[:8],
                'message': repo.head.commit.message.strip(),
                'author': repo.head.commit.author.name,
                'date': repo.head.commit.committed_datetime.isoformat()
            },
            'remotes': [remote.name for remote in repo.remotes],
            'file_count': count_files(repo_path)
        }
    except Exception as e:
        return {'error': str(e)}

def count_files(directory: str) -> int:
    """Count the number of files in a directory recursively."""
    count = 0
    for root, dirs, files in os.walk(directory):
        # Skip .git directory
        if '.git' in dirs:
            dirs.remove('.git')
        count += len(files)
    return count
        