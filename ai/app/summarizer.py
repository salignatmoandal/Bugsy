"""
summarizer.py
-------------
This module provides code summarization using either Cohere API or a local ONNX model.
"""

import os
from typing import Optional

from parser import CodebaseAnalyzer, analyze_codebase

# Try importing Cohere SDK for API-based summarization
try:
    import cohere
except ImportError:
    cohere = None

# Try importing ONNX Runtime for local model inference (placeholder)
try:
    import onnxruntime as ort
except ImportError:
    ort = None

# Import local modules (corrige cette ligne)
from insights import CodeInsights  # ← CORRIGE ICI

class CodeSummarizer:
    def __init__(
        self,
        use_cohere: bool = True,
        cohere_api_key: Optional[str] = None,
        onnx_model_path: Optional[str] = None
    ):
        """
        Initialize the summarizer with either Cohere or ONNX backend.

        Args:
            use_cohere (bool): If True, use Cohere API; otherwise, use ONNX.
            cohere_api_key (str, optional): API key for Cohere. If not provided, will use COHERE_API_KEY env variable.
            onnx_model_path (str, optional): Path to the ONNX model file (if using ONNX).
        """
        self.use_cohere = use_cohere
        if use_cohere:
            if not cohere:
                raise ImportError("Cohere SDK is not installed. Please install with 'pip install cohere'.")
            # Initialize Cohere client with API key
            self.client = cohere.Client(cohere_api_key or os.getenv("COHERE_API_KEY"))
        else:
            if not ort:
                raise ImportError("ONNX Runtime is not installed. Please install with 'pip install onnxruntime'.")
            if not onnx_model_path:
                raise ValueError("You must provide an ONNX model path when use_cohere is False.")
            # Initialize ONNX inference session
            self.session = ort.InferenceSession(onnx_model_path)

    def summarize(self, code: str, language: str = "TypeScript") -> str:
        """
        Summarize the given code and return an English summary.

        Args:
            code (str): The code to summarize.

        Returns:
            str: The generated summary in English.
        """
        if self.use_cohere:
            # Prompt contextuel et plus précis
            prompt = (
                f"You are an expert {language} developer.\n"
                f"Summarize the following {language} file. "
                f"Focus on the main logic, structure, and purpose. "
                f"If the file only contains type declarations, imports, or is empty, say so.\n"
                f"---\n"
                f"{code}"
            )
            response = self.client.generate(
                model="command",
                prompt=prompt,
                max_tokens=200,
                temperature=0.3,
            )
            return response.generations[0].text.strip()
        else:
            # Placeholder for ONNX inference
            # In a real implementation, you would preprocess the code,
            # tokenize it, and run inference with the ONNX model.
            return "ONNX summarization not implemented yet."

# Example usage for direct script execution
if __name__ == "__main__":
    # 1. Analyse un dossier pour obtenir les fichiers source
    repo = "/Users/mawensalignat-moandal/Desktop/Engineering/personal/projects/SaaS/productivity/Noodl/frontend/src"
    analysis = analyze_codebase(repo)
    
    # 2. Prend le contenu du premier fichier Python ou TypeScript trouvé
    # Ne résume que les fichiers avec au moins X lignes et au moins une fonction
    source_files = [f for f in analysis['files']
                if f['language'] in ['python', 'typescript']
                and len(f.get('content', '')) > 100
                and len(f.get('functions', [])) > 0]
    if not source_files:
        print("No Python or TypeScript file found.")
    else:
        file_info = source_files[0]
        code_content = file_info.get('content', '')
        print(f"Testing summarization for file: {file_info['path']}")
        print(f"Code sample:\n{code_content[:200]}...\n")  # Affiche les 200 premiers caractères
        
        # 3. Utilise le summarizer
        # Initialize our analysis components
        analyzer = CodebaseAnalyzer()

        # Initialize summarizer with error handling
        try:
            api_key = os.getenv("COHERE_API_KEY")
            if api_key:
                summarizer = CodeSummarizer(use_cohere=True, cohere_api_key=api_key)
                print("✅ Cohere summarizer initialized successfully")
            else:
                print("⚠️  No COHERE_API_KEY found - disabling AI summaries")
                summarizer = None
        except Exception as e:
            print(f"⚠️  Cohere initialization failed: {e}")
            print("📝 Using fallback summarizer (no AI summaries)")
            summarizer = None

        insights = CodeInsights()
        summarizer = CodeSummarizer(use_cohere=True, cohere_api_key=os.getenv("COHERE_API_KEY"))
        summary = summarizer.summarize(code_content, language=file_info['language'])
        print("AI Summary:")
        print(summary)

