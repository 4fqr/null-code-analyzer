"""
Model download utility
Separate script for downloading AI models
"""

from pathlib import Path
from nullcode.core.ai_engine import AIEngine


def main():
    """Download CodeBERT model for offline use"""
    print("=" * 70)
    print("  NULL-CODE-ANALYZER - Model Downloader")
    print("=" * 70)
    print()
    print("Downloading mrm8488/codebert-base-finetuned-detect-insecure-code")
    print("Model size: ~480MB | Estimated time: 5-8 minutes")
    print(f"Cache location: {AIEngine.CACHE_DIR}")
    print()
    print("This model is fine-tuned for vulnerability detection.")
    print("After download, you can run deep scans offline.")
    print()
    print("Press Ctrl+C to cancel...")
    print()
    
    try:
        engine = AIEngine(use_cached=False)
        engine._ensure_model_downloaded()
        
        print()
        print("✓ Model downloaded successfully!")
        print()
        print(f"Cached at: {AIEngine.CACHE_DIR}")
        print()
        print("You can now run offline deep scans:")
        print("  nullcode scan ./project --mode deep")
        print()
        
    except KeyboardInterrupt:
        print("\n\nDownload cancelled by user")
        return 1
    except Exception as e:
        print(f"\n\nError downloading model: {e}")
        print("\nTroubleshooting:")
        print("  1. Check internet connection")
        print("  2. Verify disk space (~500MB required)")
        print("  3. Try again later if Hugging Face is down")
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
