"""
Secure screen utilities to replace unsafe os.system() calls.

Provides safe alternatives to os.system('cls') and os.system('clear')
without shell injection vulnerabilities.
"""

import platform
import subprocess
import sys


def secure_clear_screen():
    """
    Securely clear the terminal screen without using os.system().
    
    This function provides a safe alternative to os.system('cls') and 
    os.system('clear') by using subprocess.run() with proper security measures.
    """
    try:
        if platform.system() == "Windows":
            # Use cmd /c cls for Windows
            subprocess.run(['cmd', '/c', 'cls'], 
                         check=False, 
                         capture_output=True, 
                         timeout=5,
                         creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        else:
            # Use clear for Unix-like systems
            subprocess.run(['clear'], 
                         check=False, 
                         capture_output=True, 
                         timeout=5)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        # Fallback: print enough newlines to clear screen
        _fallback_clear_screen()
    except Exception:
        # Final fallback: minimal clearing
        _minimal_clear_screen()


def _fallback_clear_screen():
    """Fallback screen clearing using newlines."""
    try:
        # Get terminal size if possible
        try:
            import shutil
            terminal_height = shutil.get_terminal_size().lines
            newlines = max(50, terminal_height + 10)  # Add extra lines
        except (OSError, AttributeError):
            newlines = 50  # Default fallback
        
        print('\n' * newlines)
    except Exception:
        _minimal_clear_screen()


def _minimal_clear_screen():
    """Minimal screen clearing as last resort."""
    print('\n' * 25)


def secure_screen_pause(message: str = "Press Enter to continue..."):
    """
    Secure pause function that doesn't expose input() directly.
    
    Args:
        message: Message to display before pausing
    """
    try:
        if not isinstance(message, str):
            message = "Press Enter to continue..."
        
        # Sanitize message to prevent escape sequence injection
        sanitized_message = ''.join(c for c in message if c.isprintable() or c.isspace())
        sanitized_message = sanitized_message[:100]  # Limit length
        
        print(sanitized_message, end='', flush=True)
        sys.stdin.readline()
    except (EOFError, KeyboardInterrupt):
        print("\nOperation interrupted.")
    except Exception:
        print("\nContinuing...")


def get_terminal_width() -> int:
    """
    Safely get terminal width.
    
    Returns:
        Terminal width in characters, or 80 as fallback
    """
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except (OSError, AttributeError):
        return 80  # Default fallback width


def print_separator(char: str = "-", width: int = None):
    """
    Print a separator line safely.
    
    Args:
        char: Character to use for separator (default: "-")
        width: Width of separator (default: terminal width)
    """
    try:
        if not isinstance(char, str) or len(char) != 1 or not char.isprintable():
            char = "-"
        
        if width is None:
            width = get_terminal_width()
        
        if not isinstance(width, int) or width < 1 or width > 200:
            width = 80
        
        print(char * width)
    except Exception:
        print("-" * 80)  # Safe fallback


if __name__ == "__main__":
    # Demo of secure screen utilities
    print("Secure Screen Utilities Demo")
    print_separator("=")
    print("This demonstrates safe screen clearing without os.system()")
    print()
    secure_screen_pause("Press Enter to clear screen...")
    secure_clear_screen()
    print("Screen cleared successfully!")
    print_separator()
    print("Demo completed.")
