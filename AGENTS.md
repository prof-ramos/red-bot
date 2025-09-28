# RED-BOT Development Guidelines

## Build/Lint/Test Commands

### Setup and Dependencies
```bash
# Install dependencies using uv (recommended)
uv pip install gradio requests beautifulsoup4 openai

# Alternative: Install with pip
pip install gradio requests beautifulsoup4 openai
```

### Running the Application
```bash
# Run the bot directly
python redbot.py

# Or use the setup script (includes dependency installation)
./setup.sh
```

### Testing
```bash
# No formal test suite exists. Manual testing recommended:
# 1. Run the bot: python redbot.py
# 2. Test commands: /help, /osint, /sqltest, /hashcrack, /subdomain
# 3. Verify Gradio interface loads on http://localhost:7860
```

### Linting and Code Quality
```bash
# No linting tools configured. Recommended setup:
pip install flake8 black isort mypy

# Run linting
flake8 redbot.py

# Format code
black redbot.py

# Sort imports
isort redbot.py

# Type checking
mypy redbot.py
```

## Code Style Guidelines

### Python Standards
- **Python Version**: 3.8+ (uses modern type hints and f-strings)
- **Encoding**: UTF-8 for all files
- **Line Length**: Keep lines under 100 characters when possible
- **Documentation**: All functions must have Portuguese docstrings

### Imports
```python
# Standard library imports first
import os
import hashlib
from typing import List, Dict, Tuple

# Third-party imports second
import gradio as gr
import requests
from bs4 import BeautifulSoup

# Local imports last (if any)
```

### Naming Conventions
- **Classes**: PascalCase (e.g., `RedBot`)
- **Functions/Methods**: snake_case (e.g., `load_system_prompt`)
- **Variables**: snake_case (e.g., `conversation_history`)
- **Constants**: UPPER_CASE (e.g., `ALLOWED_DOMAINS`)
- **Type Hints**: Use for all function parameters and return values

### Error Handling
```python
# Always use try/except with specific exceptions
try:
    # Risky operation
    response = requests.get(url, timeout=5)
except requests.RequestException as e:
    # Handle specific error type
    return f"Erro na requisição: {str(e)}"
except Exception as e:
    # Fallback for unexpected errors
    return f"Erro inesperado: {str(e)}"
```

### Code Structure
- **Classes**: Group related methods together
- **Functions**: Keep under 50 lines when possible
- **Security**: Never log sensitive data (passwords, API keys)
- **Logging**: Use print() for debugging, consider proper logging for production

### Security Best Practices
- **Input Validation**: Always validate and sanitize user inputs
- **API Keys**: Store in environment variables, never in code
- **Timeouts**: Set reasonable timeouts for network operations
- **Error Messages**: Don't leak sensitive information in error messages
- **Ethical Use**: All security tools must include legal disclaimers

### Documentation
- **Docstrings**: Required for all classes and public methods
- **Language**: Portuguese (following project convention)
- **Examples**: Include usage examples in docstrings when helpful

### Example Code Style
```python
def analyze_vulnerability(self, target: str) -> str:
    """
    Analisa vulnerabilidades em um alvo específico.

    Args:
        target (str): URL ou domínio alvo da análise

    Returns:
        str: Relatório detalhado da análise

    Example:
        >>> bot.analyze_vulnerability("http://example.com")
        "Análise completa de vulnerabilidades..."
    """
    try:
        # Implementation here
        pass
    except Exception as e:
        return f"Erro na análise: {str(e)}"
```

## Development Workflow

1. **Code Changes**: Make changes following the style guidelines above
2. **Testing**: Manually test functionality through the Gradio interface
3. **Security Review**: Ensure no sensitive data is logged or exposed
4. **Documentation**: Update docstrings and comments as needed
5. **Commit**: Use descriptive commit messages in Portuguese

## Environment Setup

- **Package Manager**: uv (recommended) or pip
- **Virtual Environment**: Required (.venv directory)
- **API Keys**: Set OPENROUTER_API_KEY environment variable for AI features
- **Platform**: macOS with Apple Silicon (M3) preferred
- add to memory. Sempre me responda e sempre documente tudo em pt-br
- add to memory
- add to memory. Sempre marque o coderabbitai nos PR