# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RED-BOT is a security education chatbot built with Gradio. The project focuses on cybersecurity education and defensive security practices.

**IMPORTANT SECURITY NOTICE**: This repository contains security testing tools. Claude Code should only assist with defensive security analysis, vulnerability explanations, and educational content. Do not enhance or create new offensive capabilities.

## Project Structure

- `redbot.py` - Main chatbot application with Gradio interface
- `prompt.md` - System prompt for the security education assistant
- `setup.sh` - Environment setup script using `uv` package manager
- `README.md` - Project documentation

## Development Commands

### Setup and Installation
```bash
# Install dependencies and run the bot
./setup.sh
```

### Manual Execution
```bash
# Run the bot directly (after dependency installation)
python redbot.py
```

### Development Environment
```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies manually
uv pip install gradio requests beautifulsoup4 openai

# Run with debugging
python redbot.py
```

## Architecture

### Core Components
1. **Gradio Interface**: Web-based chat interface on port 7860
2. **RedBot Class**: Main bot logic with specialized security education methods
3. **OpenRouter Integration**: Optional AI model integration for enhanced responses
4. **Command System**: Slash commands for specific security education topics

### Security Education Areas
- **Vulnerability Analysis**: Educational explanations of common vulnerabilities
- **Defensive Techniques**: Best practices and mitigation strategies
- **Security Concepts**: Theoretical knowledge and practical guidance
- **Code Security**: Secure coding practices and examples

## Environment Configuration

- **Package Manager**: `uv` (Ultrafast Python package installer)
- **Target Platform**: macOS with Apple Silicon
- **Shell**: zsh
- **System Package Manager**: Homebrew
- **Python Environment**: Virtual environment in `.venv/`

## Dependencies

Core dependencies installed via `uv`:
- `gradio` - Web interface framework
- `requests` - HTTP client library
- `beautifulsoup4` - HTML parsing
- `openai` - OpenRouter API integration (optional)

## Development Guidelines

### Code Standards
- Clean, documented Python code
- Portuguese documentation per global configuration
- Focus on educational content and defensive security
- Implement proper error handling and input validation

### Security Constraints
- **Defensive Focus Only**: Assist only with defensive security and education
- **No Offensive Enhancements**: Do not improve or create offensive capabilities
- **Educational Purpose**: All features should serve educational goals
- **Legal Compliance**: Ensure all guidance promotes legal and ethical practices

## Ethical Guidelines

This project is strictly for educational and defensive security purposes. All features must:
- Promote ethical security practices
- Include appropriate warnings about legal usage
- Focus on defensive techniques and vulnerability understanding
- Never enhance offensive capabilities