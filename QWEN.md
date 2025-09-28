# RED-BOT Project Context

## Project Overview

RED-BOT é um **ChatBot especializado em Red Team** desenvolvido utilizando **Gradio**. O projeto foi projetado para fornecer assistência em tarefas relacionadas a segurança cibernética, com foco em **Red Team** e **Ethical Hacking**. O bot oferece ajuda em questões relacionadas a testes de penetração, exploração de vulnerabilidades e automação de tarefas de segurança.

Este é um projeto de código aberto sob a licença MIT, com foco em segurança defensiva e educação em cibersegurança, seguindo práticas éticas e legais rigorosas.

## Project Structure

- **redbot.py**: Script principal do RED-BOT com a lógica do chatbot e interface Gradio
- **prompt.md**: Contém o prompt do sistema que define as diretrizes e especializações do assistente
- **setup.sh**: Script para configurar o ambiente do projeto e instalar as dependências
- **README.md**: Documentação principal do projeto
- **AGENTS.md**: Diretrizes de desenvolvimento e comandos para build/lint/test
- **CLAUDE.md**: Configurações e diretrizes específicas para o Claude Code
- **.claude/settings.local.json**: Configurações locais para o Claude Code
- **.venv/**: Ambiente virtual Python (git ignore)
- **repomix-output.md**: Arquivo de saída de análise do repositório

## Key Technologies & Dependencies

- **Python 3.8+**: Linguagem principal do projeto
- **Gradio**: Framework para interface web interativa
- **OpenAI**: Integração com API OpenRouter (modelos de IA)
- **requests**: Requisições HTTP para consultas de segurança
- **beautifulsoup4**: Parsing HTML para operações OSINT
- **hashlib**: Operações de hash em password cracking
- **uv**: Gerenciador de pacotes Python ultrafástico

## Building and Running

### Setup Environment
```bash
# Método recomendado: usar o script de setup
./setup.sh

# Ou manualmente
uv venv
source .venv/bin/activate
uv pip install gradio requests beautifulsoup4 openai
```

### Running the Application
```bash
# Executar o bot após setup
python redbot.py

# O bot estará disponível em: http://localhost:7860
```

### API Configuration (Opcional)
Para habilitar respostas inteligentes baseadas em IA:
```bash
export OPENROUTER_API_KEY="sua-chave-aqui"
```

## Development Conventions

### Code Style
- Python 3.8+ com type hints modernos e f-strings
- Codificação UTF-8 para todos os arquivos
- Comprimento de linha mantido abaixo de 100 caracteres quando possível
- Docstrings em português para todas as funções

### Naming Conventions
- Classes: PascalCase (ex: `RedBot`)
- Funções/Métodos: snake_case (ex: `load_system_prompt`)
- Variáveis: snake_case (ex: `conversation_history`)
- Constantes: UPPER_CASE (ex: `ALLOWED_DOMAINS`)

### Security Best Practices
- Validação e sanitização de inputs do usuário
- Armazenamento de chaves de API em variáveis de ambiente
- Configuração de timeouts razoáveis para operações de rede
- Não vazamento de informações sensíveis em mensagens de erro
- Uso ético obrigatório - todas as ferramentas incluem avisos legais

### Error Handling
Sempre usar try/except com exceções específicas e manipulação de erros adequada:

```python
try:
    response = requests.get(url, timeout=5)
except requests.RequestException as e:
    return f"Erro na requisição: {str(e)}"
except Exception as e:
    return f"Erro inesperado: {str(e)}"
```

## Core Functionality

### Main Features
O RED-BOT inclui funcionalidades para:
- OSINT (Open Source Intelligence)
- Análise de vulnerabilidades web
- Testes de SQL Injection
- Quebra de hashes MD5
- Busca de subdomínios
- Análise de vulnerabilidades XSS, IDOR, CSRF, SSRF, CORS
- Análise de autenticação quebrada
- Explicação de conceitos de segurança

### Command System
O bot responde a diversos comandos slash:
- `/help` - Mostra todos os comandos disponíveis
- `/osint <consulta>` - Busca informações com Google Dorking
- `/sqltest <URL>` - Testa vulnerabilidades SQL Injection
- `/hashcrack <hash>` - Quebra hashes MD5
- `/subdomain <dominio>` - Busca subdomínios
- `/xss`, `/idor`, `/csrf`, `/ssrf`, `/cors` - Análises de vulnerabilidades
- E muitos outros comandos especializados

### Architecture
O projeto é organizado em:
1. Interface Gradio com design cibernético em tons de cinza escuro
2. Classe RedBot com lógica especializada em segurança
3. Integração OpenRouter opcional para respostas de IA
4. Sistema de comandos slash para funcionalidades específicas
5. Respostas baseadas em regras como fallback

## Important Notes

### Legal & Ethical Guidelines
- O uso deve ser exclusivamente em sistemas autorizados
- Projeto para fins educacionais e de segurança defensiva
- Todos os testes e automações devem seguir diretrizes legais
- Aviso legal obrigatório sobre uso ético

### Target Environment
- Plataforma: macOS com Apple Silicon (M3) preferido
- Shell: zsh
- Gerenciador de pacotes: Homebrew e uv
- Ambiente virtual: .venv/

### Special Instructions
- Sempre responder e documentar em português (pt-br)
- Foco em segurança defensiva e educação
- Assistência apenas com análise defensiva e segurança educacional
- Não aprimorar ou criar capacidades ofensivas