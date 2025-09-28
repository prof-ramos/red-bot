This file is a merged representation of the entire codebase, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
.claude/
  settings.local.json
CLAUDE.md
prompt.md
README.md
redbot.py
setup.sh
```

# Files

## File: .claude/settings.local.json
`````json
{
  "permissions": {
    "allow": [
      "Bash(cat:*)"
    ],
    "deny": [],
    "ask": []
  }
}
`````

## File: CLAUDE.md
`````markdown
# CLAUDE.md

Este arquivo fornece orientações para o Claude Code (claude.ai/code) ao trabalhar com código neste repositório.

## Visão Geral do Projeto

RED-BOT é um ChatBot especializado em RedTeam desenvolvido com Gradio. O projeto foca em fornecer assistência para tarefas de Ethical Hacking, Red Team e CyberSecurity, com ênfase em Python e automação usando IA.

## Estrutura do Projeto

- `redbot.py` - Arquivo principal do bot (atualmente vazio, aguardando implementação)
- `prompt.md` - Contém o prompt detalhado do sistema para o assistente de Ethical Hacking
- `setup.sh` - Script de configuração para instalação de dependências com `uv`
- `README.md` - Documentação básica do projeto

## Comandos de Desenvolvimento

### Instalação e Execução
```bash
# Instalar dependências e executar o bot
./setup.sh
```

### Execução Manual
```bash
# Executar o redbot diretamente (após instalação das dependências)
python redbot.py
```

## Arquitetura do Sistema

### Componentes Principais
1. **Interface Gradio**: Interface web para interação com o chatbot
2. **Sistema de Prompts**: Prompts especializados definidos em `prompt.md` para diferentes áreas:
   - OSINT (Open Source Intelligence)
   - Análise de aplicações web
   - Password cracking
   - Automação de segurança

### Áreas de Especialização
- **OSINT**: Coleta de informações de fontes abertas
- **Web Application Security**: Análise de vulnerabilidades em aplicações web
- **Password Cracking**: Técnicas de quebra de senhas
- **Automação**: Scripts Python para automatizar tarefas de segurança

## Configuração do Ambiente

- **Gerenciador de Pacotes**: `uv` (Ultrafast Python package installer)
- **Plataforma Alvo**: MacBook M3 com 8GB RAM
- **Shell**: zsh
- **Package Manager do Sistema**: Homebrew

## Considerações de Segurança

O projeto deve seguir rigorosamente as diretrizes éticas e legais:
- Todos os testes devem ser realizados apenas em ambientes controlados
- Sempre obter permissão explícita antes de realizar qualquer teste
- Focar exclusivamente em segurança defensiva e ethical hacking
- Nunca criar código malicioso ou para uso não autorizado

## Desenvolvimento

### Padrões de Código
- Código Python limpo e bem documentado
- Comentários em português brasileiro conforme configuração global
- Foco em eficiência e clareza
- Implementação de boas práticas de segurança

### Dependências
- Gradio (para interface web)
- Requests (para requisições HTTP)
- BeautifulSoup (para parsing HTML)
- Hashlib (para operações de hash)
- Itertools (para ataques de força bruta)

## Nota sobre Ética

Este projeto é destinado exclusivamente para fins educacionais e de segurança defensiva. Todas as funcionalidades devem ser usadas responsavelmente e dentro dos limites legais.
`````

## File: prompt.md
`````markdown
# Prompt para Assistente de Ethical Hacking

## Introdução
Você é um assistente de inteligência artificial dedicado a ajudar no aprendizado e na execução de tarefas práticas no campo de Ethical Hacking, Red Team, CyberSecurity, com um foco particular em Python e Automação utilizando Inteligência Artificial. Seu papel é ser um mentor, colaborador e tutor, oferecendo apoio contínuo e respostas práticas e teóricas a questões relacionadas à área de segurança cibernética.

## Objetivos

### 1. Tirar Dúvidas
Oferecer explicações claras, concisas e detalhadas sobre conceitos, metodologias e ferramentas utilizadas em Ethical Hacking, Red Team e CyberSecurity, com ênfase em Python.

**Requisitos:**
- Sempre forneça explicações completas, com exemplos práticos quando necessário.

### 2. Melhorar Códigos
Auxiliar na revisão, otimização e melhoria de códigos em Python.

**Requisitos:**
- O objetivo é aumentar a eficiência, reduzir redundâncias e melhorar a clareza do código.
- Sempre explique as mudanças feitas no código de forma compreensível.

### 3. Automatizar Ações
Criar, ajustar e otimizar scripts Python para automatizar tarefas repetitivas ou críticas na área de segurança cibernética, como testes de penetração, análise de vulnerabilidades, auditorias de sistemas e outras funções essenciais de Red Team.

### 4. Criar Códigos
Oferecer assistência para a criação de novos scripts e programas em Python, orientando na implementação de funcionalidades específicas necessárias para testes de segurança ou automações desejadas.

### 5. Organizar Documentos
Apoiar na organização e gestão de documentos técnicos, relatórios e outros materiais relacionados aos projetos de estudo e segurança cibernética. Isso inclui a organização de scripts, logs de auditoria, resultados de testes e relatórios de vulnerabilidade.

### 6. Suporte Geral
Agir como um "colega de laboratório", oferecendo orientação prática e teórica para o processo de aprendizado contínuo. Ser uma fonte de insights para novos caminhos de exploração, ferramentas emergentes e melhorias no processo de automação e Python.

## Diretrizes de Interação
- Sempre que for necessário, forneça código Python eficiente, limpo e bem documentado.
- Não hesite em sugerir melhorias ou otimizações nas abordagens de automação e implementação de scripts.
- Responda de forma prática e objetiva, evitando jargões excessivos. Se for técnico, garanta que a explicação seja acessível para um aluno com nível intermediário a avançado.
- Adapte as respostas ao nível de conhecimento do usuário, oferecendo desafios técnicos adequados ao seu progresso.
- Se o usuário tiver alguma dúvida ou precisar de ajuda com algum código, revise o código cuidadosamente, sugerindo melhorias ou otimizações que podem ser feitas para alcançar os objetivos mais rapidamente.

## Exemplo de Interação

**Consulta do Usuário:** "Como posso usar Python para automatizar um ataque de força bruta simples contra uma senha?"

**Resposta:**
"Para automatizar um ataque de força bruta em Python, você pode usar a biblioteca itertools para gerar todas as combinações possíveis de senhas. Claro, sempre execute esse tipo de script apenas em sistemas para os quais você tem permissão para realizar testes. Aqui está um exemplo básico de código para ilustrar o processo:"

```python
import itertools
import string

def brute_force_attack(target_password):
    chars = string.ascii_lowercase + string.digits
    for length in range(1, 9):  # Limite de 8 caracteres
        for attempt in itertools.product(chars, repeat=length):
            guess = ''.join(attempt)
            print(f"Tentando: {guess}")
            if guess == target_password:
                print(f"Senha encontrada: {guess}")
                return guess
    return None

# Exemplo de uso
target_password = "abc123"  # Apenas para testes
brute_force_attack(target_password)
```

"Esse código vai tentar todas as combinações de caracteres até encontrar a senha certa. Se você precisar de mais recursos, como implementar mais estratégias ou otimizar o processo, podemos discutir outras abordagens, como ataques distribuídos ou usar ferramentas já existentes, como Hashcat ou John the Ripper."

## Aviso Legal
Lembre-se de que todos os testes e automações devem ser realizados exclusivamente em ambientes controlados e com permissão explícita. Você deve seguir rigorosamente todas as diretrizes legais e éticas durante o processo de aprendizado e experimentação.

## Prompt do Sistema

### Título
System Prompt

### Descrição
You are a highly skilled assistant specializing in OSINT (Open Source Intelligence), Web Application Security, Site Analysis, and Password Cracking, providing technical solutions, detailed guidance, and Python scripts for automation in these fields. You are focused on helping users with tasks such as gathering open-source intelligence, finding vulnerabilities in web applications, automating security testing, and performing ethical password cracking operations.

### Configuração do Usuário
- **Dispositivo:** MacBook M3 with 8GB of RAM
- **Shell:** zsh
- **Gerenciador de Pacotes:** Homebrew

### Áreas de Foco

#### 1. OSINT (Open Source Intelligence)
**Coleta de Informações:**
- Automate searches on social media, forums, and public domains.
- Extract metadata from files (e.g., PDFs, images, documents).
- Query APIs from open sources (e.g., Shodan, Censys, WHOIS).

**Ferramentas e Técnicas:**
- Integrate tools such as theHarvester, Maltego, or SpiderFoot with Python scripts.
- Create custom scripts for parsing HTML/JSON data.

**Exemplo de Código:**
```python
import requests
from bs4 import BeautifulSoup

def osint_google_dorking(query):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    url = f"https://www.google.com/search?q={query}"
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    results = [a['href'] for a in soup.find_all('a', href=True) if 'url?q=' in a['href']]
    return results

# Example: Search for exposed files of a domain
print(osint_google_dorking('site:example.com filetype:pdf'))
```

#### 2. Web Applications and Sites
**Análise de Vulnerabilidades:**
- Identify common vulnerabilities (e.g., SQL Injection, XSS, CSRF).
- Test security configurations (e.g., HTTP Headers, CORS).

**Scans de Automação:**
- Integrate with tools like OWASP ZAP, Burp Suite, or sqlmap via API.
- Develop custom scanners for specific tests.

**Exemplo de Código:**
```python
import requests

def test_sql_injection(url, payloads):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            vulnerabilities.append(payload)
    return vulnerabilities

# Example: Test common SQL Injection payloads
payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users--"]
print(test_sql_injection("http://example.com/page", payloads))
```

#### 3. Password Cracking
**Técnicas de Ataque:**
- Brute force with custom wordlists.
- Dictionary attacks with mutation rules (e.g., hashcat).
- Rainbow tables for common hashes (e.g., MD5, SHA1).

**Automação em Python:**
- Integrate with libraries like hashlib, requests for authentication.
- Optimize performance using concurrency (e.g., asyncio, threading).

**Exemplo de Código:**
```python
import hashlib
import itertools
import string

def brute_force_hash(target_hash, charset=string.ascii_lowercase + string.digits, max_length=8):
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            guess = ''.join(attempt)
            guess_hash = hashlib.md5(guess.encode()).hexdigest()
            if guess_hash == target_hash:
                return guess
    return None

# Example: Break an MD5 hash
target_hash = "e99a18c428cb38d5f260853678922e03"  # Hash for "abc123"
print(brute_force_hash(target_hash))
```

### Diretrizes de Resposta

#### OSINT
- Suggest reliable data sources and public APIs.
- Alert about the legal limits on data collection and the need for explicit authorization.

#### Web Applications
- Emphasize the importance of authorized testing and compliance with legal standards.
- Recommend using proxy tools like Burp Suite for complementary manual analysis.

#### Password Cracking
- Explicitly discuss ethics and legality when performing password cracking tests.
- Suggest mitigation techniques like rate limiting, salts, and secure password storage.

### Exemplo Completo de Interação

**Consulta do Usuário:** "How can I automate the search for subdomains with Python?"

**Resposta:**
```python
import requests

def find_subdomains(domain, wordlist_path="wordlist.txt"):
    subdomains = []
    with open(wordlist_path, "r") as file:
        words = file.readlines()
    
    for word in words:
        subdomain = word.strip() + "." + domain
        try:
            response = requests.get(f"http://{subdomain}", timeout=5)
            if response.status_code == 200:
                subdomains.append(subdomain)
        except requests.ConnectionError:
            continue
    return subdomains

# Example usage
print(find_subdomains("example.com"))
```

**Considerações:**
- Use custom wordlists (e.g., subdomains-top1million.txt).
- Add multithreading for greater speed and efficiency.
- Consider integrating with SecurityTrails or Shodan API for more comprehensive results.

### Aviso Legal
All tests and experiments must be conducted on systems where you have explicit permission to perform such actions. Never perform brute force attacks, scans, or any other tests without legal authorization. Ensure you are acting within legal and ethical boundaries, avoiding compromising the integrity and security of unauthorized systems.
`````

## File: README.md
`````markdown
# RED-BOT

**RED-BOT** é um **ChatBot especializado em Red Team** desenvolvido utilizando **Gradio**. Ele foi projetado para fornecer assistência em tarefas relacionadas a segurança cibernética, com foco em **Red Team** e **Ethical Hacking**. Ao rodar o bot, você obterá ajuda em questões relacionadas a testes de penetração, exploração de vulnerabilidades e automação de tarefas de segurança.

## Estrutura do Projeto

- **prompt.md**: Contém o **prompt** do ChatBot, que define as diretrizes e especializações do assistente. Ele é a base para o comportamento do **RED-BOT**.
- **setup.sh**: Script para configurar o ambiente do projeto e instalar as dependências necessárias.
- **redbot.py**: O script principal do **RED-BOT**, onde a lógica do chatbot é executada.

## Instruções para Execução

### 1. Clonar o Repositório

Primeiro, clone este repositório para o seu ambiente local:

```bash
git clone https://github.com/seuusuario/red-bot.git
cd red-bot
````

### 2. Rodar o Setup

Execute o script `setup.sh` para garantir que todas as dependências sejam verificadas e instaladas automaticamente. O script também configurará o ambiente para o bot funcionar corretamente.

```bash
bash setup.sh
```

O **setup.sh** realizará as seguintes ações:

* Verificará a instalação do **uvicorn** e outras dependências do projeto.
* Instalará as dependências necessárias caso ainda não estejam instaladas.
* Configurará o ambiente para rodar o **RED-BOT**.

### 3. Rodar o ChatBot

Após a execução do **setup.sh**, o bot estará pronto para ser executado. Para rodá-lo, utilize o seguinte comando:

```bash
python redbot.py
```

Isso iniciará o **RED-BOT** e o disponibilizará para interações através da interface do Gradio.

## Dependências

O projeto utiliza o **Gradio** para a interface do chatbot e outras bibliotecas para funcionalidades relacionadas a segurança cibernética. As principais dependências incluem:

* **Gradio**: Para a criação da interface interativa.
* **uvicorn**: Servidor ASGI para rodar a aplicação.
* **requests**: Para fazer requisições HTTP, como consultas de segurança e análise de vulnerabilidades.
* **outros pacotes de segurança cibernética**: Dependendo dos objetivos do projeto, como **shodan**, **beautifulsoup4**, **paramiko**, etc.

Todas as dependências serão instaladas automaticamente ao rodar o `setup.sh`.

## Como Funciona

O **RED-BOT** utiliza um **ChatBot** para auxiliar em atividades de **Red Team**, oferecendo conselhos sobre ataques, técnicas de exploração, testes de penetração, etc. O comportamento do bot é definido no arquivo **prompt.md**, que descreve como o assistente deve interagir com os usuários, além de suas áreas de especialização, como:

* **OSINT (Open Source Intelligence)**
* **Segurança de Aplicações Web**
* **Automatização de Tarefas com Python**
* **Quebra de Senhas**
* **Análise de Vulnerabilidades**

## Como Personalizar

Caso você queira personalizar o **RED-BOT** ou adaptá-lo a novas necessidades, você pode editar o arquivo **prompt.md** para ajustar os comportamentos do assistente e suas respostas. Esse arquivo é onde você pode definir as diretrizes e comandos que o bot deve seguir.

## Contribuições

Se você tem ideias de melhorias ou quer colaborar com o projeto, fique à vontade para criar um **pull request** ou abrir uma **issue**. Agradecemos por qualquer contribuição que melhore a funcionalidade ou a segurança do **RED-BOT**.

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contato

Para mais informações ou dúvidas, entre em contato com [seu\_email@dominio.com](mailto:seu_email@dominio.com).

```

### Melhorias no **README.md**:

1. **Clareza nas instruções**: Estruturei o conteúdo para tornar as instruções mais claras e diretas, explicando detalhadamente o que cada comando faz.
2. **Secções organizadas**: Agora o README está bem dividido em seções como "Instruções para Execução", "Dependências", "Como Funciona", etc.
3. **Facilidade de personalização**: A seção sobre personalização do bot foi melhorada, explicando como o arquivo **prompt.md** pode ser editado para ajustes.
4. **Exemplos de uso e contribuições**: Forneci exemplos claros de como rodar o chatbot e como contribuir para o projeto.
5. **Contato**: Uma seção de contato foi incluída para facilitar a comunicação com o mantenedor do projeto.

Esse formato ajuda os usuários a entender rapidamente o fluxo de configuração e uso do **RED-BOT**, além de facilitar a contribuição e personalização do bot.
```
`````

## File: redbot.py
`````python
#!/usr/bin/env python3
"""
RED-BOT - ChatBot especializado em Red Team e Ethical Hacking
Desenvolvido com Gradio para interface web interativa
"""

import gradio as gr
import requests
from bs4 import BeautifulSoup
import hashlib
import itertools
import string
import time
from typing import List, Dict, Tuple

class RedBot:
    def __init__(self):
        self.system_prompt = self.load_system_prompt()
        self.conversation_history = []
        
    def load_system_prompt(self) -> str:
        """Carrega o prompt do sistema do arquivo prompt.md"""
        try:
            with open('prompt.md', 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return "Assistente especializado em Ethical Hacking e Red Team"
    
    def osint_google_dorking(self, query: str) -> List[str]:
        """Realiza Google Dorking para OSINT"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            }
            url = f"https://www.google.com/search?q={query}"
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            results = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if 'url?q=' in href and 'google.com' not in href:
                    clean_url = href.split('url?q=')[1].split('&')[0]
                    results.append(clean_url)
            
            return results[:10]
        except Exception as e:
            return [f"Erro na busca: {str(e)}"]
    
    def test_sql_injection(self, url: str, payloads: List[str]) -> Dict:
        """Testa vulnerabilidades de SQL Injection"""
        vulnerabilities = []
        try:
            for payload in payloads:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=5)
                
                error_patterns = [
                    'error', 'syntax', 'mysql', 'postgresql', 'oracle',
                    'sql', 'database', 'warning', 'fatal'
                ]
                
                for pattern in error_patterns:
                    if pattern in response.text.lower():
                        vulnerabilities.append({
                            'payload': payload,
                            'response_length': len(response.text),
                            'status_code': response.status_code
                        })
                        break
            
            return {
                'url': url,
                'vulnerabilities_found': len(vulnerabilities),
                'details': vulnerabilities
            }
        except Exception as e:
            return {'error': str(e)}
    
    def brute_force_hash(self, target_hash: str, charset: str = None, max_length: int = 6) -> str:
        """Quebra hash MD5 usando força bruta"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        for length in range(1, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                guess = ''.join(attempt)
                guess_hash = hashlib.md5(guess.encode()).hexdigest()
                if guess_hash == target_hash.lower():
                    return guess
                
                if length > 4:
                    time.sleep(0.001)
        
        return ""
    
    def find_subdomains(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """Encontra subdomínios usando lista de palavras"""
        if wordlist is None:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging']
        
        subdomains = []
        for word in wordlist:
            subdomain = f"{word}.{domain}"
            try:
                response = requests.get(f"http://{subdomain}", timeout=3)
                if response.status_code == 200:
                    subdomains.append(subdomain)
            except:
                try:
                    response = requests.get(f"https://{subdomain}", timeout=3)
                    if response.status_code == 200:
                        subdomains.append(subdomain)
                except:
                    continue
        
        return subdomains
    
    def process_message(self, message: str, chat_history: List[List[str]]) -> Tuple[str, List[List[str]]]:
        """Processa mensagem do usuário e retorna resposta"""
        
        if message.startswith('/osint'):
            query = message.replace('/osint', '').strip()
            if query:
                results = self.osint_google_dorking(query)
                response = f"🔍 **Resultados OSINT para '{query}':**\n\n"
                for i, result in enumerate(results[:5], 1):
                    response += f"{i}. {result}\n"
            else:
                response = "❌ Uso: /osint <consulta de busca>"
        
        elif message.startswith('/sqltest'):
            parts = message.split()
            if len(parts) >= 2:
                url = parts[1]
                payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users--"]
                results = self.test_sql_injection(url, payloads)
                response = f"🛡️ **Teste SQL Injection em {url}:**\n\n"
                response += f"Vulnerabilidades encontradas: {results.get('vulnerabilities_found', 0)}\n"
                if results.get('details'):
                    response += "Payloads que causaram erros:\n"
                    for vuln in results['details'][:3]:
                        response += f"- {vuln['payload']}\n"
            else:
                response = "❌ Uso: /sqltest <URL>"
        
        elif message.startswith('/hashcrack'):
            parts = message.split()
            if len(parts) >= 2:
                target_hash = parts[1]
                result = self.brute_force_hash(target_hash)
                if result:
                    response = f"🔓 **Hash quebrado!** Resultado: `{result}`"
                else:
                    response = "🔒 Hash não foi quebrado com os parâmetros atuais"
            else:
                response = "❌ Uso: /hashcrack <hash_md5>"
        
        elif message.startswith('/subdomain'):
            parts = message.split()
            if len(parts) >= 2:
                domain = parts[1]
                subdomains = self.find_subdomains(domain)
                response = f"🌐 **Subdomínios encontrados para {domain}:**\n\n"
                if subdomains:
                    for subdomain in subdomains:
                        response += f"✅ {subdomain}\n"
                else:
                    response += "Nenhum subdomínio encontrado"
            else:
                response = "❌ Uso: /subdomain <dominio.com>"
        
        elif message.startswith('/help'):
            response = """🤖 **RED-BOT - Comandos Disponíveis:**

**Comandos OSINT:**
• `/osint <consulta>` - Google Dorking
• `/subdomain <dominio>` - Busca subdomínios

**Comandos Web Security:**
• `/sqltest <URL>` - Teste SQL Injection

**Comandos Password Cracking:**
• `/hashcrack <hash>` - Quebra hash MD5

**Comandos Gerais:**
• `/help` - Mostra esta ajuda

**Exemplo de uso:**
```
/osint site:exemplo.com filetype:pdf
/sqltest http://exemplo.com/login
/hashcrack 5d41402abc4b2a76b9719d911017c592
/subdomain exemplo.com
```

⚠️ **AVISO:** Use apenas em sistemas autorizados!"""
        
        else:
            response = self.generate_response(message)
        
        chat_history.append([message, response])
        return "", chat_history
    
    def generate_response(self, message: str) -> str:
        """Gera resposta baseada no prompt do sistema"""
        
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['python', 'código', 'script', 'programar']):
            response = """🐍 **Desenvolvimento Python para Red Team:**

Posso ajudar você com:
• Scripts de automação para testes de segurança
• Ferramentas de OSINT personalizadas  
• Scanners de vulnerabilidade
• Ferramentas de força bruta
• Análise de logs e dados

**Exemplo - Scanner de portas simples:**
```python
import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_host(host, ports):
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(host, p), ports)
    return [p for p in results if p is not None]
```

Digite `/help` para ver comandos disponíveis!"""
        
        elif any(word in message_lower for word in ['osint', 'informação', 'reconhecimento']):
            response = """🔍 **OSINT - Open Source Intelligence:**

**Técnicas principais:**
• Google Dorking para encontrar arquivos expostos
• Análise de metadados em documentos
• Busca em redes sociais e fóruns
• Consultas em bases de dados públicas (Shodan, Censys)

**Ferramentas recomendadas:**
• theHarvester - Coleta emails e subdomínios
• Maltego - Mapeamento de relacionamentos
• SpiderFoot - Automação de OSINT
• Shodan - Scanner de dispositivos IoT

**Google Dorks úteis:**
```
site:exemplo.com filetype:pdf
intitle:"index of" site:exemplo.com
"senha" OR "password" site:exemplo.com
```

Use `/osint <consulta>` para buscar informações!"""
        
        elif any(word in message_lower for word in ['sql', 'web', 'aplicação', 'vulnerabilidade']):
            response = """🛡️ **Segurança de Aplicações Web:**

**Vulnerabilidades comuns:**
• SQL Injection - Manipulação de consultas SQL
• XSS (Cross-Site Scripting) - Injeção de código JavaScript
• CSRF - Requisições maliciosas cross-site
• Directory Traversal - Acesso a arquivos não autorizados

**Ferramentas de teste:**
• Burp Suite - Proxy para análise de tráfego
• OWASP ZAP - Scanner de vulnerabilidades
• SQLMap - Automatização de SQL Injection
• Nikto - Scanner de vulnerabilidades web

**Headers de segurança importantes:**
```
Content-Security-Policy
X-Frame-Options  
X-XSS-Protection
Strict-Transport-Security
```

Use `/sqltest <URL>` para testar SQL Injection!"""
        
        elif any(word in message_lower for word in ['senha', 'password', 'hash', 'crack']):
            response = """🔐 **Password Cracking e Análise:**

**Tipos de ataque:**
• Força bruta - Testa todas as combinações
• Ataque de dicionário - Usa listas de senhas comuns
• Rainbow tables - Hashes pré-computados
• Ataques híbridos - Combina técnicas

**Ferramentas principais:**
• Hashcat - GPU-accelerated password cracking
• John the Ripper - CPU password cracker
• Hydra - Força bruta para serviços de rede
• Medusa - Alternative para Hydra

**Hashes comuns:**
```
MD5: 32 caracteres hex
SHA1: 40 caracteres hex  
SHA256: 64 caracteres hex
NTLM: 32 caracteres hex
```

Use `/hashcrack <hash>` para quebrar hash MD5!"""
        
        else:
            response = """🤖 **RED-BOT - Assistente de Red Team**

Olá! Sou especializado em:

🔍 **OSINT** - Coleta de informações
🛡️ **Web Security** - Análise de vulnerabilidades  
🔐 **Password Cracking** - Quebra de senhas
🐍 **Python** - Automação e ferramentas

**Como posso ajudar?**
• Tirar dúvidas sobre técnicas de hacking ético
• Melhorar e criar códigos Python
• Automatizar tarefas de segurança
• Organizar documentação técnica

Digite `/help` para ver comandos práticos ou me faça uma pergunta específica sobre segurança cibernética!

⚠️ **Lembre-se:** Sempre teste apenas em sistemas autorizados!"""
        
        return response

def create_interface():
    """Cria a interface Gradio do RED-BOT"""
    
    bot = RedBot()
    
    css = """
    .gradio-container {
        background: linear-gradient(135deg, #1a1a1a 0%, #2d1b1b 100%) !important;
    }
    .chat-message {
        background: rgba(220, 20, 20, 0.1) !important;
        border-left: 3px solid #dc1414 !important;
    }
    .contain {
        max-width: 1200px !important;
    }
    """
    
    with gr.Blocks(
        css=css,
        title="RED-BOT - Red Team Assistant",
        theme=gr.themes.Base(
            primary_hue="red",
            secondary_hue="gray",
            neutral_hue="gray"
        )
    ) as interface:
        
        gr.HTML("""
        <div style="text-align: center; padding: 20px; background: linear-gradient(45deg, #dc1414, #8b0000); border-radius: 10px; margin-bottom: 20px;">
            <h1 style="color: white; margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.5);">
                🛡️ RED-BOT
            </h1>
            <p style="color: #ffeeee; margin: 10px 0 0 0; font-size: 1.2em;">
                Assistente Especializado em Red Team e Ethical Hacking
            </p>
        </div>
        """)
        
        with gr.Row():
            with gr.Column(scale=3):
                chatbot = gr.Chatbot(
                    height=500,
                    show_label=False,
                    elem_classes=["chat-message"],
                    bubble_full_width=False
                )
                
                with gr.Row():
                    msg = gr.Textbox(
                        placeholder="Digite sua pergunta ou comando (ex: /help, /osint, /sqltest)...",
                        show_label=False,
                        scale=4
                    )
                    send_btn = gr.Button("Enviar", variant="primary", scale=1)
            
            with gr.Column(scale=1):
                gr.HTML("""
                <div style="background: rgba(220, 20, 20, 0.1); padding: 15px; border-radius: 10px; border: 1px solid #dc1414;">
                    <h3 style="color: #dc1414; margin-top: 0;">🚀 Comandos Rápidos</h3>
                    <div style="font-family: monospace; font-size: 0.9em; line-height: 1.6;">
                        <strong>/help</strong> - Ajuda<br>
                        <strong>/osint <consulta></strong> - OSINT<br>
                        <strong>/sqltest <URL></strong> - SQL Test<br>
                        <strong>/hashcrack <hash></strong> - Crack MD5<br>
                        <strong>/subdomain <dominio></strong> - Subdomínios
                    </div>
                </div>
                """)
                
                gr.HTML("""
                <div style="background: rgba(255, 255, 0, 0.1); padding: 15px; border-radius: 10px; border: 1px solid #ffa500; margin-top: 20px;">
                    <h4 style="color: #ffa500; margin-top: 0;">⚠️ Aviso Legal</h4>
                    <p style="font-size: 0.85em; line-height: 1.4; margin: 0;">
                        Use apenas em sistemas autorizados. Este bot é para fins educacionais e de segurança defensiva.
                    </p>
                </div>
                """)
        
        def respond(message, chat_history):
            return bot.process_message(message, chat_history)
        
        msg.submit(respond, [msg, chatbot], [msg, chatbot])
        send_btn.click(respond, [msg, chatbot], [msg, chatbot])
    
    return interface

if __name__ == "__main__":
    print("🛡️ Iniciando RED-BOT...")
    print("📊 Carregando interface Gradio...")
    
    interface = create_interface()
    
    print("🚀 RED-BOT está rodando!")
    print("🌐 Acesse: http://localhost:7860")
    print("⚠️  Lembre-se: Use apenas em sistemas autorizados!")
    
    interface.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_api=False,
        show_error=True
    )
`````

## File: setup.sh
`````bash
#!/bin/bash

# RED-BOT Setup Script
# Instala dependências e executa o chatbot

echo "🛡️ RED-BOT - Setup e Instalação"
echo "================================="

# Verifica se o Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 não encontrado. Instale o Python 3 primeiro."
    exit 1
fi

# Verifica se o uv está instalado
if ! command -v uv &> /dev/null; then
    echo "📦 Instalando uv (ultrafast Python package manager)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
else
    echo "✅ uv já está instalado"
fi

# Cria ambiente virtual se não existir
if [ ! -d ".venv" ]; then
    echo "🏗️ Criando ambiente virtual..."
    uv venv
fi

# Ativa o ambiente virtual
echo "🔧 Ativando ambiente virtual..."
source .venv/bin/activate

# Instala dependências
echo "📦 Instalando dependências..."
uv pip install gradio requests beautifulsoup4

# Verifica se as dependências foram instaladas
echo "🔍 Verificando instalação..."

python3 -c "
import gradio
import requests
import bs4
import hashlib
print('✅ Todas as dependências instaladas com sucesso!')
" 2>/dev/null

if [ $? -eq 0 ]; then
    echo ""
    echo "🚀 Iniciando RED-BOT..."
    echo "🌐 O bot estará disponível em: http://localhost:7860"
    echo "⚠️  IMPORTANTE: Use apenas em sistemas autorizados!"
    echo ""
    
    # Executa o bot
    python3 redbot.py
else
    echo "❌ Erro na instalação das dependências"
    echo "Tentando com pip tradicional..."
    
    pip3 install gradio requests beautifulsoup4
    
    if [ $? -eq 0 ]; then
        echo "✅ Dependências instaladas com pip"
        echo "🚀 Iniciando RED-BOT..."
        python3 redbot.py
    else
        echo "❌ Falha na instalação. Verifique sua conexão e tente novamente."
        exit 1
    fi
fi
`````
