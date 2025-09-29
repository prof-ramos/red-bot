# RED-BOT

**RED-BOT** é um **ChatBot especializado em Red Team** desenvolvido utilizando **Gradio**. Ele foi projetado para fornecer assistência em tarefas relacionadas a segurança cibernética, com foco em **Red Team** e **Ethical Hacking**. Ao rodar o bot, você obterá ajuda em questões relacionadas a testes de penetração, exploração de vulnerabilidades e automação de tarefas de segurança.

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Gradio-4.0+-F44B21?style=for-the-badge&logo=gradio&logoColor=white" alt="Gradio">
  <img src="https://img.shields.io/badge/Licença-MIT-025E8C?style=for-the-badge" alt="MIT License">
</div>

## 🌟 Recursos

- **Interface web moderna** com design cibernético em tons de cinza escuros
- **Integração com Feather Icons** para melhor experiência visual
- **Otimizações de Performance Avançadas**:
  - Cache inteligente para operações OSINT e hash cracking
  - HTTP assíncrono com connection pooling
  - Processamento paralelo para operações de segurança
  - Gerenciamento otimizado de memória e recursos
- **Funcionalidades avançadas de segurança cibernética**:
  - OSINT (Open Source Intelligence) com cache
  - Testes de SQL Injection otimizados
  - Quebra de hashes MD5 com algoritmos melhorados
  - Busca de subdomínios paralela
  - Análise de vulnerabilidades XSS, IDOR, CSRF, SSRF, CORS
  - E muito mais!

## 🏗️ Estrutura do Projeto

- **redbot.py**: O script principal do **RED-BOT** com otimizações de performance, incluindo cache inteligente, HTTP assíncrono e processamento paralelo
- **prompt.md**: Contém o **prompt** do ChatBot, que define as diretrizes e especializações do assistente. Ele é a base para o comportamento do **RED-BOT**
- **setup.sh**: Script para configurar o ambiente do projeto e instalar as dependências necessárias
- **requirements.txt**: Arquivo com as dependências otimizadas, incluindo `aiohttp`, `cachetools` e outras bibliotecas de performance
- **README.md**: Documentação do projeto
- **AGENTS.md**: Documentação sobre agentes e ferramentas de desenvolvimento
- **CLAUDE.md**: Configurações específicas para integração com Claude
- **DEPLOY.md**: Instruções para deployment do projeto
- **docker-compose.yml**: Configuração Docker Compose otimizada com limites de recursos aprimorados
- **Dockerfile**: Arquivo Docker multi-stage otimizado para performance
- **QWEN.md**: Configurações para integração com Qwen
- **repomix-output.md**: Saída do repomix para análise do repositório

## 🚀 Instruções para Execução

### 1. Pré-requisitos

Certifique-se de ter o Python 3.8+ instalado no seu sistema, além do gerenciador de pacotes `uv`:

```bash
# Instalar uv (gerenciador de pacotes ultrafástico)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Clone o Repositório

Primeiro, clone este repositório para o seu ambiente local:

```bash
git clone https://github.com/seuusuario/red-bot.git
cd red-bot
```

### 3. Rodar o Setup

Execute o script `setup.sh` para garantir que todas as dependências sejam verificadas e instaladas automaticamente. O script também configurará o ambiente para o bot funcionar corretamente.

```bash
bash setup.sh
```

O **setup.sh** realizará as seguintes ações:

* Verificará a instalação do **uv** e outras dependências do projeto
* Instalará as dependências necessárias caso ainda não estejam instaladas
* Criará e ativará um ambiente virtual Python
* Configurará o ambiente para rodar o **RED-BOT**

### 4. Rodar o ChatBot

Após a execução do **setup.sh**, o bot estará pronto para ser executado. Para rodá-lo, utilize o seguinte comando:

```bash
python redbot.py
```

Isso iniciará o **RED-BOT** e o disponibilizará para interações através da interface do Gradio em `http://localhost:7860`.

### **Execução com Docker (Recomendado)**

Para obter o melhor desempenho e isolamento, utilize o Docker:

```bash
# Construir e executar com Docker Compose
docker-compose up --build

# Ou executar em background
docker-compose up -d --build
```

O container Docker está otimizado com:
- **Multi-stage build** para imagem menor e mais segura
- **Non-root user** para melhor segurança
- **Resource limits** configurados para performance ideal
- **Health checks** automáticos
- **Environment variables** para tuning fino de performance

## 🧩 Dependências

O projeto utiliza o **Gradio** para a interface do chatbot e um conjunto otimizado de bibliotecas para funcionalidades relacionadas a segurança cibernética com foco em performance. As principais dependências incluem:

### **Core Dependencies**
* **Gradio**: Para a criação da interface interativa otimizada
* **aiohttp**: Para requisições HTTP assíncronas com connection pooling
* **cachetools**: Para cache TTL inteligente (TTLCache) em operações OSINT e hash
* **OpenAI**: Para integração com a API OpenRouter (modelos de IA)

### **Security & Parsing Libraries**
* **requests**: Para fazer requisições HTTP compatíveis, como consultas de segurança
* **beautifulsoup4**: Para parsing HTML eficiente em operações OSINT
* **hashlib**: Para operações de hash otimizadas em password cracking
* **itertools**: Para operações de força bruta com controle de performance

### **Async & Performance Libraries**
* **asyncio**: Para operações assíncronas e processamento paralelo
* **concurrent.futures**: Para execução paralela de tarefas CPU-bound

Todas as dependências serão instaladas automaticamente ao rodar o `setup.sh` ou através do Docker.

## 🔐 Configuração da API OpenRouter (Opcional)

Para habilitar respostas inteligentes baseadas em IA, configure uma chave da API OpenRouter:

1. Acesse [OpenRouter.ai](https://openrouter.ai) e crie uma conta
2. Gere uma API key no dashboard
3. Configure a variável de ambiente:

```bash
export OPENROUTER_API_KEY="sua-chave-aqui"
```

Se a chave não estiver configurada, o bot funcionará em modo rule-based com respostas pré-definidas.

## ⚡ Otimizações de Performance

O **RED-BOT v2.0** inclui várias otimizações de performance para garantir resposta rápida e eficiente:

### **Cache Inteligente**
- **OSINT Cache**: Resultados de buscas Google Dorking armazenados por 1 hora
- **Hash Cache**: Resultados de quebra de hash armazenados por 2 horas
- **LRU Eviction**: Remoção automática de entradas antigas quando o cache atinge o limite

### **HTTP Otimizado**
- **Connection Pooling**: Reutilização de conexões HTTP para reduzir latência
- **Async Operations**: Requisições assíncronas para operações I/O-bound
- **Timeout Management**: Timeouts configuráveis para evitar travamentos
- **Retry Logic**: Reconexão automática em caso de falhas temporárias

### **Processamento Paralelo**
- **Async/Await**: Operações não-bloqueantes para melhor responsividade
- **ThreadPoolExecutor**: Processamento paralelo para operações CPU-intensive
- **Background Processing**: Execução de tarefas pesadas em segundo plano

### **Gerenciamento de Recursos**
- **Memory Optimization**: Controle de uso de memória com limpeza automática
- **Connection Limits**: Pool de conexões limitado para estabilidade
- **Resource Monitoring**: Logs detalhados de performance e uso de recursos

## ⚙️ Como Funciona

O **RED-BOT** utiliza um **ChatBot** para auxiliar em atividades de **Red Team**, oferecendo conselhos sobre ataques, técnicas de exploração, testes de penetração, etc. O comportamento do bot é definido no arquivo **prompt.md**, que descreve como o assistente deve interagir com os usuários, além de suas áreas de especialização, como:

* **OSINT (Open Source Intelligence)**
* **Segurança de Aplicações Web**
* **Automatização de Tarefas com Python**
* **Quebra de Senhas**
* **Análise de Vulnerabilidades**

## 💬 Comandos Disponíveis

O RED-BOT responde a diversos comandos slash especializados:

### Comandos OSINT
* `/osint <consulta>` - Google Dorking
* `/subdomain <dominio>` - Busca subdomínios

### Comandos Web Security
* `/sqltest <URL>` - Teste SQL Injection

### Comandos Password Cracking
* `/hashcrack <hash>` - Quebra hash MD5

### Análise de Bug Bounty
* `/xss` - Análise de vulnerabilidades XSS
* `/api_exposure` - Exposição de dados via API
* `/idor` - Insecure Direct Object References
* `/csrf` - Cross-Site Request Forgery
* `/ssrf` - Server-Side Request Forgery
* `/auth_reset` - Autenticação quebrada em reset
* `/file_idor` - IDOR em uploads de arquivo
* `/cors` - CORS mal configurado
* `/error_leak` - Vazamento via mensagens de erro
* `/admin_panel` - Painel admin vulnerável

### Comandos Gerais
* `/help` - Mostra esta ajuda

**Exemplo de uso:**
```
 /osint site:exemplo.com filetype:pdf
 /sqltest http://exemplo.com/login
 /hashcrack 5d41402abc4b2a76b9719d911017c592
 /subdomain exemplo.com
 /xss
```

## 🎨 Design da Interface

A interface do RED-BOT foi aprimorada com os seguintes recursos de UI/UX:

* **Design cibernético em tons de cinza escuros** - Usando uma paleta de cores sofisticada com gradientes em tons de preto e cinza
* **Ícones Feather** - Integração dos Feather Icons para uma experiência visual mais rica
* **Responsividade** - Design adaptável para diferentes tamanhos de tela
* **Tipografia monoespaçada** - Usando JetBrains Mono para um visual mais técnico
* **Animações sutis** - Efeitos de transição e glow para melhor experiência do usuário
* **Acessibilidade** - Contraste adequado e elementos com tamanhos apropriados para toque
* **Layout intuitivo** - Organização clara dos elementos com barra lateral de comandos

## 🔧 Como Personalizar

Caso você queira personalizar o **RED-BOT** ou adaptá-lo a novas necessidades, você pode:

1. Editar o arquivo **prompt.md** para ajustar os comportamentos do assistente e suas respostas
2. Modificar o CSS na função `create_interface()` em `redbot.py` para alterar o design
3. Adicionar novos comandos editando o método `process_message()` em `RedBot`
4. Estender as funcionalidades criando novos métodos na classe `RedBot`

Esse arquivo é onde você pode definir as diretrizes e comandos que o bot deve seguir.

## 🛠️ Desenvolvimento

### Linting e Qualidade de Código

Para manter a qualidade do código, utilize as seguintes ferramentas:

```bash
# Instalar ferramentas de linting
pip install flake8 black isort mypy

# Verificar linting
flake8 redbot.py

# Formatar código
black redbot.py

# Organizar imports
isort redbot.py

# Verificar tipos
mypy redbot.py
```

### Testes

O projeto inclui testes de performance e funcionalidade:

#### **Testes de Performance**
```bash
# Testar cache OSINT
curl "http://localhost:7860" # Verificar resposta inicial
# Executar múltiplas consultas OSINT e verificar cache hits nos logs

# Testar operações assíncronas
# Monitorar uso de CPU/memória durante operações pesadas
```

#### **Testes Funcionais**
- Testes manuais através da interface Gradio em `http://localhost:7860`
- Verificação de cache através dos logs em `logs/redbot.log`
- Teste de operações paralelas e assíncronas

#### **Monitoramento de Performance**
- Logs de performance em `logs/redbot.log`
- Métricas de cache hit/miss
- Tempos de resposta para operações HTTP
- Uso de memória e CPU durante operações

## 🤝 Contribuições

Se você tem ideias de melhorias ou quer colaborar com o projeto, fique à vontade para criar um **pull request** ou abrir uma **issue**. Agradecemos por qualquer contribuição que melhore a funcionalidade ou a segurança do **RED-BOT**.

Para contribuir:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Faça commit de suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Faça push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um pull request

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## ⚠️ Aviso Legal

Use apenas em sistemas autorizados. Este bot é para fins educacionais e de segurança defensiva. Sempre respeite as leis locais e obtenha permissão antes de realizar testes de segurança em sistemas que não são de sua propriedade.

## 📞 Contato

Para mais informações ou dúvidas, entre em contato com [seu_email@dominio.com](mailto:seu_email@dominio.com).

---

<div align="center">
  <sub>RED-BOT - Assistente de Red Team e Ethical Hacking</sub>
</div>