# RED-BOT

**RED-BOT** é um **ChatBot especializado em Red Team** desenvolvido utilizando **Gradio**. Ele foi projetado para fornecer assistência em tarefas relacionadas a segurança cibernética, com foco em **Red Team** e **Ethical Hacking**. Ao rodar o bot, você obterá ajuda em questões relacionadas a testes de penetração, exploração de vulnerabilidades e automação de tarefas de segurança.

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Gradio-4.0+-F44B21?style=for-the-badge&logo=gradio&logoColor=white" alt="Gradio">
  <img src="https://img.shields.io/badge/Licença-MIT-025E8C?style=for-the-badge" alt="MIT License">
</div>

## 🌟 Recursos

- Interface web moderna com design cibernético em tons de cinza escuros
- Integração com Feather Icons para melhor experiência visual
- Funcionalidades avançadas de segurança cibernética:
  - OSINT (Open Source Intelligence)
  - Testes de SQL Injection
  - Quebra de hashes MD5
  - Busca de subdomínios
  - Análise de vulnerabilidades XSS, IDOR, CSRF, SSRF, CORS
  - E muito mais!

## 🏗️ Estrutura do Projeto

- **redbot.py**: O script principal do **RED-BOT**, onde toda a lógica do chatbot e interface Gradio é executada
- **prompt.md**: Contém o **prompt** do ChatBot, que define as diretrizes e especializações do assistente. Ele é a base para o comportamento do **RED-BOT**
- **setup.sh**: Script para configurar o ambiente do projeto e instalar as dependências necessárias
- **requirements.txt**: Arquivo com as dependências necessárias para execução do projeto
- **README.md**: Documentação do projeto
- **AGENTS.md**: Documentação sobre agentes e ferramentas de desenvolvimento
- **CLAUDE.md**: Configurações específicas para integração com Claude
- **DEPLOY.md**: Instruções para deployment do projeto
- **docker-compose.yml**: Configuração Docker Compose para containerização
- **Dockerfile**: Arquivo Docker para criação da imagem do projeto
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

## 🧩 Dependências

O projeto utiliza o **Gradio** para a interface do chatbot e outras bibliotecas para funcionalidades relacionadas a segurança cibernética. As principais dependências incluem:

* **Gradio**: Para a criação da interface interativa
* **OpenAI**: Para integração com a API OpenRouter (modelos de IA)
* **requests**: Para fazer requisições HTTP, como consultas de segurança e análise de vulnerabilidades
* **beautifulsoup4**: Para parsing HTML em operações OSINT
* **hashlib**: Para operações de hash em password cracking
* **itertools**: Para operações de força bruta
* **openai**: Para integração com modelos de linguagem
* **maigret**: Para buscas OSINT em redes sociais
* **sublist3r**: Para descoberta de subdomínios
* **playwright**: Para automação de navegador e inspeção avançada de páginas
* **MCP Chrome DevTools**: Integração planejada com Chrome DevTools via Model Context Protocol para inspeção avançada de navegador

Todas as dependências serão instaladas automaticamente ao rodar o `setup.sh`.

## 🔐 Configuração da API OpenRouter (Opcional)

Para habilitar respostas inteligentes baseadas em IA, configure uma chave da API OpenRouter:

1. Acesse [OpenRouter.ai](https://openrouter.ai) e crie uma conta
2. Gere uma API key no dashboard
3. Configure a variável de ambiente:

```bash
export OPENROUTER_API_KEY="sua-chave-aqui"
```

Se a chave não estiver configurada, o bot funcionará em modo rule-based com respostas pré-definidas.

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
* `/osint <consulta>` - Google Dorking ou busca social com Maigret
* `/subdomain <dominio>` - Busca subdomínios com Sublist3r
* `/inspect <url>` - Inspeção avançada de página com browser

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
 /osint john_doe  # Busca social com Maigret
 /sqltest http://exemplo.com/login
 /hashcrack 5d41402abc4b2a76b9719d911017c592
 /subdomain exemplo.com
 /inspect https://exemplo.com
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
* **Sistema de Feedback** - Botões de curtida/não curtida para avaliar respostas

## 🔧 Integração MCP (Model Context Protocol)

O RED-BOT inclui preparação para integração com o Model Context Protocol para capacidades avançadas:

### Chrome DevTools MCP
- **Status**: Placeholder implementado
- **Configuração**:
  ```json
  {
    "mcpServers": {
      "chrome-devtools": {
        "command": "npx",
        "args": ["chrome-devtools-mcp@latest"]
      }
    }
  }
  ```
- **Uso**: Atualmente usa Playwright como fallback para inspeção de navegador
- **Benefícios Futuros**: Controle direto do Chrome DevTools via IA para análise avançada de páginas web

### Implementação Atual
O comando `/inspect <url>` utiliza Playwright para inspeção de páginas, com estrutura preparada para migração para MCP quando o SDK Python estiver disponível.

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

O projeto atualmente não possui testes automatizados. Testes manuais são recomendados através da interface Gradio em `http://localhost:7860`.

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