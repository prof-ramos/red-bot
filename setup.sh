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
uv pip install -r requirements.txt

# Instala browsers do Playwright
echo "🌐 Instalando browsers do Playwright..."
playwright install chromium

# Verifica se as dependências foram instaladas
echo "🔍 Verificando instalação..."

python3 -c "
import gradio
import requests
import bs4
import hashlib
import openai
import maigret
import sublist3r
from playwright.sync_api import sync_playwright
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
