# FASE 1: Build - Instalação de dependências
# Usamos uma imagem base slim do Python 3.10
FROM python:3.10-slim as builder

# Define o diretório de trabalho
WORKDIR /app

# Instala dependências do sistema (build-essential para compilações, curl para healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# Copia o arquivo de dependências e instala em um diretório separado para cache
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---

# FASE 2: Final - Imagem de produção
# Usa a mesma imagem base para consistência
FROM python:3.10-slim

# Cria um usuário não-root para segurança
RUN useradd --create-home --shell /bin/bash redbot
USER redbot
WORKDIR /home/redbot/app

# Copia as dependências instaladas da fase de build
COPY --from=builder /root/.local /home/redbot/.local

# Adiciona o diretório de binários do usuário ao PATH
ENV PATH="/home/redbot/.local/bin:${PATH}"

# Copia os arquivos da aplicação
COPY --chown=redbot:redbot . .

# Expõe a porta que o Gradio utiliza
EXPOSE 7860

# Healthcheck para verificar se a aplicação está respondendo
# Tenta acessar a página principal a cada 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:7860 || exit 1

# Comando para iniciar a aplicação
# O host 0.0.0.0 é necessário para que seja acessível de fora do container
CMD ["python3", "redbot.py"]
