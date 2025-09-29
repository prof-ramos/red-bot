83
O **setup.sh** realizará as seguintes ações:
84
​
85
* Verificará a instalação do **uv** e outras dependências do projeto
86
* Instalará as dependências necessárias caso ainda não estejam instaladas
87
* Criará e ativará um ambiente virtual Python
88
* Configurará o ambiente para rodar o **RED-BOT**
89
​
90
### 4. Rodar o ChatBot
91
​
92
Após a execução do **setup.sh**, o bot estará pronto para ser executado. Para rodá-lo, utilize o seguinte comando:
93
​
94
```bash
95
python redbot.py
96
```
97
​
98
Isso iniciará o **RED-BOT** e o disponibilizará para interações através da interface do Gradio em `http://localhost:7860`.
99
​
100
### **Execução com Docker (Recomendado)**
101
​
102
Para obter o melhor desempenho e isolamento, utilize o Docker:
103
​
104
```bash
105
# Construir e executar com Docker Compose
106
docker-compose up --build
107
​
108
# Ou executar em background
109
docker-compose up -d --build
110
```
111
​
112
O container Docker está otimizado com:
113
- **Multi-stage build** para imagem menor e mais segura
114
- **Non-root user** para melhor segurança
115
- **Resource limits** configurados para performance ideal
116
- **Health checks** automáticos
117
- **Environment variables** para tuning fino de performance
118
​
119
## 🧩 Dependências
120
​
121
O projeto utiliza o **Gradio** para a interface do chatbot e um conjunto otimizado de bibliotecas para funcionalidades relacionadas a segurança cibernética com foco em performance. As principais dependências incluem:
122
​
123
### **Core Dependencies**
124
* **Gradio**: Para a criação da interface interativa otimizada
125
* **aiohttp**: Para requisições HTTP assíncronas com connection pooling
126
* **cachetools**: Para cache TTL inteligente (TTLCache) em operações OSINT e hash
127
* **OpenAI**: Para integração com a API OpenRouter (modelos de IA)
128
* **requests**: Para fazer requisições HTTP, como consultas de segurança e análise de vulnerabilidades
129
* **beautifulsoup4**: Para parsing HTML em operações OSINT
130
* **hashlib**: Para operações de hash em password cracking
131
* **itertools**: Para operações de força bruta
132
* **openai**: Para integração com modelos de linguagem
133
* **maigret**: Para buscas OSINT em redes sociais
134
* **sublist3r**: Para descoberta de subdomínios
135
* **playwright**: Para automação de navegador e inspeção avançada de páginas
136
* **MCP Chrome DevTools**: Integração planejada com Chrome DevTools via Model Context Protocol para inspeção avançada de navegador
137
​
138
### **Security & Parsing Libraries**
139
* **requests**: Para fazer requisições HTTP compatíveis, como consultas de segurança
140
* **beautifulsoup4**: Para parsing HTML eficiente em operações OSINT
141
* **hashlib**: Para operações de hash otimizadas em password cracking
142
* **itertools**: Para operações de força bruta com controle de performance
143
​
144
### **Async & Performance Libraries**
145
* **asyncio**: Para operações assíncronas e processamento paralelo