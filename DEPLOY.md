# Manual de Deploy - RED-BOT

Este documento detalha o processo de deploy da aplicação RED-BOT utilizando Docker e Portainer.

---

## 1. Pré-requisitos

Antes de iniciar, garanta que seu ambiente atende aos seguintes requisitos:

### 1.1. Software
- **Docker Engine**: Versão `20.10.0` ou superior.
- **Docker Compose**: Versão `1.29.0` ou superior (se não estiver usando a interface do Portainer).
- **Portainer**: Versão `2.9.0` ou superior (recomendado).
- **Git**: Para clonar o repositório.

### 1.2. Hardware (Mínimo Recomendado)
- **CPU**: 1 vCPU
- **RAM**: 1 GB
- **Disco**: 2 GB de espaço livre (para a imagem Docker e cache).

### 1.3. Rede
- Acesso de saída à internet (porta `443/TCP`) para baixar a imagem base, dependências Python e para que o bot acesse APIs externas (Google, OpenRouter).
- A porta `7860/TCP` deve estar livre no host para ser mapeada para a interface web do RED-BOT.

---

## 2. Configuração Inicial

Siga os passos abaixo para preparar o ambiente de deploy.

### 2.1. Clonar o Repositório

Clone o projeto para o servidor onde o Docker está sendo executado.

```bash
git clone <URL_DO_SEU_REPOSITORIO>
cd red-bot
```

### 2.2. Configurar Variáveis de Ambiente

A aplicação requer uma chave de API para se conectar ao OpenRouter. **Não é recomendado** colocar a chave diretamente no arquivo `docker-compose.yml`.

A configuração será feita diretamente na interface do Portainer no passo `3.2` para maior segurança.

### 2.3. Criação de Volumes e Diretórios

Nenhuma ação é necessária. O `docker-compose.yml` não utiliza volumes persistentes, pois a aplicação é stateless (não armazena dados que precisam persistir entre reinicializações).

---

## 3. Deploy via Portainer

O método recomendado para deploy é utilizando uma **Stack** no Portainer.

### 3.1. Importar a Stack no Portainer

1.  Acesse sua instância do Portainer.
2.  No menu lateral, vá para **Stacks**.
3.  Clique em **+ Add stack**.
4.  Dê um nome para a stack, por exemplo, `red-bot-stack`.
5.  No **Web editor**, cole o conteúdo do arquivo `docker-compose.yml` deste repositório.

### 3.2. Configurar Variáveis de Ambiente no Portainer

1.  Ainda na página de criação da stack, role para baixo até a seção **Advanced options**.
2.  Encontre a seção **Environment variables**.
3.  Clique em **+ Add environment variable**.
4.  Configure da seguinte forma:
    - **Name**: `OPENROUTER_API_KEY`
    - **Value**: `sua_chave_secreta_aqui`
5.  Esta abordagem é segura, pois a variável é injetada no container sem ser exposta no arquivo de composição.

### 3.3. Deploy e Verificação

1.  Clique no botão **Deploy the stack**.
2.  O Portainer irá baixar a imagem base, construir a imagem da aplicação e iniciar o container.
3.  Aguarde alguns minutos. Você pode acompanhar o progresso nos logs do container.
4.  Para verificar a saúde, vá para a lista de **Containers**. O container `redbot-app` deve estar com o status **running** e **healthy** (o healthcheck pode levar um minuto para ficar verde).
5.  Acesse a aplicação no seu navegador: `http://<IP_DO_SEU_SERVIDOR>:7860`.

### 3.4. Troubleshooting (Solução de Problemas)

- **Container não inicia ou está "unhealthy"**: Verifique os logs do container. Clique no ícone de **Logs** (📄) ao lado do container na lista. Erros de instalação de dependências ou falhas na inicialização do Python serão mostrados aqui.
- **Erro `OPENROUTER_API_KEY não configurada`**: Verifique se a variável de ambiente foi adicionada corretamente na configuração da stack no Portainer.
- **Página não carrega**: Confirme se não há um firewall bloqueando a porta `7860` no seu servidor.

---

## 4. Manutenção

### 4.1. Como Atualizar a Aplicação

Quando houver atualizações no código-fonte (no repositório Git):

1.  No servidor, puxe as atualizações mais recentes:
    ```bash
    cd red-bot
    git pull
    ```
2.  No Portainer, vá para **Stacks** e selecione a `red-bot-stack`.
3.  Clique em **Editor**.
4.  Ative a opção **Pull latest image version**.
5.  Clique em **Update the stack**. O Portainer irá reconstruir a imagem com o novo código e recriar o container sem downtime perceptível.

### 4.2. Backup de Dados Persistentes

- **Código-fonte**: O backup do código já é garantido pelo versionamento no Git.
- **Dados da Aplicação**: A aplicação é **stateless**, ou seja, não gera dados que precisam de backup. Toda a configuração é feita via código ou variáveis de ambiente.

### 4.3. Monitoramento Básico

- **Uso de Recursos**: Na tela de **Containers** do Portainer, você pode monitorar o consumo de CPU e RAM do container `redbot-app`.
- **Status**: A coluna **Status** indica se o container está em execução e se o healthcheck está passando (`healthy`).

### 4.4. Logs Importantes a Observar

Os logs do container são a principal fonte de informação para diagnóstico.

- **Acesso**: Vá para **Containers** -> `redbot-app` -> **Logs** (📄).
- **O que observar**:
    - Mensagens de inicialização do Gradio.
    - Erros de conexão com a API do OpenRouter.
    - Stack traces de erros Python, caso ocorram.
    - Saídas do `HEALTHCHECK` indicando o status da aplicação.
