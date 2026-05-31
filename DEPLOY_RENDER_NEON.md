# Deploy do Banco de Horas no Render + Neon

## 1. Subir o projeto para o GitHub

Na pasta do projeto:

```powershell
git init
git add .
git commit -m "Preparar deploy Render Neon"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
git push -u origin main
```

O arquivo `banco_horas.db` está no `.gitignore`, então os dados locais não serão enviados ao GitHub.

## 2. Criar o banco no Neon

1. Acesse o Neon e crie um novo projeto PostgreSQL.
2. Clique em **Connect**.
3. Copie a connection string, preferencialmente a pooled se disponível.
4. Ela deve se parecer com:

```text
postgresql://usuario:senha@host.neon.tech/dbname?sslmode=require
```

## 3. Criar o serviço no Render

1. No Render, clique em **New > Web Service**.
2. Conecte o repositório GitHub.
3. Configure:

```text
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app
```

4. Em **Environment Variables**, adicione:

```text
DATABASE_URL = connection string do Neon
SECRET_KEY   = uma senha longa aleatória
```

O arquivo `render.yaml` também já foi criado para facilitar o Blueprint.

## 4. Primeiro acesso online

No primeiro deploy, o sistema cria as tabelas automaticamente.

Usuário master padrão:

```text
CPF: 000.000.000-00
Senha: Ibipora@2024
```

O sistema solicitará troca de senha se este for o primeiro usuário criado.

## 5. Migrar dados locais para o Neon

Depois que o Neon estiver criado, execute localmente:

```powershell
$env:DATABASE_URL="postgresql://usuario:senha@host.neon.tech/dbname?sslmode=require"
.venv\Scripts\python.exe scripts\migrar_sqlite_para_neon.py --clear
```

Use `--clear` apenas se quiser limpar o Neon antes de copiar os dados locais.

## 6. Observações importantes

- O SQLite local continuará funcionando quando `DATABASE_URL` não existir.
- No Render, o sistema usará PostgreSQL/Neon automaticamente.
- Configure o SMTP no painel **Admin > E-mail** se quiser recuperação de senha por e-mail.
