# tefvx API — Sistema de Licenças

API de verificação de keys + painel admin web.

## Deploy no Render

1. Crie um repo no GitHub com esses arquivos
2. No Render → New Web Service → Connect GitHub
3. Deploy automático!

## Senha padrão do admin

`tefvx@admin` (mude no Render → Environment → ADMIN_PASSWORD)

## Endpoints

- `POST /api/verify` — Verifica key (usado pelo app)
- `/` — Painel admin

## Testar localmente

```bash
pip install -r requirements.txt
python app.py
```

Acesse: http://localhost:5000
