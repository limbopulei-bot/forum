# fsociety public chat

Chat público em tempo real com contas, arquivos e painel do dono.

## Rodar

1. Instale Node.js 18+.
2. No diretório do projeto:
   npm install
3. Defina o IP autorizado do dono:
   - Linux/macOS: `OWNER_IPS="SEU_IP" ADMIN_PASSWORD="lll3" npm start`
   - Windows PowerShell: `$env:OWNER_IPS="SEU_IP"; $env:ADMIN_PASSWORD="lll3"; npm start`
4. Abra `http://localhost:3000`.

## Admin

O painel fica acessível pelo atalho Ctrl+Shift+A e, além da senha, exige que o IP da requisição esteja em OWNER_IPS.

Importante: em produção, configure corretamente seu proxy/reverse proxy e HTTPS antes de confiar em `X-Forwarded-For`. Não use uma senha fraca como `lll3` em um site público.

## Recursos

- cadastro/login
- chat público em tempo real via WebSocket
- mensagens
- imagens, PDFs e áudios (até 25 MB)
- aviso global
- banir/desbanir
- expulsar
- cargos moderator/admin
- redirecionamento global
- histórico local em `data/db.json`
