# Verificação em duas etapas

Antes de reiniciar o Auth atualizado, execute `migrations/001-mfa.sql` no banco configurado em DB_NAME. Faça backup antes da migração. A tabela é adicional e não modifica os usuários existentes.

Gere uma chave com `openssl rand -hex 32` e salve no `.env` do Auth como `MFA_ENCRYPTION_KEY=<valor>`. Não publique essa chave. Guarde uma cópia segura junto dos backups: perdê-la impede validar os autenticadores cadastrados. Não gere outra chave em cada deploy.

Execute `npm ci && npm test` e reinicie o Auth com `pm2 restart 2 --update-env` (ou o nome correspondente). Faça o build e deploy normal do frontend. O NGINX continua encaminhando `/auth/` ao Auth, sem alterações.

No frontend, clique em Administrador para abrir Segurança da conta. Confirme sua senha, escaneie o QR Code, guarde os códigos de recuperação e confirme um código do aplicativo. No próximo login, senha e segundo fator serão necessários. Para desativar, informe senha e um código válido.

Os desafios expiram em cinco minutos, permitem cinco tentativas e ficam em memória. Reiniciar o Auth invalida os desafios pendentes; basta iniciar o login novamente. Esta implementação destina-se a uma única instância Auth; múltiplas instâncias exigem armazenamento compartilhado dos desafios e limites. Os limites por IP são conservadores atrás do NGINX, pois Express não confia automaticamente em cabeçalhos de proxy.

O segundo fator protege novos logins. JWTs já emitidos continuam válidos até expirar (duas horas). Os segredos usam AES-256-GCM e os códigos de recuperação aleatórios são armazenados como SHA-256. A validação usa bloqueio de linha no banco para impedir reutilização concorrente do mesmo código.
