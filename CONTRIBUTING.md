# Contribuindo com o Gerador de Senha

Obrigado pelo interesse! Contribuições são bem-vindas.

## Como contribuir

1. Faça um fork do repositório
2. Crie uma branch para sua feature: `git checkout -b minha-feature`
3. Faça suas alterações no `gerador_senha.c`
4. Compile e teste localmente (veja instruções no README)
5. Abra um Pull Request com uma descrição clara do que foi feito

## Áreas abertas para contribuição

- Suporte a mais provedores de email temporário
- Dark mode
- Auto-lock por inatividade
- Exportar/importar cofre (CSV, JSON)
- Categorias/tags para entradas do cofre
- Verificação de senhas vazadas via HaveIBeenPwned
- Tradução para outros idiomas (já há suporte a PT e EN)

## Estilo de código

- C99 puro, sem dependências externas além da WinAPI
- Sem alocação desnecessária — prefira buffers estáticos quando o tamanho é conhecido
- Limpe sempre buffers sensíveis com `SecureZeroMemory` antes de liberar
- Mantenha as strings de UI nos arrays `L_PT` e `L_EN` — nunca hardcode texto visível ao usuário fora deles

## Reportando bugs

Abra uma issue com:
- Versão do Windows
- O que você fez
- O que aconteceu
- O que era esperado
