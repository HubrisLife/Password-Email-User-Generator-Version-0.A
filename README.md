# 🔐 Gerador de Senha

**Um gerenciador de senhas nativo para Windows — seguro, leve e sem dependências.**

Criado por **Alessandro Dantas**

---

## Funcionalidades

### Gerador de Senhas
- Modo **Clássico** — comprimento de 8 a 2048 caracteres com controle total de caracteres (maiúsculas, minúsculas, números, especiais)
- Modo **Passphrase** — palavras reais encadeadas, fáceis de memorizar e difíceis de quebrar (ex: `Castle-River-Phantom42`)
- Modo **Pronunciável** — sílabas que formam palavras faladas em voz alta (ex: `GribVoxThan8Plor`)
- Modo **Padrão** — você define a estrutura (`A`=maiúscula, `a`=minúscula, `9`=dígito, `!`=especial, `*`=qualquer)

### Gerador de Usuário / Email
- Gera usernames com temas: Animais, Natureza, Tecnologia, Fantasia, Esportes ou Aleatório
- Estilos: CamelCase, minúsculas, snake_case, com.pontos
- Gera endereços de email ficcionais com domínios populares

### Email Temporário Real
- **3 provedores integrados:** Guerrilla Mail, 1SecMail e Mail.tm
- **60+ domínios disponíveis** (Mail.tm busca domínios dinamicamente)
- Inbox com auto-refresh a cada 30 segundos
- Leitura de corpo do email com remoção de HTML
- Nomes realistas gerados automaticamente (ex: `john.smith42@grr.la`)
- Chamadas de rede em thread separada — UI nunca trava

### Cofre Criptografado
- Entradas com 3 campos: rótulo + usuário/email + senha
- Busca/filtro em tempo real
- Edição inline de entradas
- Copiar senha ou usuário separadamente
- Mostrar/ocultar senha

### Segurança
- **PBKDF2-SHA256** com salt aleatório de 16 bytes e 100.000 iterações
- **BCryptGenRandom** para toda aleatoriedade (CSPRNG do Windows)
- **DPAPI** para criptografia do cofre em disco
- Bloqueio após 5 tentativas erradas (5 minutos)
- `SetWindowDisplayAffinity` bloqueia screenshots da janela
- Clipboard limpa automaticamente após 30 segundos
- `SecureZeroMemory` em todos os buffers sensíveis

### UX
- Interface em **Português** e **Inglês** (detecção automática pelo locale do Windows)
- Botão mostrar/ocultar em todos os campos de senha
- Indicador de força da senha mestre no cadastro
- Detecção de Caps Lock ativado
- Modo Visitante — usa o app sem criar conta (dados não são salvos)
- Opção de reset/reinstalação na tela de login

---

## Screenshots

> *(adicione screenshots aqui)*

---

## Como compilar

### Requisitos
- Linux com **MinGW-w64** instalado
- Ou Windows com **MSYS2 + MinGW**

### Compilando no Linux (cross-compile para Windows)

```bash
# Instalar MinGW se necessário
sudo apt install mingw-w64

# Compilar recursos
x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res

# Compilar executável
x86_64-w64-mingw32-gcc gerador_senha.c resources.res \
  -o GeradorSenha.exe \
  -municode -mwindows \
  -lcomctl32 -luser32 -lgdi32 -lcrypt32 -ladvapi32 -lshell32 -lbcrypt -lwinhttp \
  -O2 -static -static-libgcc \
  -finput-charset=UTF-8
```

### Compilando no Windows (MSYS2)

```bash
# No terminal MSYS2 MinGW64
windres resources.rc -O coff -o resources.res

gcc gerador_senha.c resources.res \
  -o GeradorSenha.exe \
  -municode -mwindows \
  -lcomctl32 -luser32 -lgdi32 -lcrypt32 -ladvapi32 -lshell32 -lbcrypt -lwinhttp \
  -O2 -static -static-libgcc
```

---

## Estrutura do projeto

```
GeradorSenha/
├── gerador_senha.c   # Código-fonte principal (~3000 linhas, C puro)
├── resources.rc      # Recursos Windows (ícone, versão, manifesto)
├── app.manifest      # Manifesto Windows (DPI awareness, estilos visuais)
├── app.ico           # Ícone do app
├── README.md
├── LICENSE
└── .gitignore
```

---

## Dados salvos

O app salva dois arquivos em `%LOCALAPPDATA%\GeradorSenha\`:

| Arquivo | Conteúdo |
|---------|----------|
| `config.dat` | Versão, salt, hash PBKDF2, contador de falhas, timestamp, username |
| `vault.dat` | Entradas criptografadas com DPAPI |

Para resetar completamente, delete a pasta `%LOCALAPPDATA%\GeradorSenha\` ou use o botão "Esqueci a senha — apagar tudo e recomeçar" na tela de login.

---

## Aviso sobre antivírus

O executável **não é assinado digitalmente** (certificados de code signing custam $200-400/ano). Isso pode acionar o Windows SmartScreen na primeira execução.

**Para executar:** clique em "Mais informações" → "Executar mesmo assim".

O código-fonte está disponível neste repositório para auditoria completa.

---

## Licença

MIT License — veja [LICENSE](LICENSE) para detalhes.

---

## Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md).
