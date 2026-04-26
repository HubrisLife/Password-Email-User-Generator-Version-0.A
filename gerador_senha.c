/*
 * Gerador de Senha v2 - Password Manager
 * Security: PBKDF2 + BCryptGenRandom + lockout + display affinity
 * UX: 3-field vault, search, edit, change master, show/hide, caps detect
 * Content: PT/EN pools, larger pools, locale-based default
 */

#define UNICODE
#define _UNICODE
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <shlobj.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <ctype.h>
#include <winhttp.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef WDA_NONE
#define WDA_NONE 0x00
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x01
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif
WINUSERAPI BOOL WINAPI SetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity);

/* ===== IDs ===== */
#define ID_LANG_BTN       1001
#define ID_LOGOUT_BTN     1002
#define ID_REG_BTN        1010
#define ID_LOGIN_BTN      1011
#define ID_REG_SHOW_PWD   1012
#define ID_REG_SHOW_CONF  1013
#define ID_LOG_SHOW_PWD   1014
#define ID_LOG_GUEST_BTN  1015
#define ID_REG_GUEST_BTN  1016
#define ID_TAB_GEN        1020
#define ID_TAB_USER       1021
#define ID_TAB_EMAIL      1022
#define ID_TAB_VAULT      1023
#define ID_TAB_SETTINGS   1024
#define ID_TAB_TEMP       1025
#define ID_TEMP_GET       1100
#define ID_TEMP_COPY      1101
#define ID_TEMP_REFRESH   1102
#define ID_TEMP_LIST      1103
#define ID_TEMP_DEL       1104
#define ID_TEMP_PROVIDER  1105
#define ID_TIMER_REFRESH  9003
/* Async worker messages posted back to main window */
#define WM_TEMP_RESULT    (WM_USER + 1)  /* wParam=1 success, lParam=unused */
#define WM_TEMP_INBOX     (WM_USER + 2)  /* wParam=1 success */
#define WM_TEMP_BODY      (WM_USER + 3)  /* wParam=1 success */

typedef struct {
    int action;        /* 0=generate, 1=refresh, 2=fetchBody */
    char domain[64];
    char mailId[32];
} WorkerArgs;
static WorkerArgs g_workerArgs;
static int g_workerBusy = 0;
#define ID_GEN_BTN        1030
#define ID_GEN_COPY       1031
#define ID_GEN_SAVE       1032
#define ID_GEN_SLIDER     1033
#define ID_GEN_CHK_UPPER  1040
#define ID_GEN_CHK_LOWER  1041
#define ID_GEN_CHK_NUMBER 1042
#define ID_GEN_CHK_SPEC   1043
#define ID_GEN_RAD_LIMIT  1044
#define ID_GEN_RAD_FULL   1045
#define ID_GEN_SHOW       1046
#define ID_GEN_MODE       1047
#define ID_GEN_PATTERN    1048
#define ID_USER_THEME     1080
#define ID_USER_STYLE     1081
#define ID_USER_NUM       1082
#define ID_USER_BASE      1083
#define ID_USER_GEN       1084
#define ID_USER_COPY      1085
#define ID_USER_SAVE      1086
#define ID_EMAIL_THEME    1090
#define ID_EMAIL_STYLE    1091
#define ID_EMAIL_NUM      1092
#define ID_EMAIL_BASE     1093
#define ID_EMAIL_DOMAIN   1094
#define ID_EMAIL_GEN      1095
#define ID_EMAIL_COPY     1096
#define ID_EMAIL_SAVE     1097
#define ID_VAULT_LIST     1050
#define ID_VAULT_SHOW     1051
#define ID_VAULT_COPY_PWD 1052
#define ID_VAULT_COPY_USR 1053
#define ID_VAULT_DEL      1054
#define ID_VAULT_EDIT     1055
#define ID_VAULT_SEARCH   1056
#define ID_SET_CHANGE_BTN 1070
#define ID_SET_RESET_BTN  1071
#define ID_TIMER_MSG      9001
#define ID_TIMER_CLIP     9002

#define STATE_REGISTER 1
#define STATE_LOGIN    2
#define STATE_LOCKED   4
#define STATE_MAIN     3
#define SUB_GEN        1
#define SUB_USER       2
#define SUB_EMAIL      3
#define SUB_VAULT      4
#define SUB_SETTINGS   5
#define SUB_TEMP       6

#define CS_LOWER  "abcdefghijklmnopqrstuvwxyz"
#define CS_UPPER  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CS_DIGITS "0123456789"
#define CS_LIMIT  "_.-"
#define CS_FULL   "!@#$%^&*()-_=+[]{}|;:,.<>?"

#define PBKDF2_ITERATIONS 100000
#define SALT_LEN 16
#define HASH_LEN 32
#define MAX_FAIL_ATTEMPTS 5
#define LOCKOUT_SECONDS 300
#define CLIPBOARD_CLEAR_SEC 30

/* ===== Word pools ===== */
/* English */
static const char *ADJ_EN[] = {
    "Swift","Brave","Silent","Wild","Noble","Fierce","Clever","Mighty","Bright",
    "Cosmic","Golden","Silver","Crimson","Azure","Emerald","Stormy","Sunny","Frosty",
    "Electric","Mystic","Ancient","Royal","Shadow","Lunar","Solar","Savage","Quiet",
    "Epic","Wicked","Loyal","Rapid","Steel","Iron","Bold","Calm","Free","Hidden",
    "Lucky","Eager","Fearless","Vivid","Radiant","Stealthy","Burning","Frozen","Wise",
    "Daring","Restless","Velvet","Stellar","Astral","Twilight","Dawn","Midnight","Crystal",
    "Glacial","Phantom","Ethereal","Primal","Furious","Tranquil","Spectral","Vibrant"
};
static const char *POOL_ANIMAL_EN[] = {
    "Tiger","Wolf","Eagle","Bear","Lion","Falcon","Panther","Dragon","Phoenix","Fox",
    "Hawk","Raven","Shark","Otter","Lynx","Cobra","Jaguar","Rhino","Leopard","Stallion",
    "Viper","Puma","Coyote","Buffalo","Mustang","Badger","Owl","Griffin","Hyena","Whale",
    "Stag","Bison","Cheetah","Heron","Mantis","Scorpion","Wyvern","Kraken","Basilisk","Manta",
    "Orca","Lemur","Marten","Caracal","Serval","Ocelot","Kodiak","Saber","Spectre","Specter"
};
static const char *POOL_NATURE_EN[] = {
    "River","Mountain","Ocean","Storm","Forest","Thunder","Meadow","Valley","Canyon",
    "Glacier","Volcano","Desert","Island","Lake","Comet","Galaxy","Nebula","Star",
    "Moon","Aurora","Cloud","Horizon","Summit","Reef","Tide","Stone","Cliff","Fjord",
    "Tundra","Geyser","Cavern","Rapids","Cascade","Mesa","Atoll","Plateau","Dune","Marsh",
    "Quasar","Pulsar","Eclipse","Solstice","Zenith","Tempest","Cyclone","Blizzard"
};
static const char *POOL_TECH_EN[] = {
    "Coder","Hacker","Pixel","Byte","Cyber","Neon","Quantum","Matrix","Vector","Nexus",
    "Proxy","Node","Cipher","Binary","Core","Chip","Grid","Logic","Bot","Glitch",
    "Script","Patch","Circuit","Beacon","Zero","Sync","Cache","Vortex","Kernel","Buffer",
    "Daemon","Packet","Socket","Thread","Compiler","Runtime","Token","Hash","Stream","Schema",
    "Codec","Crypto","Engine","Pulse","Vector","Drone","Glyph","Shard"
};
static const char *POOL_FANTASY_EN[] = {
    "Wizard","Knight","Mage","Warrior","Rogue","Paladin","Archer","Sage","Ranger",
    "Monk","Druid","Warlock","Bard","Sorcerer","Hunter","Assassin","Cleric","Berserker",
    "Templar","Oracle","Phantom","Reaper","Spectre","Champion","Necromancer","Conjurer",
    "Inquisitor","Crusader","Centurion","Gladiator","Samurai","Ronin","Shogun","Pirate",
    "Pirate","Corsair","Nomad","Pilgrim","Sentinel","Vanguard","Herald","Seer"
};
static const char *POOL_SPORTS_EN[] = {
    "Runner","Striker","Winner","Athlete","Rider","Sprinter","Jumper","Climber",
    "Skater","Surfer","Racer","Boxer","Kicker","Fighter","Hero","Captain","Scout",
    "Chaser","Ace","Pro","Rookie","Star","MVP","Goal","Champion","Vetera","Legend",
    "Pitcher","Catcher","Slugger","Sharpshooter","Quarterback","Linebacker","Halfback","Goalie",
    "Forward","Defender","Pivot","Center","Winger","Coach","Striker","Ranger"
};

/* Portuguese */
static const char *ADJ_PT[] = {
    "Rapido","Bravo","Silencioso","Selvagem","Nobre","Feroz","Esperto","Poderoso",
    "Brilhante","Cosmico","Dourado","Prateado","Carmesim","Azul","Esmeralda","Tempestuoso",
    "Ensolarado","Gelado","Eletrico","Mistico","Antigo","Real","Sombrio","Lunar","Solar",
    "Selvagem","Quieto","Epico","Sinistro","Leal","Veloz","Aco","Ferro","Audaz","Calmo",
    "Livre","Oculto","Sortudo","Ansioso","Destemido","Vivido","Radiante","Furtivo","Ardente",
    "Congelado","Sabio","Ousado","Inquieto","Veludo","Estelar","Astral","Crepuscular","Aurora",
    "Cristalino","Glacial","Fantasma","Etereo","Primal","Furioso","Tranquilo","Espectral","Vibrante"
};
static const char *POOL_ANIMAL_PT[] = {
    "Tigre","Lobo","Aguia","Urso","Leao","Falcao","Pantera","Dragao","Fenix","Raposa",
    "Gaviao","Corvo","Tubarao","Lontra","Lince","Cobra","Onca","Rinoceronte","Leopardo",
    "Garanhao","Vibora","Puma","Coiote","Bufalo","Mustangue","Texugo","Coruja","Grifo","Hiena",
    "Baleia","Veado","Bisao","Guepardo","Garca","Louvadeus","Escorpiao","Wyvern","Kraken","Basilisco",
    "Manta","Orca","Lemure","Doninha","Caracal","Serval","Jaguatirica","Sabre","Espectro","Quimera"
};
static const char *POOL_NATURE_PT[] = {
    "Rio","Montanha","Oceano","Tempestade","Floresta","Trovao","Prado","Vale","Canion",
    "Geleira","Vulcao","Deserto","Ilha","Lago","Cometa","Galaxia","Nebulosa","Estrela",
    "Lua","Aurora","Nuvem","Horizonte","Cume","Recife","Mare","Pedra","Penhasco","Fiorde",
    "Tundra","Geiser","Caverna","Corredeira","Cascata","Mesa","Atol","Planalto","Duna","Pantano",
    "Quasar","Pulsar","Eclipse","Solsticio","Zenite","Tempestade","Ciclone","Nevasca"
};
static const char *POOL_TECH_PT[] = {
    "Codigo","Hacker","Pixel","Byte","Ciber","Neon","Quantum","Matriz","Vetor","Nexus",
    "Proxy","Node","Cifra","Binario","Core","Chip","Grade","Logica","Bot","Glitch",
    "Script","Patch","Circuito","Farol","Zero","Sync","Cache","Vortex","Kernel","Buffer",
    "Daemon","Pacote","Socket","Thread","Compilador","Token","Hash","Stream","Codec","Cripto",
    "Motor","Pulso","Drone","Glifo"
};
static const char *POOL_FANTASY_PT[] = {
    "Mago","Cavaleiro","Feiticeiro","Guerreiro","Ladino","Paladino","Arqueiro","Sabio",
    "Patrulheiro","Monge","Druida","Bruxo","Bardo","Caçador","Assassino","Clerigo",
    "Berserker","Templario","Oraculo","Fantasma","Ceifador","Espectro","Campeao","Nigromante",
    "Conjurador","Inquisidor","Cruzado","Centuriao","Gladiador","Samurai","Ronin","Pirata",
    "Corsario","Nomade","Peregrino","Sentinela","Vanguarda","Arauto","Vidente"
};
static const char *POOL_SPORTS_PT[] = {
    "Corredor","Atacante","Vencedor","Atleta","Ciclista","Velocista","Saltador","Escalador",
    "Patinador","Surfista","Piloto","Boxeador","Chutador","Lutador","Heroi","Capitao",
    "Batedor","Caçador","Asse","Pro","Novato","Estrela","Craque","Gol","Campeao","Veterano",
    "Lenda","Goleiro","Atacante","Zagueiro","Meia","Ponta","Centroavante","Tecnico"
};

#define ARRSZ(a) (sizeof(a)/sizeof(a[0]))

static const char *EMAIL_DOMAINS[] = {
    "gmail.com","outlook.com","hotmail.com","yahoo.com","icloud.com",
    "protonmail.com","tutanota.com","mail.com","fastmail.com"
};

/* Real names for temp email usernames */
static const char *FIRST_NAMES[] = {
    "michael","james","william","david","robert","john","thomas","joseph",
    "charles","daniel","matthew","anthony","mark","donald","steven","paul",
    "andrew","kenneth","joshua","kevin","brian","george","edward","ronald",
    "timothy","jason","jeffrey","ryan","jacob","gary","nicholas","eric",
    "stephen","larry","scott","brandon","frank","benjamin","samuel","patrick",
    "alexander","jack","dennis","tyler","aaron","henry","douglas","peter",
    "noah","ethan","lucas","mason","logan","oliver","elijah","owen","carter",
    "wyatt","jayden","liam","sebastian","julian","leo","gabriel","caleb",
    "mary","jennifer","linda","patricia","elizabeth","barbara","susan",
    "jessica","sarah","karen","lisa","nancy","betty","sandra","ashley",
    "kimberly","emily","donna","michelle","carol","amanda","melissa",
    "stephanie","rebecca","laura","sharon","cynthia","kathleen","amy",
    "anna","angela","ruth","brenda","pamela","nicole","katherine","samantha",
    "christine","rachel","carolyn","janet","heather","diane","olivia",
    "emma","sophia","isabella","mia","charlotte","amelia","harper","evelyn",
    "abigail","ella","grace","chloe","camila","luna","aria","layla","sofia"
};
static const char *LAST_NAMES[] = {
    "smith","johnson","williams","brown","jones","garcia","miller","davis",
    "rodriguez","martinez","hernandez","lopez","gonzalez","wilson","anderson",
    "thomas","taylor","moore","jackson","martin","lee","perez","thompson",
    "white","harris","sanchez","clark","ramirez","lewis","robinson","walker",
    "young","allen","king","wright","scott","torres","nguyen","hill","flores",
    "green","adams","nelson","baker","hall","rivera","campbell","mitchell",
    "carter","roberts","gomez","phillips","evans","turner","diaz","parker",
    "cruz","edwards","collins","reyes","stewart","morris","morales","murphy",
    "cook","rogers","ortiz","morgan","cooper","peterson","bailey","reed",
    "kelly","howard","ramos","kim","cox","ward","richardson","watson","brooks",
    "wood","james","bennett","gray","ruiz","hughes","price","sanders","patel",
    "myers","long","ross","foster","powell","jenkins","perry","russell",
    "barnes","fisher","henderson","coleman","simmons","graham","wells","webb"
};

/* Generate realistic email username — defined after secureRandInt */
static void generateRealName(char *out, int outSize);


/* Guerrilla Mail domains */
static const char *GUERRILLA_DOMAINS[] = {
    "(padrao/default)",
    "sharklasers.com","guerrillamail.com","guerrillamail.info",
    "guerrillamail.biz","guerrillamail.de","guerrillamail.net",
    "guerrillamail.org","guerrillamailblock.com","grr.la",
    "spam4.me","pokemail.net"
};
/* 1SecMail domains */
static const char *SECMAIL_DOMAINS[] = {
    "1secmail.com","1secmail.org","1secmail.net",
    "kzccv.com","qiott.com","wuuvo.com","icznn.com","ezztt.com"
};
/* Mail.tm domains fetched at runtime */
#define MAILTM_MAX_DOMAINS 60
static char g_mailtmDomains[MAILTM_MAX_DOMAINS][64];
static int  g_mailtmDomainCount = 0;

/* ===== Localization ===== */
enum {
    S_APP_TITLE, S_REG_TITLE, S_REG_SUB, S_REG_USER, S_REG_PWD, S_REG_CONFIRM, S_REG_BTN,
    S_LOG_TITLE, S_LOG_SUB, S_LOG_PWD, S_LOG_BTN, S_LOG_WELCOME,
    S_LOCKED_TITLE, S_LOCKED_SUB,
    S_TAB_GEN, S_TAB_USER, S_TAB_EMAIL, S_TAB_VAULT, S_TAB_SETTINGS, S_LANG_BTN, S_LOGOUT,
    S_GEN_TITLE, S_GEN_USER, S_GEN_LEN, S_GEN_OPTS,
    S_OPT_UPPER, S_OPT_LOWER, S_OPT_NUMBER, S_OPT_SPEC, S_OPT_LIMIT, S_OPT_FULL,
    S_GEN_MODE, S_MODE_CLASSIC, S_MODE_PHRASE, S_MODE_PRONOUNCE, S_MODE_PATTERN,
    S_GEN_PATTERN_LBL, S_GEN_PATTERN_HINT,
    S_GEN_OUT, S_BTN_GEN, S_BTN_COPY, S_BTN_SAVE, S_BTN_SHOW_PWD, S_BTN_HIDE_PWD,
    S_CHK_UPPER, S_CHK_LOWER, S_CHK_NUMBER, S_CHK_SPEC, S_CHK_LEN, S_CHK_LETNUM,
    S_USER_TITLE, S_USER_THEME, S_USER_STYLE, S_USER_NUM, S_USER_BASE, S_USER_OUT,
    S_TH_ANIMAL, S_TH_NATURE, S_TH_TECH, S_TH_FANTASY, S_TH_SPORTS, S_TH_RANDOM,
    S_ST_CAMEL, S_ST_LOWER, S_ST_SNAKE, S_ST_DOT,
    S_EMAIL_TITLE, S_EMAIL_DOMAIN, S_EMAIL_OUT,
    S_VAULT_TITLE, S_VAULT_EMPTY, S_VAULT_PWD, S_VAULT_USR, S_VAULT_SEARCH, S_VAULT_COPY_PWD, S_VAULT_COPY_USR,
    S_BTN_SHOW, S_BTN_HIDE, S_BTN_DEL, S_BTN_EDIT,
    S_SET_TITLE, S_SET_CHANGE_TITLE, S_SET_CUR_PWD, S_SET_NEW_PWD, S_SET_NEW_CONF, S_SET_CHANGE_BTN, S_SET_CHANGED,
    S_MSG_COPIED, S_MSG_SAVED, S_MSG_DELETED, S_MSG_EDITED, S_MSG_NO_PWD, S_MSG_PWD_MATCH,
    S_MSG_PWD_SHORT, S_MSG_WRONG, S_MSG_NEED_TYPE, S_MSG_NEED_LEN, S_MSG_USER_EMPTY, S_MSG_LOCKED, S_MSG_CAPS,
    S_DLG_LABEL, S_DLG_LABEL_TITLE, S_DLG_USER, S_DLG_PASSWORD,
    S_DLG_CONFIRM_DEL, S_DLG_TITLE_CONFIRM, S_DLG_EDIT_TITLE,
    S_STR_VERY_WEAK, S_STR_WEAK, S_STR_OK, S_STR_GOOD, S_STR_STRONG,
    S_SET_RESET_TITLE, S_SET_RESET_DESC, S_SET_RESET_BTN, S_DLG_CONFIRM_RESET,
    S_TAB_TEMP, S_TEMP_TITLE, S_TEMP_ADDR, S_TEMP_GET, S_TEMP_COPY_ADDR,
    S_TEMP_INBOX, S_TEMP_REFRESH, S_TEMP_EMPTY, S_TEMP_LOADING, S_TEMP_ERROR,
    S_TEMP_FROM, S_TEMP_DEL, S_TEMP_AUTO, S_TEMP_DOMAIN,
    S_TEMP_PROVIDER, S_PROV_GUERRILLA, S_PROV_SECMAIL, S_PROV_MAILTM,
    S_TEMP_FETCHING,
    S_GUEST_BTN, S_GUEST_WARN, S_GUEST_TITLE,
    S_COUNT
};

static const wchar_t *L_PT[S_COUNT] = {
    L"Gerador de Senha", L"Criar conta",
    L"Defina seu nome de usuário e senha mestre para proteger seu cofre",
    L"Nome de usuário:", L"Senha mestre:", L"Confirmar senha:", L"Cadastrar",
    L"Entrar", L"Digite sua senha mestre para acessar o cofre", L"Senha mestre:", L"Entrar", L"Olá, %ls",
    L"Conta bloqueada", L"Muitas tentativas erradas. Aguarde %d segundos.",
    L"Senha", L"Usuário", L"Email", L"Cofre", L"Config", L"EN", L"Sair",
    L"Gerar nova senha", L"Nome de usuário (opcional):", L"Comprimento:", L"Tipos de caracteres:",
    L"Maiúsculas (A-Z)", L"Minúsculas (a-z)", L"Números (0-9)", L"Caracteres especiais",
    L"Limitados ( _ . - )", L"Completos ( ! @ # ... )",
    L"Modo:", L"Clássico", L"Passphrase", L"Pronunciável", L"Padrão",
    L"Padrão (A=maiúscula, a=minúscula, 9=número, !=especial, *=qualquer):",
    L"Ex: Aa99!!Aa99!! ou ****-****-****",
    L"Senha gerada:", L"Gerar", L"Copiar", L"Salvar", L"👁", L"🚫",
    L"Letra minúscula", L"Letra maiúscula", L"Número", L"Caractere especial",
    L"8-2048 caracteres", L"Letra e número",
    L"Gerar nome de usuário", L"Tema:", L"Estilo:", L"Incluir números", L"Usar meu nome como base",
    L"Usuário gerado:",
    L"Animais", L"Natureza", L"Tecnologia", L"Fantasia", L"Esportes", L"Aleatório",
    L"CamelCase", L"minúsculas", L"snake_case", L"com.pontos",
    L"Gerar email", L"Domínio:", L"Email gerado:",
    L"Senhas salvas", L"Nenhuma entrada salva. Gere uma e clique em Salvar.", L"Senha:", L"Usuário:",
    L"Buscar...", L"Copiar senha", L"Copiar usuário",
    L"Mostrar", L"Ocultar", L"Excluir", L"Editar",
    L"Configurações", L"Trocar senha mestre", L"Senha atual:", L"Nova senha:", L"Confirmar nova:",
    L"Trocar senha", L"Senha mestre alterada com sucesso.",
    L"Copiado!", L"Salvo!", L"Excluído.", L"Atualizado!",
    L"Gere primeiro.", L"As senhas não coincidem.",
    L"Senha mestre muito curta (mínimo 6 caracteres).",
    L"Senha mestre incorreta.", L"Selecione ao menos um tipo de caractere.",
    L"Comprimento muito curto para os requisitos.",
    L"Nome de usuário é obrigatório.",
    L"Conta bloqueada por %d segundos.",
    L"⚠ Caps Lock ativado",
    L"Rótulo (ex: Gmail):", L"Salvar entrada", L"Usuário/email:", L"Senha:",
    L"Excluir esta entrada?", L"Confirmar", L"Editar entrada",
    L"Muito fraca", L"Fraca", L"Razoável", L"Boa", L"Forte",
    L"Reinstalar / Reset",
    L"Apaga TODOS os dados e começa do zero. Remove a senha mestre e tudo do cofre.",
    L"Esqueci a senha — apagar tudo e recomeçar",
    L"Isso vai APAGAR PERMANENTEMENTE sua senha mestre e TODAS as entradas do cofre. Continuar?",
    L"Email Temp", L"Email temporário real", L"Endereço gerado:",
    L"Gerar novo endereço", L"Copiar endereço",
    L"Caixa de entrada", L"Atualizar", L"Nenhum email recebido ainda.",
    L"Carregando...", L"Erro ao conectar. Verifique a internet.",
    L"De:", L"Apagar", L"Atualização automática a cada 30s", L"Domínio:",
    L"Provedor:", L"Guerrilla Mail", L"1SecMail", L"Mail.tm",
    L"Buscando domínios...",
    L"Continuar como visitante",
    L"⚠ MODO VISITANTE: nada será salvo. Senhas geradas, entradas no cofre e qualquer dado serão PERDIDOS ao fechar o app. Continuar mesmo assim?",
    L"[VISITANTE] Gerador de Senha"
};

static const wchar_t *L_EN[S_COUNT] = {
    L"Password Generator", L"Create account",
    L"Set your username and master password to protect your vault",
    L"Username:", L"Master password:", L"Confirm password:", L"Register",
    L"Sign in", L"Enter your master password to access the vault", L"Master password:", L"Sign in", L"Hello, %ls",
    L"Account locked", L"Too many failed attempts. Wait %d seconds.",
    L"Password", L"Username", L"Email", L"Vault", L"Settings", L"PT", L"Sign out",
    L"Generate new password", L"Username (optional):", L"Length:", L"Character types:",
    L"Uppercase (A-Z)", L"Lowercase (a-z)", L"Numbers (0-9)", L"Special characters",
    L"Limited ( _ . - )", L"Full ( ! @ # ... )",
    L"Mode:", L"Classic", L"Passphrase", L"Pronounceable", L"Pattern",
    L"Pattern (A=upper, a=lower, 9=digit, !=special, *=any):",
    L"Ex: Aa99!!Aa99!! or ****-****-****",
    L"Generated password:", L"Generate", L"Copy", L"Save", L"👁", L"🚫",
    L"Lowercase letter", L"Uppercase letter", L"Number", L"Special character",
    L"8-2048 characters", L"Letter and number",
    L"Generate username", L"Theme:", L"Style:", L"Include numbers", L"Use my name as base",
    L"Generated username:",
    L"Animals", L"Nature", L"Tech", L"Fantasy", L"Sports", L"Random",
    L"CamelCase", L"lowercase", L"snake_case", L"dot.style",
    L"Generate email", L"Domain:", L"Generated email:",
    L"Saved entries", L"No entries saved. Generate one and click Save.", L"Password:", L"Username:",
    L"Search...", L"Copy password", L"Copy username",
    L"Show", L"Hide", L"Delete", L"Edit",
    L"Settings", L"Change master password", L"Current password:", L"New password:", L"Confirm new:",
    L"Change password", L"Master password changed successfully.",
    L"Copied!", L"Saved!", L"Deleted.", L"Updated!",
    L"Generate first.", L"Passwords do not match.",
    L"Master password too short (minimum 6 characters).",
    L"Wrong master password.", L"Select at least one character type.",
    L"Length too short for requirements.",
    L"Username is required.",
    L"Account locked for %d seconds.",
    L"⚠ Caps Lock is on",
    L"Label (e.g. Gmail):", L"Save entry", L"Username/email:", L"Password:",
    L"Delete this entry?", L"Confirm", L"Edit entry",
    L"Very weak", L"Weak", L"OK", L"Good", L"Strong",
    L"Reinstall / Reset",
    L"Deletes ALL data and starts from scratch. Removes master password and entire vault.",
    L"Forgot password — erase everything and start over",
    L"This will PERMANENTLY DELETE your master password and ALL vault entries. Continue?",
    L"Temp Mail", L"Real temporary email", L"Generated address:",
    L"Generate new address", L"Copy address",
    L"Inbox", L"Refresh", L"No emails received yet.",
    L"Loading...", L"Connection error. Check your internet.",
    L"From:", L"Delete", L"Auto-refresh every 30s", L"Domain:",
    L"Provider:", L"Guerrilla Mail", L"1SecMail", L"Mail.tm",
    L"Fetching domains...",
    L"Continue as guest",
    L"⚠ GUEST MODE: nothing will be saved. Generated passwords, vault entries, and any data will be LOST when you close the app. Continue anyway?",
    L"[GUEST] Password Generator"
};

static const wchar_t **LANGS[2] = { L_PT, L_EN };
#define T(id) LANGS[g_lang][id]

/* ===== Globals ===== */
static int g_lang = 0;
static int g_state = 0;
static int g_subState = SUB_GEN;
static int g_isGuest = 0;
static char g_master[256] = "";
static char g_username[64] = "";
static wchar_t g_configPath[MAX_PATH];
static wchar_t g_vaultPath[MAX_PATH];
static wchar_t g_currentPwd[2048] = L"";
static wchar_t g_currentUser[160] = L"";
static wchar_t g_currentEmail[200] = L"";
static int g_msgTimerActive = 0;
static int g_clipTimerActive = 0;
static wchar_t g_lastClipped[200] = L"";
static int g_lockoutSeconds = 0;
static FILETIME g_lockoutStart;

static COLORREF clrBg = RGB(248, 248, 247);
static COLORREF clrCard = RGB(255, 255, 255);
static COLORREF clrText = RGB(26, 26, 25);
static COLORREF clrMuted = RGB(122, 120, 114);
static COLORREF clrAccent = RGB(29, 158, 117);
static COLORREF clrError = RGB(226, 75, 74);
static COLORREF clrWarn = RGB(186, 117, 23);
static COLORREF clrBorder = RGB(224, 221, 213);
static COLORREF clrInputBg = RGB(241, 239, 232);

static HFONT fUI, fBold, fTitle, fMono, fSmall, fEmoji;
static HWND hMain;

/* Register controls */
static HWND hRegLblTitle, hRegLblSub, hRegLblUser, hRegUser, hRegLblPwd, hRegLblConf;
static HWND hRegPwd, hRegConfirm, hRegShowPwd, hRegShowConf, hRegBtn, hRegMsg, hRegStrengthBar, hRegStrengthLbl, hRegCapsLbl;
static int g_regStrength = 0;
/* Login controls */
static HWND hLogLblTitle, hLogLblSub, hLogLblPwd, hLogPwd, hLogShowPwd, hLogBtn, hLogMsg, hLogCapsLbl;
static HWND hLogGuestBtn, hRegGuestBtn;
/* Top bar */
static HWND hLangBtn, hLogoutBtn, hTabGenBtn, hTabUserBtn, hTabEmailBtn, hTabVaultBtn, hTabSetBtn, hMainTitle;
/* Generator */
static HWND hGenLblTitle, hGenLblUser, hGenUser, hGenLblLen, hGenLenVal, hGenSlider;
static HWND hGenLblOpts, hGenChkUpper, hGenChkLower, hGenChkNumber, hGenChkSpec;
static HWND hGenRadLimit, hGenRadFull;
static HWND hGenLblMode, hGenMode, hGenLblPattern, hGenPattern, hGenPatternHint;
static HWND hGenLblOut, hGenOut, hGenShow, hGenCopy, hGenSave, hGenGen;
static HWND hGenChk[6], hGenBar, hGenMsg;
static int g_genRevealed = 0;
static int g_barPct = 0;
static COLORREF g_barColor;
/* Username gen */
static HWND hUserLblTitle, hUserLblTheme, hUserTheme, hUserLblStyle, hUserStyle, hUserChkNum, hUserChkBase;
static HWND hUserLblOut, hUserOut, hUserCopy, hUserSave, hUserGen, hUserMsg;
/* Email gen */
static HWND hEmailLblTitle, hEmailLblTheme, hEmailTheme, hEmailLblStyle, hEmailStyle, hEmailChkNum, hEmailChkBase;
static HWND hEmailLblDomain, hEmailDomain, hEmailLblOut, hEmailOut, hEmailCopy, hEmailSave, hEmailGen, hEmailMsg;
/* Vault */
static HWND hVaultLblTitle, hVaultLblSearch, hVaultSearch, hVaultList, hVaultLblUsr, hVaultUsr;
static HWND hVaultLblPwd, hVaultPwd, hVaultShow, hVaultCopyPwd, hVaultCopyUsr, hVaultEdit, hVaultDel, hVaultMsg, hVaultEmpty;
static int g_vaultRevealed = 0;
static int *g_vaultFilter = NULL;
static int g_vaultFilterCount = 0;
/* Settings */
static HWND hSetLblTitle, hSetLblChange, hSetLblCur, hSetLblNew, hSetLblConf;
static HWND hSetCurPwd, hSetNewPwd, hSetNewConf, hSetChangeBtn, hSetMsg;
static HWND hLogResetBtn;

/* Temp mail state */
typedef struct { char id[32]; char from[160]; char subject[200]; char date[32]; } MailEntry;
static MailEntry g_mails[30];
static int g_mailCount = 0;
static char g_tempEmail[128] = "";
static char g_sidToken[200] = "";   /* Guerrilla Mail session token */
static char g_mailtmToken[600] = ""; /* Mail.tm JWT */
static char g_mailtmPass[64] = "";   /* Mail.tm account password */
static char g_1secLogin[64] = "";    /* 1SecMail username part */
static char g_1secDomain[64] = "";   /* 1SecMail domain part */
static int g_provider = 0;          /* 0=Guerrilla, 1=1SecMail, 2=Mail.tm */
static int g_tempRefreshActive = 0;

static HWND hTabTempBtn;
static HWND hTempLblTitle, hTempLblAddr, hTempAddr, hTempCopyAddr, hTempGet;
static HWND hTempLblProvider, hTempProvider;
static HWND hTempLblDomain, hTempDomain;
static HWND hTempLblInbox, hTempList, hTempRefresh, hTempEmpty;
static HWND hTempLblFrom, hTempFrom, hTempLblSubj, hTempSubj;
static HWND hTempBody, hTempDel, hTempMsg, hTempAuto;

typedef struct {
    char label[128];
    char username[128];
    char password[128];
} VaultEntry;
static VaultEntry *g_entries = NULL;
static int g_entryCount = 0;

/* ===== Crypto: BCrypt random ===== */
static int secureRandom(BYTE *buf, DWORD len) {
    NTSTATUS s = BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s == STATUS_SUCCESS;
}

static int secureRandInt(int max) {
    if (max <= 0) return 0;
    DWORD r;
    if (!secureRandom((BYTE*)&r, sizeof(r))) return rand() % max;
    return (int)(r % (DWORD)max);
}

/* Generate realistic-looking email username */
static void generateRealName(char *out, int outSize) {
    int fc = (int)ARRSZ(FIRST_NAMES), lc = (int)ARRSZ(LAST_NAMES);
    const char *first = FIRST_NAMES[secureRandInt(fc)];
    const char *last  = LAST_NAMES[secureRandInt(lc)];
    int style = secureRandInt(6);
    int useNum = secureRandInt(2);
    int num = secureRandInt(98) + 1;
    char base[64];
    switch (style) {
        case 0: snprintf(base, sizeof(base), "%s.%s",   first, last); break;
        case 1: snprintf(base, sizeof(base), "%s%s",    first, last); break;
        case 2: snprintf(base, sizeof(base), "%s_%s",   first, last); break;
        case 3: snprintf(base, sizeof(base), "%c.%s",   first[0], last); break;
        case 4: snprintf(base, sizeof(base), "%c%s",    first[0], last); break;
        case 5: snprintf(base, sizeof(base), "%s%c",    first, last[0]); break;
    }
    if (useNum) snprintf(out, outSize, "%s%d", base, num);
    else        snprintf(out, outSize, "%s",   base);
}

/* ===== PBKDF2-SHA256 ===== */
static int pbkdf2_sha256(const BYTE *pwd, DWORD pwdLen, const BYTE *salt, DWORD saltLen,
                          DWORD iterations, BYTE *out, DWORD outLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (s != STATUS_SUCCESS) return 0;
    s = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pwd, pwdLen, (PUCHAR)salt, saltLen, iterations, out, outLen, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return s == STATUS_SUCCESS;
}

/* ===== DPAPI for vault ===== */
static int dpapiEncrypt(const BYTE *pt, DWORD ptLen, const BYTE *ent, DWORD entLen, BYTE **out, DWORD *outLen) {
    DATA_BLOB in = {ptLen, (BYTE*)pt};
    DATA_BLOB e = {entLen, (BYTE*)ent};
    DATA_BLOB o = {0, NULL};
    if (!CryptProtectData(&in, L"GeradorSenha", &e, NULL, NULL, 0, &o)) return 0;
    *out = (BYTE*)malloc(o.cbData);
    if (!*out) { LocalFree(o.pbData); return 0; }
    memcpy(*out, o.pbData, o.cbData);
    *outLen = o.cbData;
    LocalFree(o.pbData);
    return 1;
}

static int dpapiDecrypt(const BYTE *ct, DWORD ctLen, const BYTE *ent, DWORD entLen, BYTE **out, DWORD *outLen) {
    DATA_BLOB in = {ctLen, (BYTE*)ct};
    DATA_BLOB e = {entLen, (BYTE*)ent};
    DATA_BLOB o = {0, NULL};
    if (!CryptUnprotectData(&in, NULL, &e, NULL, NULL, 0, &o)) return 0;
    *out = (BYTE*)malloc(o.cbData);
    if (!*out) { LocalFree(o.pbData); return 0; }
    memcpy(*out, o.pbData, o.cbData);
    *outLen = o.cbData;
    LocalFree(o.pbData);
    return 1;
}

/* ===== Paths & config ===== */
static void initPaths(void) {
    wchar_t appdata[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
    wchar_t folder[MAX_PATH];
    swprintf(folder, MAX_PATH, L"%ls\\GeradorSenha", appdata);
    CreateDirectoryW(folder, NULL);
    swprintf(g_configPath, MAX_PATH, L"%ls\\config.dat", folder);
    swprintf(g_vaultPath,  MAX_PATH, L"%ls\\vault.dat", folder);
}

static int hasConfigFile(void) {
    DWORD a = GetFileAttributesW(g_configPath);
    return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
}

/* config.dat v2 format:
 * [1 byte] version=2
 * [16 bytes] salt
 * [32 bytes] PBKDF2(pwd, salt, 100000)
 * [4 bytes] failed attempts count
 * [8 bytes] FILETIME of last failure
 * [1 byte] username length
 * [N bytes] username UTF-8
 */

static int readConfigBytes(BYTE *salt, BYTE *hash, DWORD *failCount, FILETIME *lastFail, char *username) {
    HANDLE h = CreateFileW(g_configPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BYTE ver = 0; DWORD r;
    int ok = 1;
    if (!ReadFile(h, &ver, 1, &r, NULL) || r != 1 || ver != 2) ok = 0;
    if (ok && (!ReadFile(h, salt, SALT_LEN, &r, NULL) || r != SALT_LEN)) ok = 0;
    if (ok && (!ReadFile(h, hash, HASH_LEN, &r, NULL) || r != HASH_LEN)) ok = 0;
    if (ok && (!ReadFile(h, failCount, 4, &r, NULL) || r != 4)) ok = 0;
    if (ok && (!ReadFile(h, lastFail, sizeof(FILETIME), &r, NULL) || r != sizeof(FILETIME))) ok = 0;
    if (ok) {
        BYTE ulen = 0;
        if (ReadFile(h, &ulen, 1, &r, NULL) && r == 1 && ulen > 0 && ulen < 64) {
            if (ReadFile(h, username, ulen, &r, NULL) && r == ulen) username[ulen] = 0;
        }
    }
    CloseHandle(h);
    return ok;
}

static int writeConfigBytes(const BYTE *salt, const BYTE *hash, DWORD failCount, FILETIME lastFail, const char *username) {
    HANDLE h = CreateFileW(g_configPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BYTE ver = 2; DWORD w; int ok = 1;
    BYTE ulen = (BYTE)strlen(username);
    if (!WriteFile(h, &ver, 1, &w, NULL) || w != 1) ok = 0;
    if (ok && (!WriteFile(h, salt, SALT_LEN, &w, NULL) || w != SALT_LEN)) ok = 0;
    if (ok && (!WriteFile(h, hash, HASH_LEN, &w, NULL) || w != HASH_LEN)) ok = 0;
    if (ok && (!WriteFile(h, &failCount, 4, &w, NULL) || w != 4)) ok = 0;
    if (ok && (!WriteFile(h, &lastFail, sizeof(FILETIME), &w, NULL) || w != sizeof(FILETIME))) ok = 0;
    if (ok && (!WriteFile(h, &ulen, 1, &w, NULL) || w != 1)) ok = 0;
    if (ok && ulen > 0 && (!WriteFile(h, username, ulen, &w, NULL) || w != ulen)) ok = 0;
    CloseHandle(h);
    return ok;
}

static int registerNewMaster(const char *user, const char *pwd) {
    BYTE salt[SALT_LEN], hash[HASH_LEN];
    if (!secureRandom(salt, SALT_LEN)) return 0;
    if (!pbkdf2_sha256((BYTE*)pwd, (DWORD)strlen(pwd), salt, SALT_LEN, PBKDF2_ITERATIONS, hash, HASH_LEN)) return 0;
    FILETIME ft = {0, 0};
    return writeConfigBytes(salt, hash, 0, ft, user);
}

/* Returns: 1=success, 0=wrong, -1=locked */
static int verifyMasterPassword(const char *pwd) {
    BYTE salt[SALT_LEN], stored[HASH_LEN], computed[HASH_LEN];
    DWORD failCount = 0;
    FILETIME lastFail = {0, 0};
    if (!readConfigBytes(salt, stored, &failCount, &lastFail, g_username)) return 0;

    /* Check lockout */
    if (failCount >= MAX_FAIL_ATTEMPTS) {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER nu, lu;
        nu.LowPart = now.dwLowDateTime; nu.HighPart = now.dwHighDateTime;
        lu.LowPart = lastFail.dwLowDateTime; lu.HighPart = lastFail.dwHighDateTime;
        long long diffSec = (long long)((nu.QuadPart - lu.QuadPart) / 10000000ULL);
        if (diffSec < LOCKOUT_SECONDS) {
            g_lockoutSeconds = LOCKOUT_SECONDS - (int)diffSec;
            return -1;
        } else {
            failCount = 0;
        }
    }

    if (!pbkdf2_sha256((BYTE*)pwd, (DWORD)strlen(pwd), salt, SALT_LEN, PBKDF2_ITERATIONS, computed, HASH_LEN)) return 0;
    int match = (memcmp(stored, computed, HASH_LEN) == 0);

    if (match) {
        FILETIME zero = {0, 0};
        writeConfigBytes(salt, stored, 0, zero, g_username);
        return 1;
    } else {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        writeConfigBytes(salt, stored, failCount + 1, now, g_username);
        if (failCount + 1 >= MAX_FAIL_ATTEMPTS) {
            g_lockoutSeconds = LOCKOUT_SECONDS;
            return -1;
        }
        return 0;
    }
}

static int changeMasterPassword(const char *oldPwd, const char *newPwd);

static void loadUsernameOnly(void) {
    BYTE salt[SALT_LEN], hash[HASH_LEN];
    DWORD fc; FILETIME lf;
    readConfigBytes(salt, hash, &fc, &lf, g_username);
}

/* ===== Vault I/O =====
 * vault.dat v2: [1 byte ver=2][4 bytes count][per-entry: 4 bytes encLen][encBlob]
 * Decrypted blob: [2 lblLen][label][2 userLen][user][2 pwdLen][pwd]
 */
static void freeVault(void) {
    if (g_entries) { SecureZeroMemory(g_entries, g_entryCount * sizeof(VaultEntry)); free(g_entries); g_entries = NULL; }
    g_entryCount = 0;
    if (g_vaultFilter) { free(g_vaultFilter); g_vaultFilter = NULL; }
    g_vaultFilterCount = 0;
}

static int loadVaultFile(void) {
    freeVault();
    HANDLE h = CreateFileW(g_vaultPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 1;
    BYTE ver = 0; DWORD r;
    if (!ReadFile(h, &ver, 1, &r, NULL) || r != 1) { CloseHandle(h); return 0; }
    if (ver != 2) { CloseHandle(h); return 0; }
    DWORD count = 0;
    if (!ReadFile(h, &count, 4, &r, NULL) || r != 4) { CloseHandle(h); return 0; }
    if (count > 1000) { CloseHandle(h); return 0; }
    g_entries = (VaultEntry*)calloc(count > 0 ? count : 1, sizeof(VaultEntry));
    if (!g_entries) { CloseHandle(h); return 0; }
    DWORD ml = (DWORD)strlen(g_master);
    for (DWORD i = 0; i < count; i++) {
        DWORD bl = 0;
        if (!ReadFile(h, &bl, 4, &r, NULL) || r != 4 || bl > 8192) break;
        BYTE *blob = (BYTE*)malloc(bl);
        if (!blob) break;
        if (!ReadFile(h, blob, bl, &r, NULL) || r != bl) { free(blob); break; }
        BYTE *plain = NULL; DWORD pl = 0;
        if (dpapiDecrypt(blob, bl, (BYTE*)g_master, ml, &plain, &pl)) {
            DWORD off = 0;
            if (off + 2 <= pl) {
                WORD ll = *(WORD*)(plain + off); off += 2;
                if (ll < 127 && off + ll + 2 <= pl) {
                    memcpy(g_entries[g_entryCount].label, plain + off, ll);
                    g_entries[g_entryCount].label[ll] = 0; off += ll;
                    WORD ul = *(WORD*)(plain + off); off += 2;
                    if (ul < 127 && off + ul + 2 <= pl) {
                        memcpy(g_entries[g_entryCount].username, plain + off, ul);
                        g_entries[g_entryCount].username[ul] = 0; off += ul;
                        WORD pwl = *(WORD*)(plain + off); off += 2;
                        if (pwl < 127 && off + pwl <= pl) {
                            memcpy(g_entries[g_entryCount].password, plain + off, pwl);
                            g_entries[g_entryCount].password[pwl] = 0;
                            g_entryCount++;
                        }
                    }
                }
            }
            SecureZeroMemory(plain, pl);
            free(plain);
        }
        free(blob);
    }
    CloseHandle(h);
    return 1;
}

static int saveVaultFile(void) {
    if (g_isGuest) return 1;  /* guest mode: don't persist */
    HANDLE h = CreateFileW(g_vaultPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BYTE ver = 2; DWORD w;
    WriteFile(h, &ver, 1, &w, NULL);
    DWORD count = (DWORD)g_entryCount;
    WriteFile(h, &count, 4, &w, NULL);
    DWORD ml = (DWORD)strlen(g_master);
    for (int i = 0; i < g_entryCount; i++) {
        WORD ll  = (WORD)strlen(g_entries[i].label);
        WORD ul  = (WORD)strlen(g_entries[i].username);
        WORD pwl = (WORD)strlen(g_entries[i].password);
        DWORD tot = 2 + ll + 2 + ul + 2 + pwl;
        BYTE *plain = (BYTE*)malloc(tot);
        if (!plain) continue;
        DWORD off = 0;
        memcpy(plain + off, &ll, 2); off += 2;
        memcpy(plain + off, g_entries[i].label, ll); off += ll;
        memcpy(plain + off, &ul, 2); off += 2;
        memcpy(plain + off, g_entries[i].username, ul); off += ul;
        memcpy(plain + off, &pwl, 2); off += 2;
        memcpy(plain + off, g_entries[i].password, pwl);
        BYTE *enc = NULL; DWORD el = 0;
        if (dpapiEncrypt(plain, tot, (BYTE*)g_master, ml, &enc, &el)) {
            WriteFile(h, &el, 4, &w, NULL);
            WriteFile(h, enc, el, &w, NULL);
            free(enc);
        }
        SecureZeroMemory(plain, tot);
        free(plain);
    }
    CloseHandle(h);
    return 1;
}

static int addVaultEntry(const char *lbl, const char *user, const char *pwd) {
    VaultEntry *n = (VaultEntry*)realloc(g_entries, (g_entryCount + 1) * sizeof(VaultEntry));
    if (!n) return 0;
    g_entries = n;
    memset(&g_entries[g_entryCount], 0, sizeof(VaultEntry));
    strncpy(g_entries[g_entryCount].label, lbl, sizeof(g_entries[g_entryCount].label) - 1);
    if (user) strncpy(g_entries[g_entryCount].username, user, sizeof(g_entries[g_entryCount].username) - 1);
    strncpy(g_entries[g_entryCount].password, pwd, sizeof(g_entries[g_entryCount].password) - 1);
    g_entryCount++;
    return saveVaultFile();
}

static int updateVaultEntry(int idx, const char *lbl, const char *user, const char *pwd) {
    if (idx < 0 || idx >= g_entryCount) return 0;
    memset(&g_entries[idx], 0, sizeof(VaultEntry));
    strncpy(g_entries[idx].label, lbl, sizeof(g_entries[idx].label) - 1);
    if (user) strncpy(g_entries[idx].username, user, sizeof(g_entries[idx].username) - 1);
    strncpy(g_entries[idx].password, pwd, sizeof(g_entries[idx].password) - 1);
    return saveVaultFile();
}

static void removeVaultEntry(int i) {
    if (i < 0 || i >= g_entryCount) return;
    SecureZeroMemory(&g_entries[i], sizeof(VaultEntry));
    for (int j = i; j < g_entryCount - 1; j++) g_entries[j] = g_entries[j + 1];
    g_entryCount--;
    saveVaultFile();
}

/* Change master password: re-encrypt vault with new password */
static int changeMasterPassword(const char *oldPwd, const char *newPwd) {
    if (verifyMasterPassword(oldPwd) != 1) return -1;
    BYTE salt[SALT_LEN], hash[HASH_LEN];
    if (!secureRandom(salt, SALT_LEN)) return 0;
    if (!pbkdf2_sha256((BYTE*)newPwd, (DWORD)strlen(newPwd), salt, SALT_LEN, PBKDF2_ITERATIONS, hash, HASH_LEN)) return 0;
    FILETIME zero = {0, 0};
    /* re-write vault first with new key */
    SecureZeroMemory(g_master, sizeof(g_master));
    strncpy(g_master, newPwd, sizeof(g_master) - 1);
    if (!saveVaultFile()) return 0;
    if (!writeConfigBytes(salt, hash, 0, zero, g_username)) return 0;
    return 1;
}

/* ===== Helpers ===== */
static void utf8ToWide(const char *s, wchar_t *d, int n) { MultiByteToWideChar(CP_UTF8, 0, s, -1, d, n); }
static void wideToUtf8(const wchar_t *s, char *d, int n) { WideCharToMultiByte(CP_UTF8, 0, s, -1, d, n, NULL, NULL); }

static void shuffleStr(char *a, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = secureRandInt(i + 1);
        char t = a[i]; a[i] = a[j]; a[j] = t;
    }
}

static int strContainsCI(const char *hay, const char *nee) {
    if (!nee || strlen(nee) < 3) return 0;
    char lh[128], ln[128];
    int hl = (int)strlen(hay); if (hl >= 128) hl = 127;
    int nl = (int)strlen(nee); if (nl >= 128) nl = 127;
    for (int i = 0; i < hl; i++) lh[i] = (char)tolower((unsigned char)hay[i]);
    lh[hl] = 0;
    for (int i = 0; i < nl; i++) ln[i] = (char)tolower((unsigned char)nee[i]);
    ln[nl] = 0;
    return strstr(lh, ln) != NULL;
}

/* ===== Passphrase generator ===== */
static const char *PASSPHRASE_WORDS[] = {
    "apple","bridge","castle","dragon","eagle","forest","garden","harbor",
    "island","jungle","keeper","lemon","marble","nectar","ocean","palace",
    "quartz","river","silver","tiger","umbra","valley","winter","yellow","zenith",
    "anchor","breeze","copper","diamond","ember","falcon","glacier","horizon",
    "ivory","jasper","knight","lantern","magnet","noble","oyster","phantom",
    "queen","rapids","shadow","throne","ultra","violet","wisdom","xylene","yoga",
    "amber","blaze","crane","drift","elder","flame","grove","haven","iris",
    "jewel","karma","lotus","maple","north","olive","prism","quest","raven",
    "storm","thorn","unity","viper","whale","xerox","yarn","zeal",
    "atlas","bloom","cliff","dagger","ether","frost","grand","hydra","indie",
    "joker","kite","lunar","mango","nexus","oasis","pixel","quota","radar",
    "solar","turbo","urban","vapor","warden","xenon","yonder","zero",
    "acorn","brush","cedar","depth","epoch","flint","grain","hedge","inlet",
    "jolt","knack","lace","marsh","neon","orbit","plume","quill","ridge",
    "spine","talon","utmost","vault","wraith","xylem","yolk","zinc",
    /* Portuguese words mixed in */
    "pedra","vento","chuva","fogo","terra","noite","claro","monte",
    "selva","campo","bruma","raio","troar","bravo","forte","largo",
    "delta","alfa","omega","sigma","kappa","theta","gamma","zeta"
};
#define PASSPHRASE_WORD_COUNT (sizeof(PASSPHRASE_WORDS)/sizeof(PASSPHRASE_WORDS[0]))

static void generatePassphrase(char *out, int outSize, int wordCount, int uS) {
    const char *sep[] = {"-", "_", ".", " ", ""};
    int sepIdx = secureRandInt(4); /* last "" only for compact */
    char *p = out; int rem = outSize - 1;
    for (int i = 0; i < wordCount && rem > 0; i++) {
        const char *w = PASSPHRASE_WORDS[secureRandInt((int)PASSPHRASE_WORD_COUNT)];
        /* capitalize first letter */
        char word[32];
        strncpy(word, w, sizeof(word)-1); word[sizeof(word)-1] = 0;
        if (word[0] >= 'a' && word[0] <= 'z') word[0] = (char)(word[0] - 32);
        int wl = (int)strlen(word);
        if (wl > rem) wl = rem;
        memcpy(p, word, wl); p += wl; rem -= wl;
        /* add number after word sometimes */
        if (uS && secureRandInt(3) == 0 && rem > 2) {
            int n = secureRandInt(99);
            char nb[8]; snprintf(nb, sizeof(nb), "%d", n);
            int nl = (int)strlen(nb);
            if (nl <= rem) { memcpy(p, nb, nl); p += nl; rem -= nl; }
        }
        /* separator (not after last word) */
        if (i < wordCount - 1 && rem > 0) {
            const char *s = sep[sepIdx];
            int sl = (int)strlen(s);
            if (sl <= rem) { memcpy(p, s, sl); p += sl; rem -= sl; }
        }
    }
    *p = 0;
}

/* ===== Pronounceable password ===== */
static const char *CONSONANTS[] = {
    "b","br","bl","c","ch","cr","cl","d","dr","f","fl","fr",
    "g","gl","gr","h","j","k","l","m","n","p","pl","pr",
    "qu","r","s","sh","sl","sn","sp","st","str","sw","t","th","tr","tw",
    "v","w","wh","x","y","z"
};
static const char *VOWELS[] = {
    "a","e","i","o","u","ai","au","ea","ee","ei","oo","ou","ia","io"
};
#define CONS_COUNT (sizeof(CONSONANTS)/sizeof(CONSONANTS[0]))
#define VOW_COUNT  (sizeof(VOWELS)/sizeof(VOWELS[0]))

static void generatePronounceable(char *out, int outSize, int length, int uS) {
    char *p = out; int rem = outSize - 1; int gen = 0;
    while (gen < length && rem > 0) {
        /* CVC syllable */
        const char *c1 = CONSONANTS[secureRandInt((int)CONS_COUNT)];
        const char *v  = VOWELS[secureRandInt((int)VOW_COUNT)];
        const char *c2 = CONSONANTS[secureRandInt((int)CONS_COUNT)];
        /* randomly uppercase first letter of syllable for variety */
        char syl[16]; int sl;
        snprintf(syl, sizeof(syl), "%s%s%s", c1, v, c2);
        if (secureRandInt(4) == 0 && syl[0] >= 'a' && syl[0] <= 'z')
            syl[0] = (char)(syl[0] - 32);
        sl = (int)strlen(syl);
        if (sl > rem) sl = rem;
        memcpy(p, syl, sl); p += sl; rem -= sl; gen += sl;
        /* insert digit or special every ~8 chars */
        if (uS && gen % 8 < 3 && rem > 1) {
            char extras[] = "0123456789!@#$%";
            *p = extras[secureRandInt(15)]; p++; rem--; gen++;
        }
    }
    *p = 0;
}

/* ===== Pattern-based generator =====
   A = random uppercase
   a = random lowercase
   9 = random digit
   ! = random special char
   * = any random char
   anything else = literal
*/
static void generateFromPattern(char *out, int outSize, const char *pattern, int sL) {
    const char *spec = sL ? CS_LIMIT : CS_FULL;
    const char *all  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    char *p = out; int rem = outSize - 1;
    for (int i = 0; pattern[i] && rem > 0; i++) {
        char c;
        switch (pattern[i]) {
            case 'A': c = CS_UPPER[secureRandInt(26)]; break;
            case 'a': c = CS_LOWER[secureRandInt(26)]; break;
            case '9': c = CS_DIGITS[secureRandInt(10)]; break;
            case '!': c = spec[secureRandInt((int)strlen(spec))]; break;
            case '*': c = all[secureRandInt((int)strlen(all))]; break;
            default:  c = pattern[i]; break;
        }
        *p++ = c; rem--;
    }
    *p = 0;
}

/* ===== Password generator (classic) ===== */
static int generatePassword(char *out, int outSize, int length, int uU, int uL,
                            int uN, int uS, int sL, const char *user) {
    if (!uU && !uL && !uN && !uS) return 0;
    char pool[512] = "";
    if (uL) strcat(pool, CS_LOWER);
    if (uU) strcat(pool, CS_UPPER);
    if (uN) strcat(pool, CS_DIGITS);
    const char *spec = sL ? CS_LIMIT : CS_FULL;
    if (uS) strcat(pool, spec);
    int pl = (int)strlen(pool);
    if (pl == 0) return 0;
    int mr = (uU?1:0) + (uL?1:0) + (uN?1:0) + (uS?1:0);
    if (length < mr) return -1;
    if (length >= outSize) return 0;
    char *buf = (char*)malloc(length + 1);
    if (!buf) return 0;
    for (int a = 0; a < 500; a++) {
        int idx = 0;
        if (uL) buf[idx++] = CS_LOWER[secureRandInt(26)];
        if (uU) buf[idx++] = CS_UPPER[secureRandInt(26)];
        if (uN) buf[idx++] = CS_DIGITS[secureRandInt(10)];
        if (uS) buf[idx++] = spec[secureRandInt((int)strlen(spec))];
        for (int i = idx; i < length; i++) buf[i] = pool[secureRandInt(pl)];
        buf[length] = 0;
        shuffleStr(buf, length);
        if (!strContainsCI(buf, user)) { strcpy(out, buf); free(buf); return 1; }
    }
    free(buf);
    return 0;
}

/* ===== Username/Email generator (PT or EN pools) ===== */
static const char **getThemePool(int theme, int *count) {
    int useEN = (g_lang == 1);
    if (theme == 5) theme = secureRandInt(5);
    if (useEN) {
        switch (theme) {
            case 0: *count = ARRSZ(POOL_ANIMAL_EN);  return POOL_ANIMAL_EN;
            case 1: *count = ARRSZ(POOL_NATURE_EN);  return POOL_NATURE_EN;
            case 2: *count = ARRSZ(POOL_TECH_EN);    return POOL_TECH_EN;
            case 3: *count = ARRSZ(POOL_FANTASY_EN); return POOL_FANTASY_EN;
            case 4: *count = ARRSZ(POOL_SPORTS_EN);  return POOL_SPORTS_EN;
            default: *count = ARRSZ(POOL_ANIMAL_EN); return POOL_ANIMAL_EN;
        }
    } else {
        switch (theme) {
            case 0: *count = ARRSZ(POOL_ANIMAL_PT);  return POOL_ANIMAL_PT;
            case 1: *count = ARRSZ(POOL_NATURE_PT);  return POOL_NATURE_PT;
            case 2: *count = ARRSZ(POOL_TECH_PT);    return POOL_TECH_PT;
            case 3: *count = ARRSZ(POOL_FANTASY_PT); return POOL_FANTASY_PT;
            case 4: *count = ARRSZ(POOL_SPORTS_PT);  return POOL_SPORTS_PT;
            default: *count = ARRSZ(POOL_ANIMAL_PT); return POOL_ANIMAL_PT;
        }
    }
}

static const char **getAdjPool(int *count) {
    if (g_lang == 1) { *count = ARRSZ(ADJ_EN); return ADJ_EN; }
    *count = ARRSZ(ADJ_PT); return ADJ_PT;
}

static void toLowerStr(char *s) {
    for (int i = 0; s[i]; i++) s[i] = (char)tolower((unsigned char)s[i]);
}

static void generateUsername(char *out, int outSize, int theme, int style, int useNum, int useBase, const char *base) {
    int nc, ac;
    const char **nouns = getThemePool(theme, &nc);
    const char **adjs = getAdjPool(&ac);
    const char *adj = adjs[secureRandInt(ac)];
    const char *nn = nouns[secureRandInt(nc)];
    int num = useNum ? secureRandInt(1000) : -1;

    char baseClean[64] = "";
    if (useBase && base && base[0]) {
        char tmp[64]; int t = 0;
        for (int i = 0; base[i] && t < 63; i++) {
            unsigned char c = (unsigned char)base[i];
            if (isalnum(c)) tmp[t++] = (char)c;
        }
        tmp[t] = 0;
        strcpy(baseClean, tmp);
    }

    char buf[200] = "";
    if (style == 0) {
        if (baseClean[0]) {
            char b2[64]; strcpy(b2, baseClean);
            if (b2[0]) b2[0] = (char)toupper((unsigned char)b2[0]);
            snprintf(buf, sizeof(buf), "%s%s%s", b2, adj, nn);
        } else snprintf(buf, sizeof(buf), "%s%s", adj, nn);
        if (num >= 0) { char t[16]; snprintf(t, sizeof(t), "%d", num); strncat(buf, t, sizeof(buf) - strlen(buf) - 1); }
    } else if (style == 1) {
        if (baseClean[0]) snprintf(buf, sizeof(buf), "%s%s%s", baseClean, adj, nn);
        else snprintf(buf, sizeof(buf), "%s%s", adj, nn);
        toLowerStr(buf);
        if (num >= 0) { char t[16]; snprintf(t, sizeof(t), "%d", num); strncat(buf, t, sizeof(buf) - strlen(buf) - 1); }
    } else if (style == 2) {
        if (baseClean[0]) snprintf(buf, sizeof(buf), "%s_%s_%s", baseClean, adj, nn);
        else snprintf(buf, sizeof(buf), "%s_%s", adj, nn);
        toLowerStr(buf);
        if (num >= 0) { char t[16]; snprintf(t, sizeof(t), "_%d", num); strncat(buf, t, sizeof(buf) - strlen(buf) - 1); }
    } else {
        if (baseClean[0]) snprintf(buf, sizeof(buf), "%s.%s.%s", baseClean, adj, nn);
        else snprintf(buf, sizeof(buf), "%s.%s", adj, nn);
        toLowerStr(buf);
        if (num >= 0) { char t[16]; snprintf(t, sizeof(t), ".%d", num); strncat(buf, t, sizeof(buf) - strlen(buf) - 1); }
    }
    strncpy(out, buf, outSize - 1);
    out[outSize - 1] = 0;
}

/* ===== HTTP GET with retry (WinHTTP) ===== */
static int httpGetOnce(const wchar_t *host, const wchar_t *path, char *outBuf, int outSize) {
    HINTERNET hSes = WinHttpOpen(L"GeradorSenha/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return 0;
    HINTERNET hCon = WinHttpConnect(hSes, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return 0; }
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return 0; }
    WinHttpSetTimeouts(hReq, 8000, 8000, 15000, 15000);
    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok || !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
        return 0;
    }
    int total = 0; DWORD rd = 0;
    while (total < outSize - 1) {
        DWORD av = 0;
        if (!WinHttpQueryDataAvailable(hReq, &av) || av == 0) break;
        if (av > (DWORD)(outSize - 1 - total)) av = outSize - 1 - total;
        if (!WinHttpReadData(hReq, outBuf + total, av, &rd)) break;
        total += rd;
    }
    outBuf[total] = 0;
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return total > 0;
}

static int httpGet(const wchar_t *host, const wchar_t *path, char *outBuf, int outSize) {
    for (int attempt = 0; attempt < 3; attempt++) {
        if (httpGetOnce(host, path, outBuf, outSize)) return 1;
        if (attempt < 2) Sleep(1000);
    }
    return 0;
}

/* Extract value of a JSON key (handles quoted strings and unquoted numbers) */
static int jsonStr(const char *json, const char *key, char *out, int outSize) {
    out[0] = 0;
    char pat[160]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    int i = 0;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && i < outSize - 1) {
            if (*p == '\\' && *(p+1)) {
                p++;
                if (*p == 'n') { out[i++] = '\n'; p++; continue; }
                if (*p == 'r') { p++; continue; }
                if (*p == 't') { out[i++] = ' '; p++; continue; }
                if (*p == 'u') {
                    /* skip 4-hex unicode escape, replace with '?' */
                    p++;
                    for (int k = 0; k < 4 && *p; k++) p++;
                    if (i < outSize - 1) out[i++] = '?';
                    continue;
                }
                out[i++] = *p++;
                continue;
            }
            out[i++] = *p++;
        }
    } else if ((*p >= '0' && *p <= '9') || *p == '-') {
        /* unquoted number */
        while (((*p >= '0' && *p <= '9') || *p == '-' || *p == '.') && i < outSize - 1) {
            out[i++] = *p++;
        }
    } else if (*p == 'n' && p[1] == 'u' && p[2] == 'l' && p[3] == 'l') {
        /* null - leave empty */
    }
    out[i] = 0;
    return i > 0;
}

/* ===== HTTP POST with retry (WinHTTP) ===== */
static int httpPostOnce(const wchar_t *host, const wchar_t *path,
                    const char *jsonBody, const wchar_t *authHeader,
                    char *outBuf, int outSize) {
    HINTERNET hSes = WinHttpOpen(L"GeradorSenha/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return 0;
    HINTERNET hCon = WinHttpConnect(hSes, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return 0; }
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"POST", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return 0; }
    WinHttpSetTimeouts(hReq, 5000, 5000, 10000, 10000);
    wchar_t hdrs[512] = L"Content-Type: application/json\r\n";
    if (authHeader) {
        wcscat(hdrs, authHeader);
        wcscat(hdrs, L"\r\n");
    }
    DWORD bodyLen = (DWORD)strlen(jsonBody);
    BOOL ok = WinHttpSendRequest(hReq, hdrs, (DWORD)-1,
        (LPVOID)jsonBody, bodyLen, bodyLen, 0);
    if (!ok || !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
        return 0;
    }
    int total = 0; DWORD rd = 0;
    while (total < outSize - 1) {
        DWORD av = 0;
        if (!WinHttpQueryDataAvailable(hReq, &av) || av == 0) break;
        if (av > (DWORD)(outSize - 1 - total)) av = outSize - 1 - total;
        if (!WinHttpReadData(hReq, outBuf + total, av, &rd)) break;
        total += rd;
    }
    outBuf[total] = 0;
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return total > 0;
}

static int httpPost(const wchar_t *host, const wchar_t *path,
                    const char *jsonBody, const wchar_t *authHeader,
                    char *outBuf, int outSize) {
    for (int attempt = 0; attempt < 3; attempt++) {
        if (httpPostOnce(host, path, jsonBody, authHeader, outBuf, outSize)) return 1;
        if (attempt < 2) Sleep(1000);
    }
    return 0;
}

/* ===== Guerrilla Mail ===== */
static int apiGetNewAddress(void) {
    char buf[4096];
    if (!httpGet(L"api.guerrillamail.com", L"/ajax.php?f=get_email_address", buf, sizeof(buf)))
        return 0;
    jsonStr(buf, "email_addr", g_tempEmail, sizeof(g_tempEmail));
    jsonStr(buf, "sid_token",  g_sidToken,  sizeof(g_sidToken));
    g_mailCount = 0;
    return g_tempEmail[0] != 0;
}

static int apiCheckInbox(void) {
    if (!g_sidToken[0]) return 0;
    wchar_t tokenW[200]; utf8ToWide(g_sidToken, tokenW, 200);
    wchar_t path[512];
    swprintf(path, 512, L"/ajax.php?f=get_email_list&offset=0&sid_token=%ls", tokenW);
    char buf[65536];
    if (!httpGet(L"api.guerrillamail.com", path, buf, sizeof(buf))) return 0;
    char newTok[200];
    if (jsonStr(buf, "sid_token", newTok, sizeof(newTok)) && newTok[0])
        strncpy(g_sidToken, newTok, sizeof(g_sidToken) - 1);
    g_mailCount = 0;
    const char *p = buf;
    while (g_mailCount < 30) {
        const char *hit = strstr(p, "\"mail_id\"");
        if (!hit) break;
        char id[32]="", from[160]="", subj[200]="", date[32]="";
        jsonStr(hit, "mail_id",      id,   sizeof(id));
        jsonStr(hit, "mail_from",    from, sizeof(from));
        jsonStr(hit, "mail_subject", subj, sizeof(subj));
        jsonStr(hit, "mail_date",    date, sizeof(date));
        if (id[0]) {
            strncpy(g_mails[g_mailCount].id,      id,   31);
            strncpy(g_mails[g_mailCount].from,    from, 159);
            strncpy(g_mails[g_mailCount].subject, subj, 199);
            strncpy(g_mails[g_mailCount].date,    date, 31);
            g_mailCount++;
        }
        p = hit + 9;
    }
    return 1;
}

static int apiSetEmailUser(const char *user, const char *domain) {
    if (!g_sidToken[0]) return 0;
    wchar_t tokenW[200], userW[64], domainW[64];
    utf8ToWide(g_sidToken, tokenW, 200);
    utf8ToWide(user, userW, 64);
    utf8ToWide(domain, domainW, 64);
    wchar_t path[512];
    swprintf(path, 512, L"/ajax.php?f=set_email_user&email_user=%ls&domain=%ls&sid_token=%ls",
             userW, domainW, tokenW);
    char buf[4096];
    if (!httpGet(L"api.guerrillamail.com", path, buf, sizeof(buf))) return 0;
    jsonStr(buf, "email_addr", g_tempEmail, sizeof(g_tempEmail));
    char newTok[200];
    if (jsonStr(buf, "sid_token", newTok, sizeof(newTok)) && newTok[0])
        strncpy(g_sidToken, newTok, sizeof(g_sidToken) - 1);
    return g_tempEmail[0] != 0;
}

static int apiFetchBody(const char *mailId, char *bodyOut, int bodySize) {
    wchar_t tokenW[200], idW[32];
    utf8ToWide(g_sidToken, tokenW, 200);
    utf8ToWide(mailId, idW, 32);
    wchar_t path[512];
    swprintf(path, 512, L"/ajax.php?f=fetch_email&email_id=%ls&sid_token=%ls", idW, tokenW);
    char buf[65536];
    if (!httpGet(L"api.guerrillamail.com", path, buf, sizeof(buf))) return 0;
    char raw[65536] = "";
    jsonStr(buf, "mail_body", raw, sizeof(raw));
    int j = 0; int inTag = 0;
    for (int i = 0; raw[i] && j < bodySize - 1; i++) {
        if (raw[i] == '<') { inTag = 1; continue; }
        if (raw[i] == '>') { inTag = 0;
            if (j > 0 && bodyOut[j-1] != '\n') bodyOut[j++] = '\n';
            continue; }
        if (!inTag) bodyOut[j++] = raw[i];
    }
    bodyOut[j] = 0;
    return j > 0;
}

/* ===== 1SecMail ===== */
static int sec_genAddress(const char *domain) {
    char buf[512];
    if (!httpGet(L"www.1secmail.com", L"/api/v1/?action=genRandomMailbox&count=1", buf, sizeof(buf)))
        return 0;
    /* response: ["user@domain.com"] */
    char *at = strchr(buf, '"');
    if (!at) return 0;
    at++;
    char full[128]; int i = 0;
    while (*at && *at != '"' && i < 127) full[i++] = *at++;
    full[i] = 0;
    char *atSign = strchr(full, '@');
    if (!atSign) return 0;
    *atSign = 0;
    strncpy(g_1secLogin, full, sizeof(g_1secLogin) - 1);
    /* use chosen domain if specified, else use what API gave */
    if (domain && domain[0])
        strncpy(g_1secDomain, domain, sizeof(g_1secDomain) - 1);
    else
        strncpy(g_1secDomain, atSign + 1, sizeof(g_1secDomain) - 1);
    snprintf(g_tempEmail, sizeof(g_tempEmail), "%s@%s", g_1secLogin, g_1secDomain);
    return 1;
}

static int sec_checkInbox(void) {
    if (!g_1secLogin[0] || !g_1secDomain[0]) return 0;
    wchar_t loginW[64], domW[64];
    utf8ToWide(g_1secLogin, loginW, 64);
    utf8ToWide(g_1secDomain, domW, 64);
    wchar_t path[256];
    swprintf(path, 256, L"/api/v1/?action=getMessages&login=%ls&domain=%ls", loginW, domW);
    char buf[65536];
    if (!httpGet(L"www.1secmail.com", path, buf, sizeof(buf))) return 0;
    g_mailCount = 0;
    const char *p = buf;
    while (g_mailCount < 30) {
        const char *hit = strstr(p, "\"id\"");
        if (!hit) break;
        char id[32]="", from[160]="", subj[200]="", date[32]="";
        jsonStr(hit, "id",      id,   sizeof(id));
        jsonStr(hit, "from",    from, sizeof(from));
        jsonStr(hit, "subject", subj, sizeof(subj));
        jsonStr(hit, "date",    date, sizeof(date));
        if (id[0]) {
            strncpy(g_mails[g_mailCount].id,      id,   31);
            strncpy(g_mails[g_mailCount].from,    from, 159);
            strncpy(g_mails[g_mailCount].subject, subj, 199);
            strncpy(g_mails[g_mailCount].date,    date, 31);
            g_mailCount++;
        }
        p = hit + 4;
    }
    return 1;
}

static int sec_fetchBody(const char *mailId, char *bodyOut, int bodySize) {
    wchar_t loginW[64], domW[64], idW[32];
    utf8ToWide(g_1secLogin, loginW, 64);
    utf8ToWide(g_1secDomain, domW, 64);
    utf8ToWide(mailId, idW, 32);
    wchar_t path[256];
    swprintf(path, 256, L"/api/v1/?action=readMessage&login=%ls&domain=%ls&id=%ls", loginW, domW, idW);
    char buf[65536];
    if (!httpGet(L"www.1secmail.com", path, buf, sizeof(buf))) return 0;
    /* prefer textBody, fall back to body */
    char raw[65536] = "";
    if (!jsonStr(buf, "textBody", raw, sizeof(raw)) || !raw[0])
        jsonStr(buf, "body", raw, sizeof(raw));
    /* strip HTML tags */
    int j = 0, inTag = 0;
    for (int i = 0; raw[i] && j < bodySize - 1; i++) {
        if (raw[i] == '<') { inTag = 1; continue; }
        if (raw[i] == '>') { inTag = 0;
            if (j > 0 && bodyOut[j-1] != '\n') bodyOut[j++] = '\n';
            continue; }
        if (!inTag) bodyOut[j++] = raw[i];
    }
    bodyOut[j] = 0;
    return j > 0;
}

/* ===== Mail.tm ===== */
static int mailtm_fetchDomains(void) {
    char buf[32768];
    if (!httpGet(L"api.mail.tm", L"/domains?page=1", buf, sizeof(buf))) return 0;
    g_mailtmDomainCount = 0;
    const char *p = buf;
    while (g_mailtmDomainCount < MAILTM_MAX_DOMAINS) {
        const char *hit = strstr(p, "\"domain\"");
        if (!hit) break;
        char dom[64] = "";
        jsonStr(hit, "domain", dom, sizeof(dom));
        if (dom[0]) {
            strncpy(g_mailtmDomains[g_mailtmDomainCount++], dom, 63);
        }
        p = hit + 8;
    }
    return g_mailtmDomainCount > 0;
}

static int mailtm_createAccount(const char *addr, const char *pass) {
    char body[256];
    snprintf(body, sizeof(body), "{\"address\":\"%s\",\"password\":\"%s\"}", addr, pass);
    char buf[4096];
    httpPost(L"api.mail.tm", L"/accounts", body, NULL, buf, sizeof(buf));
    return 1; /* account may already exist on retry, continue to token */
}

static int mailtm_getToken(const char *addr, const char *pass) {
    char body[256];
    snprintf(body, sizeof(body), "{\"address\":\"%s\",\"password\":\"%s\"}", addr, pass);
    char buf[4096];
    if (!httpPost(L"api.mail.tm", L"/token", body, NULL, buf, sizeof(buf))) return 0;
    return jsonStr(buf, "token", g_mailtmToken, sizeof(g_mailtmToken));
}

static int mailtm_genAddress(const char *domain) {
    if (g_mailtmDomainCount == 0) mailtm_fetchDomains();
    const char *dom = (domain && domain[0]) ? domain :
        (g_mailtmDomainCount > 0 ? g_mailtmDomains[0] : "mail.tm");
    char user[48]; generateRealName(user, sizeof(user));
    snprintf(g_tempEmail, sizeof(g_tempEmail), "%s@%s", user, dom);
    /* generate a password for this temp account */
    snprintf(g_mailtmPass, sizeof(g_mailtmPass), "Tmp!%d%s", secureRandInt(99999), user);
    mailtm_createAccount(g_tempEmail, g_mailtmPass);
    return mailtm_getToken(g_tempEmail, g_mailtmPass);
}

static int mailtm_checkInbox(void) {
    if (!g_mailtmToken[0]) return 0;
    wchar_t auth[700];
    swprintf(auth, 700, L"Authorization: Bearer %hs", g_mailtmToken);
    /* Use GET with auth header — we re-use httpGet but need custom header.
       Simplest: build a variant that passes auth. Use httpPost path with GET verb trick:
       Actually implement a small auth-GET helper inline. */
    HINTERNET hSes = WinHttpOpen(L"GeradorSenha/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return 0;
    HINTERNET hCon = WinHttpConnect(hSes, L"api.mail.tm", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"GET", L"/messages?page=1", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    WinHttpSetTimeouts(hReq, 5000, 5000, 10000, 10000);
    wchar_t hdrs[700];
    swprintf(hdrs, 700, L"Authorization: Bearer %hs\r\n", g_mailtmToken);
    BOOL ok = WinHttpSendRequest(hReq, hdrs, (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    char buf[65536] = ""; int total = 0;
    if (ok && WinHttpReceiveResponse(hReq, NULL)) {
        DWORD rd = 0;
        while (total < (int)sizeof(buf) - 1) {
            DWORD av = 0;
            if (!WinHttpQueryDataAvailable(hReq, &av) || av == 0) break;
            if (av > (DWORD)(sizeof(buf) - 1 - total)) av = sizeof(buf) - 1 - total;
            if (!WinHttpReadData(hReq, buf + total, av, &rd)) break;
            total += rd;
        }
        buf[total] = 0;
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    if (!total) return 0;
    g_mailCount = 0;
    const char *p = buf;
    while (g_mailCount < 30) {
        const char *hit = strstr(p, "\"@id\"");
        if (!hit) break;
        /* id is like "/messages/abc123" */
        char fullId[64] = "";
        jsonStr(hit, "@id", fullId, sizeof(fullId));
        /* extract just the hash part after last / */
        char *slash = strrchr(fullId, '/');
        char id[32] = "";
        strncpy(id, slash ? slash + 1 : fullId, 31);
        /* from is nested: "from":{"address":"...","name":"..."} */
        char from[160] = "", subj[200] = "", date[32] = "";
        /* find "from" then "address" after it */
        const char *fhit = strstr(hit, "\"from\"");
        if (fhit) jsonStr(fhit, "address", from, sizeof(from));
        jsonStr(hit, "subject", subj, sizeof(subj));
        jsonStr(hit, "createdAt", date, sizeof(date));
        if (id[0]) {
            strncpy(g_mails[g_mailCount].id,      id,   31);
            strncpy(g_mails[g_mailCount].from,    from, 159);
            strncpy(g_mails[g_mailCount].subject, subj, 199);
            strncpy(g_mails[g_mailCount].date,    date, 31);
            g_mailCount++;
        }
        p = hit + 5;
    }
    return 1;
}

static int mailtm_fetchBody(const char *mailId, char *bodyOut, int bodySize) {
    HINTERNET hSes = WinHttpOpen(L"GeradorSenha/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return 0;
    HINTERNET hCon = WinHttpConnect(hSes, L"api.mail.tm", INTERNET_DEFAULT_HTTPS_PORT, 0);
    wchar_t idW[48]; utf8ToWide(mailId, idW, 48);
    wchar_t path[80]; swprintf(path, 80, L"/messages/%ls", idW);
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    WinHttpSetTimeouts(hReq, 5000, 5000, 10000, 10000);
    wchar_t hdrs[700];
    swprintf(hdrs, 700, L"Authorization: Bearer %hs\r\n", g_mailtmToken);
    BOOL ok = WinHttpSendRequest(hReq, hdrs, (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    char buf[65536] = ""; int total = 0;
    if (ok && WinHttpReceiveResponse(hReq, NULL)) {
        DWORD rd = 0;
        while (total < (int)sizeof(buf) - 1) {
            DWORD av = 0;
            if (!WinHttpQueryDataAvailable(hReq, &av) || av == 0) break;
            if (av > (DWORD)(sizeof(buf) - 1 - total)) av = sizeof(buf) - 1 - total;
            if (!WinHttpReadData(hReq, buf + total, av, &rd)) break;
            total += rd;
        }
        buf[total] = 0;
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    if (!total) return 0;
    char raw[65536] = "";
    if (!jsonStr(buf, "text", raw, sizeof(raw)) || !raw[0])
        jsonStr(buf, "html", raw, sizeof(raw));
    int j = 0, inTag = 0;
    for (int i = 0; raw[i] && j < bodySize - 1; i++) {
        if (raw[i] == '<') { inTag = 1; continue; }
        if (raw[i] == '>') { inTag = 0;
            if (j > 0 && bodyOut[j-1] != '\n') bodyOut[j++] = '\n';
            continue; }
        if (!inTag) bodyOut[j++] = raw[i];
    }
    bodyOut[j] = 0;
    return j > 0;
}

/* ===== Password strength evaluator ===== */
static int passwordStrength(const wchar_t *pwd, int *outLevel) {
    int len = (int)wcslen(pwd);
    int hL=0, hU=0, hN=0, hS=0;
    for (int i = 0; i < len; i++) {
        wchar_t c = pwd[i];
        if (c >= L'a' && c <= L'z') hL = 1;
        else if (c >= L'A' && c <= L'Z') hU = 1;
        else if (c >= L'0' && c <= L'9') hN = 1;
        else hS = 1;
    }
    int variety = hL + hU + hN + hS;
    int score = 0;
    if (len >= 6) score += 10;
    if (len >= 8) score += 15;
    if (len >= 12) score += 20;
    if (len >= 16) score += 15;
    score += variety * 10;
    if (score > 100) score = 100;
    /* level 0=very weak,1=weak,2=ok,3=good,4=strong */
    int level = 0;
    if (score >= 90) level = 4;
    else if (score >= 70) level = 3;
    else if (score >= 50) level = 2;
    else if (score >= 30) level = 1;
    *outLevel = level;
    return score;
}

/* ===== UI helpers ===== */
static void setFont(HWND h, HFONT f) { SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE); }
static void setText(HWND h, const wchar_t *t) { SetWindowTextW(h, t); }

static void showMessage(HWND lbl, const wchar_t *t, COLORREF c) {
    SetWindowTextW(lbl, t);
    SetWindowLongPtrW(lbl, GWLP_USERDATA, (LONG_PTR)c);
    InvalidateRect(lbl, NULL, TRUE);
    SetTimer(hMain, ID_TIMER_MSG, 4000, NULL);
    g_msgTimerActive = 1;
}

static void copyToClipboard(const wchar_t *txt) {
    if (OpenClipboard(hMain)) {
        EmptyClipboard();
        size_t bytes = (wcslen(txt) + 1) * sizeof(wchar_t);
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (h) {
            memcpy(GlobalLock(h), txt, bytes);
            GlobalUnlock(h);
            SetClipboardData(CF_UNICODETEXT, h);
        }
        CloseClipboard();
        wcsncpy(g_lastClipped, txt, 199);
        g_lastClipped[199] = 0;
        SetTimer(hMain, ID_TIMER_CLIP, CLIPBOARD_CLEAR_SEC * 1000, NULL);
        g_clipTimerActive = 1;
    }
}

static void maybeClearClipboard(void) {
    if (!g_lastClipped[0]) return;
    if (!OpenClipboard(hMain)) return;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        wchar_t *cur = (wchar_t*)GlobalLock(h);
        if (cur && wcscmp(cur, g_lastClipped) == 0) {
            EmptyClipboard();
        }
        if (cur) GlobalUnlock(h);
    }
    CloseClipboard();
    SecureZeroMemory(g_lastClipped, sizeof(g_lastClipped));
}

static void togglePasswordChar(HWND edit, int show) {
    SendMessageW(edit, EM_SETPASSWORDCHAR, show ? 0 : (WPARAM)L'•', 0);
    InvalidateRect(edit, NULL, TRUE);
}

static int isCapsLockOn(void) {
    return (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
}

/* ===== Multi-field dialog ===== */
typedef struct {
    const wchar_t *title;
    int fieldCount;
    const wchar_t *labels[4];
    wchar_t values[4][160];
    int passwordMask[4];
} MultiDlg;

static MultiDlg g_dlg;

static INT_PTR CALLBACK MultiDlgProc(HWND hDlg, UINT m, WPARAM wp, LPARAM lp) {
    (void)lp;
    switch (m) {
    case WM_INITDIALOG:
        SetWindowTextW(hDlg, g_dlg.title);
        for (int i = 0; i < g_dlg.fieldCount; i++) {
            SetDlgItemTextW(hDlg, 200 + i, g_dlg.labels[i]);
            SetDlgItemTextW(hDlg, 300 + i, g_dlg.values[i]);
            if (g_dlg.passwordMask[i]) {
                SendDlgItemMessageW(hDlg, 300 + i, EM_SETPASSWORDCHAR, (WPARAM)L'•', 0);
            }
        }
        SetFocus(GetDlgItem(hDlg, 300));
        SendDlgItemMessageW(hDlg, 300, EM_SETSEL, 0, -1);
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            for (int i = 0; i < g_dlg.fieldCount; i++) {
                GetDlgItemTextW(hDlg, 300 + i, g_dlg.values[i], 160);
            }
            EndDialog(hDlg, 1); return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(hDlg, 0); return TRUE; }
    }
    return FALSE;
}

static int showMultiDialog(HWND parent) {
    int N = g_dlg.fieldCount;
    int dlgH = 30 + N * 40 + 25;
    BYTE buf[1024] = {0};
    DLGTEMPLATE *dlg = (DLGTEMPLATE*)buf;
    dlg->style = DS_MODALFRAME | DS_CENTER | DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    dlg->cdit = 2 + N * 2;
    dlg->cx = 240; dlg->cy = (short)dlgH;
    WORD *p = (WORD*)(dlg + 1);
    *p++ = 0; *p++ = 0; *p++ = 0;
    *p++ = 9;
    const wchar_t *fname = L"Segoe UI";
    wcscpy((wchar_t*)p, fname); p += wcslen(fname) + 1;
    p = (WORD*)(((ULONG_PTR)p + 3) & ~3);

    int yy = 8;
    for (int i = 0; i < N; i++) {
        DLGITEMTEMPLATE *it = (DLGITEMTEMPLATE*)p;
        it->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
        it->x = 8; it->y = (short)yy; it->cx = 220; it->cy = 10; it->id = 200 + i;
        p = (WORD*)(it + 1);
        *p++ = 0xFFFF; *p++ = 0x0082; *p++ = 0; *p++ = 0;
        p = (WORD*)(((ULONG_PTR)p + 3) & ~3);
        it = (DLGITEMTEMPLATE*)p;
        it->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL;
        it->x = 8; it->y = (short)(yy + 12); it->cx = 220; it->cy = 14; it->id = 300 + i;
        p = (WORD*)(it + 1);
        *p++ = 0xFFFF; *p++ = 0x0081; *p++ = 0; *p++ = 0;
        p = (WORD*)(((ULONG_PTR)p + 3) & ~3);
        yy += 32;
    }
    DLGITEMTEMPLATE *it = (DLGITEMTEMPLATE*)p;
    it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    it->x = 120; it->y = (short)(dlgH - 22); it->cx = 50; it->cy = 14; it->id = IDOK;
    p = (WORD*)(it + 1);
    *p++ = 0xFFFF; *p++ = 0x0080;
    wcscpy((wchar_t*)p, L"OK"); p += 3; *p++ = 0;
    p = (WORD*)(((ULONG_PTR)p + 3) & ~3);
    it = (DLGITEMTEMPLATE*)p;
    it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
    it->x = 178; it->y = (short)(dlgH - 22); it->cx = 50; it->cy = 14; it->id = IDCANCEL;
    p = (WORD*)(it + 1);
    *p++ = 0xFFFF; *p++ = 0x0080;
    const wchar_t *cancel = (g_lang == 0) ? L"Cancelar" : L"Cancel";
    wcscpy((wchar_t*)p, cancel); p += wcslen(cancel) + 1;
    *p++ = 0;
    return (int)DialogBoxIndirectW(GetModuleHandle(NULL), dlg, parent, MultiDlgProc);
}

static void applyLanguage(void);
static void switchSub(int);
static void rebuildVaultList(const wchar_t *filter);

/* ===== Show/hide ===== */
static void hideAll(void) {
    HWND all[] = {
        hRegLblTitle, hRegLblSub, hRegLblUser, hRegUser, hRegLblPwd, hRegLblConf,
        hRegPwd, hRegConfirm, hRegShowPwd, hRegShowConf, hRegBtn, hRegMsg, hRegStrengthBar, hRegStrengthLbl, hRegCapsLbl, hRegGuestBtn,
        hLogLblTitle, hLogLblSub, hLogLblPwd, hLogPwd, hLogShowPwd, hLogBtn, hLogMsg, hLogCapsLbl, hLogResetBtn, hLogGuestBtn,
        hLangBtn, hLogoutBtn, hTabGenBtn, hTabUserBtn, hTabEmailBtn, hTabVaultBtn, hTabSetBtn, hMainTitle,
        hGenLblTitle, hGenLblUser, hGenUser, hGenLblLen, hGenLenVal, hGenSlider,
        hGenLblMode, hGenMode,
        hGenLblOpts, hGenChkUpper, hGenChkLower, hGenChkNumber, hGenChkSpec,
        hGenRadLimit, hGenRadFull, hGenLblPattern, hGenPattern, hGenPatternHint,
        hGenLblOut, hGenOut, hGenShow, hGenCopy, hGenSave, hGenGen,
        hGenChk[0], hGenChk[1], hGenChk[2], hGenChk[3], hGenChk[4], hGenChk[5], hGenBar, hGenMsg,
        hUserLblTitle, hUserLblTheme, hUserTheme, hUserLblStyle, hUserStyle, hUserChkNum, hUserChkBase,
        hUserLblOut, hUserOut, hUserCopy, hUserSave, hUserGen, hUserMsg,
        hEmailLblTitle, hEmailLblTheme, hEmailTheme, hEmailLblStyle, hEmailStyle, hEmailChkNum, hEmailChkBase,
        hEmailLblDomain, hEmailDomain, hEmailLblOut, hEmailOut, hEmailCopy, hEmailSave, hEmailGen, hEmailMsg,
        hVaultLblTitle, hVaultLblSearch, hVaultSearch, hVaultList, hVaultLblUsr, hVaultUsr,
        hVaultLblPwd, hVaultPwd, hVaultShow, hVaultCopyPwd, hVaultCopyUsr, hVaultEdit, hVaultDel, hVaultMsg, hVaultEmpty,
        hSetLblTitle, hSetLblChange, hSetLblCur, hSetLblNew, hSetLblConf,
        hSetCurPwd, hSetNewPwd, hSetNewConf, hSetChangeBtn, hSetMsg,
        hTabTempBtn,
        hTempLblTitle, hTempLblAddr, hTempAddr, hTempCopyAddr, hTempGet,
        hTempLblProvider, hTempProvider,
        hTempLblDomain, hTempDomain,
        hTempLblInbox, hTempList, hTempRefresh, hTempEmpty,
        hTempLblFrom, hTempFrom, hTempLblSubj, hTempSubj,
        hTempBody, hTempDel, hTempMsg, hTempAuto
    };
    for (size_t i = 0; i < sizeof(all)/sizeof(all[0]); i++) if (all[i]) ShowWindow(all[i], SW_HIDE);
}

static void showWnds(HWND *list, size_t n) { for (size_t i = 0; i < n; i++) ShowWindow(list[i], SW_SHOW); }

static void showRegister(void) {
    HWND list[] = { hRegLblTitle, hRegLblSub, hRegLblUser, hRegUser, hRegLblPwd, hRegLblConf,
        hRegPwd, hRegConfirm, hRegShowPwd, hRegShowConf, hRegBtn, hRegMsg, hRegStrengthBar, hRegStrengthLbl, hRegGuestBtn, hLangBtn };
    showWnds(list, ARRSZ(list));
}
static void showLogin(void) {
    HWND list[] = { hLogLblTitle, hLogLblSub, hLogLblPwd, hLogPwd, hLogShowPwd, hLogBtn, hLogMsg, hLogResetBtn, hLogGuestBtn, hLangBtn };
    showWnds(list, ARRSZ(list));
}
static void showMainTopBar(void) {
    HWND list[] = { hLangBtn, hLogoutBtn, hTabGenBtn, hTabUserBtn, hTabEmailBtn, hTabVaultBtn, hTabSetBtn, hTabTempBtn, hMainTitle };
    showWnds(list, ARRSZ(list));
}
static void showTempPanel(void) {
    HWND list[] = { hTempLblTitle, hTempLblAddr, hTempAddr, hTempCopyAddr, hTempGet,
        hTempLblProvider, hTempProvider,
        hTempLblDomain, hTempDomain,
        hTempLblInbox, hTempList, hTempRefresh, hTempEmpty,
        hTempLblFrom, hTempFrom, hTempLblSubj, hTempSubj,
        hTempBody, hTempDel, hTempMsg, hTempAuto };
    showWnds(list, ARRSZ(list));
}
static void showGenPanel(void) {
    HWND list[] = {
        hGenLblTitle, hGenLblUser, hGenUser, hGenLblLen, hGenLenVal, hGenSlider,
        hGenLblMode, hGenMode,
        hGenLblOpts, hGenChkUpper, hGenChkLower, hGenChkNumber, hGenChkSpec,
        hGenRadLimit, hGenRadFull, hGenLblPattern, hGenPattern, hGenPatternHint,
        hGenLblOut, hGenOut, hGenShow, hGenCopy, hGenSave, hGenGen,
        hGenChk[0], hGenChk[1], hGenChk[2], hGenChk[3], hGenChk[4], hGenChk[5], hGenBar, hGenMsg
    };
    showWnds(list, ARRSZ(list));
}
static void showUserPanel(void) {
    HWND list[] = { hUserLblTitle, hUserLblTheme, hUserTheme, hUserLblStyle, hUserStyle, hUserChkNum, hUserChkBase,
        hUserLblOut, hUserOut, hUserCopy, hUserSave, hUserGen, hUserMsg };
    showWnds(list, ARRSZ(list));
}
static void showEmailPanel(void) {
    HWND list[] = { hEmailLblTitle, hEmailLblTheme, hEmailTheme, hEmailLblStyle, hEmailStyle, hEmailChkNum, hEmailChkBase,
        hEmailLblDomain, hEmailDomain, hEmailLblOut, hEmailOut, hEmailCopy, hEmailSave, hEmailGen, hEmailMsg };
    showWnds(list, ARRSZ(list));
}
static void showVaultPanel(void) {
    HWND list[] = { hVaultLblTitle, hVaultLblSearch, hVaultSearch, hVaultList, hVaultLblUsr, hVaultUsr,
        hVaultLblPwd, hVaultPwd, hVaultShow, hVaultCopyPwd, hVaultCopyUsr, hVaultEdit, hVaultDel, hVaultMsg };
    showWnds(list, ARRSZ(list));
    if (g_entryCount == 0) ShowWindow(hVaultEmpty, SW_SHOW);
}
static void showSettingsPanel(void) {
    HWND list[] = { hSetLblTitle, hSetLblChange, hSetLblCur, hSetLblNew, hSetLblConf,
        hSetCurPwd, hSetNewPwd, hSetNewConf, hSetChangeBtn, hSetMsg };
    showWnds(list, ARRSZ(list));
}

static void switchState(int s) {
    g_state = s;
    hideAll();
    applyLanguage();
    if (s == STATE_REGISTER) showRegister();
    else if (s == STATE_LOGIN || s == STATE_LOCKED) showLogin();
    else if (s == STATE_MAIN) {
        showMainTopBar();
        if (g_subState == SUB_GEN) showGenPanel();
        else if (g_subState == SUB_USER) showUserPanel();
        else if (g_subState == SUB_EMAIL) showEmailPanel();
        else if (g_subState == SUB_SETTINGS) showSettingsPanel();
        else showVaultPanel();
    }
    InvalidateRect(hMain, NULL, TRUE);
}

static void switchSub(int s) {
    g_subState = s;
    hideAll();
    showMainTopBar();
    if (s == SUB_GEN) showGenPanel();
    else if (s == SUB_USER) showUserPanel();
    else if (s == SUB_EMAIL) showEmailPanel();
    else if (s == SUB_SETTINGS) showSettingsPanel();
    else if (s == SUB_TEMP) showTempPanel();
    else { showVaultPanel(); rebuildVaultList(L""); }
    InvalidateRect(hMain, NULL, TRUE);
}

/* ===== Apply language ===== */
static void applyLanguage(void) {
    SetWindowTextW(hMain, g_isGuest ? T(S_GUEST_TITLE) : T(S_APP_TITLE));
    setText(hLogGuestBtn, T(S_GUEST_BTN));
    setText(hRegGuestBtn, T(S_GUEST_BTN));
    setText(hRegLblTitle, T(S_REG_TITLE));
    setText(hRegLblSub, T(S_REG_SUB));
    setText(hRegLblUser, T(S_REG_USER));
    setText(hRegLblPwd, T(S_REG_PWD));
    setText(hRegLblConf, T(S_REG_CONFIRM));
    setText(hRegBtn, T(S_REG_BTN));
    if (g_username[0]) {
        wchar_t userW[64]; utf8ToWide(g_username, userW, 64);
        wchar_t buf[160]; swprintf(buf, 160, T(S_LOG_WELCOME), userW);
        setText(hLogLblTitle, buf);
    } else {
        setText(hLogLblTitle, T(S_LOG_TITLE));
    }
    if (g_state == STATE_LOCKED) {
        wchar_t b[160]; swprintf(b, 160, T(S_LOCKED_SUB), g_lockoutSeconds);
        setText(hLogLblSub, b);
    } else {
        setText(hLogLblSub, T(S_LOG_SUB));
    }
    setText(hLogLblPwd, T(S_LOG_PWD));
    setText(hLogBtn, T(S_LOG_BTN));
    setText(hLangBtn, T(S_LANG_BTN));
    setText(hLogoutBtn, T(S_LOGOUT));
    setText(hTabGenBtn, T(S_TAB_GEN));
    setText(hTabUserBtn, T(S_TAB_USER));
    setText(hTabEmailBtn, T(S_TAB_EMAIL));
    setText(hTabVaultBtn, T(S_TAB_VAULT));
    setText(hTabSetBtn, T(S_TAB_SETTINGS));
    setText(hMainTitle, g_isGuest ? T(S_GUEST_TITLE) : T(S_APP_TITLE));

    setText(hGenLblTitle, T(S_GEN_TITLE));
    setText(hGenLblUser, T(S_GEN_USER));
    setText(hGenLblLen, T(S_GEN_LEN));
    setText(hGenLblOpts, T(S_GEN_OPTS));
    setText(hGenLblMode, T(S_GEN_MODE));
    int msel = (int)SendMessageW(hGenMode, CB_GETCURSEL, 0, 0);
    SendMessageW(hGenMode, CB_RESETCONTENT, 0, 0);
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)T(S_MODE_CLASSIC));
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)T(S_MODE_PHRASE));
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)T(S_MODE_PRONOUNCE));
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)T(S_MODE_PATTERN));
    SendMessageW(hGenMode, CB_SETCURSEL, msel < 0 ? 0 : msel, 0);
    setText(hGenLblPattern, T(S_GEN_PATTERN_LBL));
    SetWindowTextW(hGenPatternHint, T(S_GEN_PATTERN_HINT));
    setText(hGenChkUpper, T(S_OPT_UPPER));
    setText(hGenChkLower, T(S_OPT_LOWER));
    setText(hGenChkNumber, T(S_OPT_NUMBER));
    setText(hGenChkSpec, T(S_OPT_SPEC));
    setText(hGenRadLimit, T(S_OPT_LIMIT));
    setText(hGenRadFull, T(S_OPT_FULL));
    setText(hGenLblOut, T(S_GEN_OUT));
    setText(hGenCopy, T(S_BTN_COPY));
    setText(hGenSave, T(S_BTN_SAVE));
    setText(hGenGen, T(S_BTN_GEN));
    setText(hGenChk[0], T(S_CHK_LOWER));
    setText(hGenChk[1], T(S_CHK_UPPER));
    setText(hGenChk[2], T(S_CHK_NUMBER));
    setText(hGenChk[3], T(S_CHK_SPEC));
    setText(hGenChk[4], T(S_CHK_LEN));
    setText(hGenChk[5], T(S_CHK_LETNUM));

    setText(hUserLblTitle, T(S_USER_TITLE));
    setText(hUserLblTheme, T(S_USER_THEME));
    setText(hUserLblStyle, T(S_USER_STYLE));
    setText(hUserChkNum, T(S_USER_NUM));
    setText(hUserChkBase, T(S_USER_BASE));
    setText(hUserLblOut, T(S_USER_OUT));
    setText(hUserCopy, T(S_BTN_COPY));
    setText(hUserSave, T(S_BTN_SAVE));
    setText(hUserGen, T(S_BTN_GEN));

    int sel = (int)SendMessageW(hUserTheme, CB_GETCURSEL, 0, 0);
    SendMessageW(hUserTheme, CB_RESETCONTENT, 0, 0);
    SendMessageW(hUserTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_ANIMAL));
    SendMessageW(hUserTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_NATURE));
    SendMessageW(hUserTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_TECH));
    SendMessageW(hUserTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_FANTASY));
    SendMessageW(hUserTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_SPORTS));
    SendMessageW(hUserTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_RANDOM));
    SendMessageW(hUserTheme, CB_SETCURSEL, sel < 0 ? 5 : sel, 0);

    sel = (int)SendMessageW(hUserStyle, CB_GETCURSEL, 0, 0);
    SendMessageW(hUserStyle, CB_RESETCONTENT, 0, 0);
    SendMessageW(hUserStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_CAMEL));
    SendMessageW(hUserStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_LOWER));
    SendMessageW(hUserStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_SNAKE));
    SendMessageW(hUserStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_DOT));
    SendMessageW(hUserStyle, CB_SETCURSEL, sel < 0 ? 0 : sel, 0);

    setText(hEmailLblTitle, T(S_EMAIL_TITLE));
    setText(hEmailLblTheme, T(S_USER_THEME));
    setText(hEmailLblStyle, T(S_USER_STYLE));
    setText(hEmailChkNum, T(S_USER_NUM));
    setText(hEmailChkBase, T(S_USER_BASE));
    setText(hEmailLblDomain, T(S_EMAIL_DOMAIN));
    setText(hEmailLblOut, T(S_EMAIL_OUT));
    setText(hEmailCopy, T(S_BTN_COPY));
    setText(hEmailSave, T(S_BTN_SAVE));
    setText(hEmailGen, T(S_BTN_GEN));

    sel = (int)SendMessageW(hEmailTheme, CB_GETCURSEL, 0, 0);
    SendMessageW(hEmailTheme, CB_RESETCONTENT, 0, 0);
    SendMessageW(hEmailTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_ANIMAL));
    SendMessageW(hEmailTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_NATURE));
    SendMessageW(hEmailTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_TECH));
    SendMessageW(hEmailTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_FANTASY));
    SendMessageW(hEmailTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_SPORTS));
    SendMessageW(hEmailTheme, CB_ADDSTRING, 0, (LPARAM)T(S_TH_RANDOM));
    SendMessageW(hEmailTheme, CB_SETCURSEL, sel < 0 ? 5 : sel, 0);

    sel = (int)SendMessageW(hEmailStyle, CB_GETCURSEL, 0, 0);
    SendMessageW(hEmailStyle, CB_RESETCONTENT, 0, 0);
    SendMessageW(hEmailStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_CAMEL));
    SendMessageW(hEmailStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_LOWER));
    SendMessageW(hEmailStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_SNAKE));
    SendMessageW(hEmailStyle, CB_ADDSTRING, 0, (LPARAM)T(S_ST_DOT));
    SendMessageW(hEmailStyle, CB_SETCURSEL, sel < 0 ? 1 : sel, 0);

    setText(hVaultLblTitle, T(S_VAULT_TITLE));
    setText(hVaultLblSearch, T(S_VAULT_SEARCH));
    setText(hVaultLblUsr, T(S_VAULT_USR));
    setText(hVaultLblPwd, T(S_VAULT_PWD));
    setText(hVaultEmpty, T(S_VAULT_EMPTY));
    setText(hVaultShow, g_vaultRevealed ? T(S_BTN_HIDE) : T(S_BTN_SHOW));
    setText(hVaultCopyPwd, T(S_VAULT_COPY_PWD));
    setText(hVaultCopyUsr, T(S_VAULT_COPY_USR));
    setText(hVaultDel, T(S_BTN_DEL));
    setText(hVaultEdit, T(S_BTN_EDIT));

    setText(hSetLblTitle, T(S_SET_TITLE));
    setText(hSetLblChange, T(S_SET_CHANGE_TITLE));
    setText(hSetLblCur, T(S_SET_CUR_PWD));
    setText(hSetLblNew, T(S_SET_NEW_PWD));
    setText(hSetLblConf, T(S_SET_NEW_CONF));
    setText(hSetChangeBtn, T(S_SET_CHANGE_BTN));
    setText(hLogResetBtn, T(S_SET_RESET_BTN));
    setText(hTabTempBtn, T(S_TAB_TEMP));
    setText(hTempLblTitle, T(S_TEMP_TITLE));
    setText(hTempLblAddr, T(S_TEMP_ADDR));
    setText(hTempGet, T(S_TEMP_GET));
    setText(hTempCopyAddr, T(S_TEMP_COPY_ADDR));
    setText(hTempLblInbox, T(S_TEMP_INBOX));
    setText(hTempRefresh, T(S_TEMP_REFRESH));
    setText(hTempEmpty, T(S_TEMP_EMPTY));
    setText(hTempLblFrom, T(S_TEMP_FROM));
    setText(hTempDel, T(S_TEMP_DEL));
    setText(hTempAuto, T(S_TEMP_AUTO));
    setText(hTempLblDomain, T(S_TEMP_DOMAIN));
    setText(hTempLblProvider, T(S_TEMP_PROVIDER));
    int psel = (int)SendMessageW(hTempProvider, CB_GETCURSEL, 0, 0);
    SendMessageW(hTempProvider, CB_RESETCONTENT, 0, 0);
    SendMessageW(hTempProvider, CB_ADDSTRING, 0, (LPARAM)T(S_PROV_GUERRILLA));
    SendMessageW(hTempProvider, CB_ADDSTRING, 0, (LPARAM)T(S_PROV_SECMAIL));
    SendMessageW(hTempProvider, CB_ADDSTRING, 0, (LPARAM)T(S_PROV_MAILTM));
    SendMessageW(hTempProvider, CB_SETCURSEL, psel < 0 ? 0 : psel, 0);
}

/* ===== Generator actions ===== */
static void updateGenChecks(const wchar_t *pwd) {
    char b[200]; wideToUtf8(pwd, b, sizeof(b));
    int len = (int)strlen(b);
    int hL=0,hU=0,hN=0,hS=0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)b[i];
        if (islower(c)) hL = 1;
        else if (isupper(c)) hU = 1;
        else if (isdigit(c)) hN = 1;
        else hS = 1;
    }
    int hLen = (len >= 8 && len <= 64);
    int hLN = ((hL || hU) && hN);
    int r[6] = {hL, hU, hN, hS, hLen, hLN};
    int p = 0;
    for (int i = 0; i < 6; i++) {
        SendMessageW(hGenChk[i], BM_SETCHECK, r[i] ? BST_CHECKED : BST_UNCHECKED, 0);
        if (r[i]) p++;
    }
    g_barPct = (p * 100) / 6;
    g_barColor = (p == 6) ? clrAccent : (p >= 4) ? clrWarn : clrError;
    InvalidateRect(hGenBar, NULL, TRUE);
}

static void doGenerate(void) {
    int len = (int)SendMessageW(hGenSlider, TBM_GETPOS, 0, 0);
    int mode = (int)SendMessageW(hGenMode, CB_GETCURSEL, 0, 0);
    if (mode < 0) mode = 0;
    int sL = SendMessageW(hGenRadLimit, BM_GETCHECK, 0, 0) == BST_CHECKED;
    char outU[2048] = "";

    if (mode == 0) {
        /* Classic */
        int uU = SendMessageW(hGenChkUpper, BM_GETCHECK, 0, 0) == BST_CHECKED;
        int uL = SendMessageW(hGenChkLower, BM_GETCHECK, 0, 0) == BST_CHECKED;
        int uN = SendMessageW(hGenChkNumber, BM_GETCHECK, 0, 0) == BST_CHECKED;
        int uS = SendMessageW(hGenChkSpec, BM_GETCHECK, 0, 0) == BST_CHECKED;
        if (!uU && !uL && !uN && !uS) { showMessage(hGenMsg, T(S_MSG_NEED_TYPE), clrError); return; }
        wchar_t userW[128]; GetWindowTextW(hGenUser, userW, 128);
        char userU[128]; wideToUtf8(userW, userU, sizeof(userU));
        int r = generatePassword(outU, sizeof(outU), len, uU, uL, uN, uS, sL, userU);
        if (r == -1) { showMessage(hGenMsg, T(S_MSG_NEED_LEN), clrError); return; }
        if (r != 1) return;
    } else if (mode == 1) {
        /* Passphrase — words, length = word count (min 2, max 50) */
        int words = len / 6; if (words < 2) words = 2; if (words > 50) words = 50;
        int uS = SendMessageW(hGenChkNumber, BM_GETCHECK, 0, 0) == BST_CHECKED;
        generatePassphrase(outU, sizeof(outU), words, uS);
    } else if (mode == 2) {
        /* Pronounceable */
        int uS = SendMessageW(hGenChkSpec, BM_GETCHECK, 0, 0) == BST_CHECKED;
        generatePronounceable(outU, sizeof(outU), len, uS);
    } else if (mode == 3) {
        /* Pattern */
        wchar_t patW[512]; GetWindowTextW(hGenPattern, patW, 512);
        if (!patW[0]) { showMessage(hGenMsg, T(S_MSG_NO_PWD), clrError); return; }
        char patU[512]; wideToUtf8(patW, patU, sizeof(patU));
        generateFromPattern(outU, sizeof(outU), patU, sL);
    }

    if (!outU[0]) return;
    utf8ToWide(outU, g_currentPwd, 2048);
    SetWindowTextW(hGenOut, g_currentPwd);
    if (!g_genRevealed) togglePasswordChar(hGenOut, 0);
    updateGenChecks(g_currentPwd);
}

static void doCopyGen(void) {
    if (!g_currentPwd[0]) { showMessage(hGenMsg, T(S_MSG_NO_PWD), clrError); return; }
    copyToClipboard(g_currentPwd);
    showMessage(hGenMsg, T(S_MSG_COPIED), clrAccent);
}

/* Save dialog: 2 fields (label + username), pwd from generator */
static void doSavePassword(void) {
    if (!g_currentPwd[0]) { showMessage(hGenMsg, T(S_MSG_NO_PWD), clrError); return; }
    g_dlg.title = T(S_DLG_LABEL_TITLE);
    g_dlg.fieldCount = 2;
    g_dlg.labels[0] = T(S_DLG_LABEL); g_dlg.values[0][0] = 0; g_dlg.passwordMask[0] = 0;
    g_dlg.labels[1] = T(S_DLG_USER);  g_dlg.values[1][0] = 0; g_dlg.passwordMask[1] = 0;
    if (showMultiDialog(hMain) != 1) return;
    if (!g_dlg.values[0][0]) return;
    char lblU[128], usrU[128], pwdU[128];
    wideToUtf8(g_dlg.values[0], lblU, 128);
    wideToUtf8(g_dlg.values[1], usrU, 128);
    wideToUtf8(g_currentPwd, pwdU, 128);
    if (addVaultEntry(lblU, usrU, pwdU)) showMessage(hGenMsg, T(S_MSG_SAVED), clrAccent);
}

/* ===== Username/Email actions ===== */
static void doGenerateUsername(void) {
    int theme = (int)SendMessageW(hUserTheme, CB_GETCURSEL, 0, 0);
    int style = (int)SendMessageW(hUserStyle, CB_GETCURSEL, 0, 0);
    int useNum = SendMessageW(hUserChkNum, BM_GETCHECK, 0, 0) == BST_CHECKED;
    int useBase = SendMessageW(hUserChkBase, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (theme < 0) theme = 5;
    if (style < 0) style = 0;
    char outU[200];
    generateUsername(outU, sizeof(outU), theme, style, useNum, useBase, g_username);
    utf8ToWide(outU, g_currentUser, 160);
    SetWindowTextW(hUserOut, g_currentUser);
}

static void doCopyUser(void) {
    if (!g_currentUser[0]) { showMessage(hUserMsg, T(S_MSG_NO_PWD), clrError); return; }
    copyToClipboard(g_currentUser);
    showMessage(hUserMsg, T(S_MSG_COPIED), clrAccent);
}

static void doSaveUser(void) {
    if (!g_currentUser[0]) { showMessage(hUserMsg, T(S_MSG_NO_PWD), clrError); return; }
    g_dlg.title = T(S_DLG_LABEL_TITLE);
    g_dlg.fieldCount = 1;
    g_dlg.labels[0] = T(S_DLG_LABEL); g_dlg.values[0][0] = 0; g_dlg.passwordMask[0] = 0;
    if (showMultiDialog(hMain) != 1) return;
    if (!g_dlg.values[0][0]) return;
    char lblU[128], valU[200];
    wideToUtf8(g_dlg.values[0], lblU, 128);
    wideToUtf8(g_currentUser, valU, 200);
    if (addVaultEntry(lblU, valU, "")) showMessage(hUserMsg, T(S_MSG_SAVED), clrAccent);
}

static void doGenerateEmail(void) {
    int theme = (int)SendMessageW(hEmailTheme, CB_GETCURSEL, 0, 0);
    int style = (int)SendMessageW(hEmailStyle, CB_GETCURSEL, 0, 0);
    int useNum = SendMessageW(hEmailChkNum, BM_GETCHECK, 0, 0) == BST_CHECKED;
    int useBase = SendMessageW(hEmailChkBase, BM_GETCHECK, 0, 0) == BST_CHECKED;
    int dom = (int)SendMessageW(hEmailDomain, CB_GETCURSEL, 0, 0);
    if (theme < 0) theme = 5;
    if (style < 0) style = 1;
    char localU[200];
    generateUsername(localU, sizeof(localU), theme, style, useNum, useBase, g_username);
    char outU[256];
    if (dom < 0 || dom >= (int)ARRSZ(EMAIL_DOMAINS)) dom = 0;
    snprintf(outU, sizeof(outU), "%s@%s", localU, EMAIL_DOMAINS[dom]);
    utf8ToWide(outU, g_currentEmail, 200);
    SetWindowTextW(hEmailOut, g_currentEmail);
}

static void doCopyEmail(void) {
    if (!g_currentEmail[0]) { showMessage(hEmailMsg, T(S_MSG_NO_PWD), clrError); return; }
    copyToClipboard(g_currentEmail);
    showMessage(hEmailMsg, T(S_MSG_COPIED), clrAccent);
}

static void doSaveEmail(void) {
    if (!g_currentEmail[0]) { showMessage(hEmailMsg, T(S_MSG_NO_PWD), clrError); return; }
    g_dlg.title = T(S_DLG_LABEL_TITLE);
    g_dlg.fieldCount = 1;
    g_dlg.labels[0] = T(S_DLG_LABEL); g_dlg.values[0][0] = 0; g_dlg.passwordMask[0] = 0;
    if (showMultiDialog(hMain) != 1) return;
    if (!g_dlg.values[0][0]) return;
    char lblU[128], valU[200];
    wideToUtf8(g_dlg.values[0], lblU, 128);
    wideToUtf8(g_currentEmail, valU, 200);
    if (addVaultEntry(lblU, valU, "")) showMessage(hEmailMsg, T(S_MSG_SAVED), clrAccent);
}

/* ===== Vault actions ===== */
static int matchesFilter(const char *str, const wchar_t *filterW) {
    if (!filterW || !filterW[0]) return 1;
    wchar_t strW[128]; utf8ToWide(str, strW, 128);
    /* lowercase compare */
    wchar_t la[128], lb[128];
    int n = (int)wcslen(strW); if (n >= 128) n = 127;
    for (int i = 0; i < n; i++) la[i] = (wchar_t)towlower(strW[i]);
    la[n] = 0;
    int m = (int)wcslen(filterW); if (m >= 128) m = 127;
    for (int i = 0; i < m; i++) lb[i] = (wchar_t)towlower(filterW[i]);
    lb[m] = 0;
    return wcsstr(la, lb) != NULL;
}

static void rebuildVaultList(const wchar_t *filter) {
    SendMessageW(hVaultList, LB_RESETCONTENT, 0, 0);
    if (g_vaultFilter) { free(g_vaultFilter); g_vaultFilter = NULL; }
    g_vaultFilterCount = 0;
    g_vaultFilter = (int*)malloc(sizeof(int) * (g_entryCount + 1));
    for (int i = 0; i < g_entryCount; i++) {
        if (matchesFilter(g_entries[i].label, filter) ||
            matchesFilter(g_entries[i].username, filter)) {
            wchar_t lW[128];
            utf8ToWide(g_entries[i].label, lW, 128);
            SendMessageW(hVaultList, LB_ADDSTRING, 0, (LPARAM)lW);
            g_vaultFilter[g_vaultFilterCount++] = i;
        }
    }
    SetWindowTextW(hVaultPwd, L"");
    SetWindowTextW(hVaultUsr, L"");
    g_vaultRevealed = 0;
    setText(hVaultShow, T(S_BTN_SHOW));
    if (g_entryCount > 0) ShowWindow(hVaultEmpty, SW_HIDE);
    else ShowWindow(hVaultEmpty, SW_SHOW);
}

static int getSelectedEntryIdx(void) {
    int sel = (int)SendMessageW(hVaultList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_vaultFilterCount) return -1;
    return g_vaultFilter[sel];
}

static void onVaultSelect(void) {
    int idx = getSelectedEntryIdx();
    if (idx < 0) { SetWindowTextW(hVaultPwd, L""); SetWindowTextW(hVaultUsr, L""); return; }
    wchar_t uW[160];
    utf8ToWide(g_entries[idx].username, uW, 160);
    SetWindowTextW(hVaultUsr, uW);
    if (g_vaultRevealed) {
        wchar_t pW[160];
        utf8ToWide(g_entries[idx].password, pW, 160);
        SetWindowTextW(hVaultPwd, pW);
        togglePasswordChar(hVaultPwd, 1);
    } else {
        wchar_t pW[160];
        utf8ToWide(g_entries[idx].password, pW, 160);
        SetWindowTextW(hVaultPwd, pW);
        togglePasswordChar(hVaultPwd, 0);
    }
}

static void doVaultShow(void) {
    g_vaultRevealed = !g_vaultRevealed;
    setText(hVaultShow, g_vaultRevealed ? T(S_BTN_HIDE) : T(S_BTN_SHOW));
    onVaultSelect();
}

static void doVaultCopyPwd(void) {
    int idx = getSelectedEntryIdx(); if (idx < 0) return;
    wchar_t pW[160];
    utf8ToWide(g_entries[idx].password, pW, 160);
    if (!pW[0]) return;
    copyToClipboard(pW);
    showMessage(hVaultMsg, T(S_MSG_COPIED), clrAccent);
}

static void doVaultCopyUsr(void) {
    int idx = getSelectedEntryIdx(); if (idx < 0) return;
    wchar_t uW[160];
    utf8ToWide(g_entries[idx].username, uW, 160);
    if (!uW[0]) return;
    copyToClipboard(uW);
    showMessage(hVaultMsg, T(S_MSG_COPIED), clrAccent);
}

static void doVaultEdit(void) {
    int idx = getSelectedEntryIdx(); if (idx < 0) return;
    g_dlg.title = T(S_DLG_EDIT_TITLE);
    g_dlg.fieldCount = 3;
    g_dlg.labels[0] = T(S_DLG_LABEL);    utf8ToWide(g_entries[idx].label, g_dlg.values[0], 160);    g_dlg.passwordMask[0] = 0;
    g_dlg.labels[1] = T(S_DLG_USER);     utf8ToWide(g_entries[idx].username, g_dlg.values[1], 160); g_dlg.passwordMask[1] = 0;
    g_dlg.labels[2] = T(S_DLG_PASSWORD); utf8ToWide(g_entries[idx].password, g_dlg.values[2], 160); g_dlg.passwordMask[2] = 0;
    if (showMultiDialog(hMain) != 1) return;
    char lblU[128], usrU[128], pwdU[128];
    wideToUtf8(g_dlg.values[0], lblU, 128);
    wideToUtf8(g_dlg.values[1], usrU, 128);
    wideToUtf8(g_dlg.values[2], pwdU, 128);
    if (updateVaultEntry(idx, lblU, usrU, pwdU)) {
        wchar_t curFilter[128]; GetWindowTextW(hVaultSearch, curFilter, 128);
        rebuildVaultList(curFilter);
        showMessage(hVaultMsg, T(S_MSG_EDITED), clrAccent);
    }
}

static void doDeleteVaultEntry(void) {
    int idx = getSelectedEntryIdx(); if (idx < 0) return;
    int r = MessageBoxW(hMain, T(S_DLG_CONFIRM_DEL), T(S_DLG_TITLE_CONFIRM), MB_YESNO | MB_ICONQUESTION);
    if (r != IDYES) return;
    removeVaultEntry(idx);
    wchar_t curFilter[128]; GetWindowTextW(hVaultSearch, curFilter, 128);
    rebuildVaultList(curFilter);
    showMessage(hVaultMsg, T(S_MSG_DELETED), clrMuted);
}

/* ===== Settings: change master password ===== */
static void doResetApp(void) {
    int r = MessageBoxW(hMain, T(S_DLG_CONFIRM_RESET), T(S_DLG_TITLE_CONFIRM),
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (r != IDYES) return;
    DeleteFileW(g_configPath);
    DeleteFileW(g_vaultPath);
    SecureZeroMemory(g_master, sizeof(g_master));
    SecureZeroMemory(g_username, sizeof(g_username));
    freeVault();
    SetWindowTextW(hSetCurPwd, L"");
    SetWindowTextW(hSetNewPwd, L"");
    SetWindowTextW(hSetNewConf, L"");
    SetWindowTextW(hRegUser, L"");
    SetWindowTextW(hRegPwd, L"");
    SetWindowTextW(hRegConfirm, L"");
    switchState(STATE_REGISTER);
}

static void doChangeMaster(void) {
    wchar_t cW[128], nW[128], confW[128];
    GetWindowTextW(hSetCurPwd, cW, 128);
    GetWindowTextW(hSetNewPwd, nW, 128);
    GetWindowTextW(hSetNewConf, confW, 128);
    if (wcslen(nW) < 6) { showMessage(hSetMsg, T(S_MSG_PWD_SHORT), clrError); return; }
    if (wcscmp(nW, confW) != 0) { showMessage(hSetMsg, T(S_MSG_PWD_MATCH), clrError); return; }
    char cU[128], nU[128];
    wideToUtf8(cW, cU, 128);
    wideToUtf8(nW, nU, 128);
    int r = changeMasterPassword(cU, nU);
    if (r == 1) {
        showMessage(hSetMsg, T(S_SET_CHANGED), clrAccent);
        SetWindowTextW(hSetCurPwd, L"");
        SetWindowTextW(hSetNewPwd, L"");
        SetWindowTextW(hSetNewConf, L"");
    } else {
        showMessage(hSetMsg, T(S_MSG_WRONG), clrError);
    }
}

/* ===== Temp mail UI actions ===== */
static void rebuildTempList(void) {
    SendMessageW(hTempList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_mailCount; i++) {
        wchar_t subjW[200], fromW[160], line[400];
        utf8ToWide(g_mails[i].subject, subjW, 200);
        utf8ToWide(g_mails[i].from, fromW, 160);
        swprintf(line, 400, L"%ls  —  %ls", subjW, fromW);
        SendMessageW(hTempList, LB_ADDSTRING, 0, (LPARAM)line);
    }
    ShowWindow(hTempEmpty, g_mailCount == 0 ? SW_SHOW : SW_HIDE);
    SetWindowTextW(hTempFrom, L"");
    SetWindowTextW(hTempSubj, L"");
    SetWindowTextW(hTempBody, L"");
}

/* ===== Background worker thread for network calls ===== */
static DWORD WINAPI tempMailWorker(LPVOID param) {
    WorkerArgs *args = (WorkerArgs*)param;
    int ok = 0;
    if (args->action == 0) {
        /* generate new address */
        if (g_provider == 0) {
            ok = apiGetNewAddress();
            if (ok) {
                char user[48]; generateRealName(user, sizeof(user));
                char *at = strchr(g_tempEmail, '@');
                const char *dom = (args->domain[0]) ? args->domain : (at ? at+1 : "sharklasers.com");
                apiSetEmailUser(user, dom);
                apiCheckInbox();
            }
        } else if (g_provider == 1) {
            ok = sec_genAddress(args->domain[0] ? args->domain : NULL);
            if (ok) sec_checkInbox();
        } else {
            ok = mailtm_genAddress(args->domain[0] ? args->domain : NULL);
            if (ok) mailtm_checkInbox();
        }
        PostMessageW(hMain, WM_TEMP_RESULT, (WPARAM)ok, 0);
    } else if (args->action == 1) {
        /* refresh inbox */
        if (g_provider == 0) ok = apiCheckInbox();
        else if (g_provider == 1) ok = sec_checkInbox();
        else ok = mailtm_checkInbox();
        PostMessageW(hMain, WM_TEMP_INBOX, (WPARAM)ok, 0);
    } else {
        /* fetch body */
        static char bodyBuf[65536];
        bodyBuf[0] = 0;
        if (g_provider == 0) ok = apiFetchBody(args->mailId, bodyBuf, sizeof(bodyBuf));
        else if (g_provider == 1) ok = sec_fetchBody(args->mailId, bodyBuf, sizeof(bodyBuf));
        else ok = mailtm_fetchBody(args->mailId, bodyBuf, sizeof(bodyBuf));
        PostMessageW(hMain, WM_TEMP_BODY, (WPARAM)ok, (LPARAM)bodyBuf);
    }
    g_workerBusy = 0;
    return 0;
}

static void launchWorker(int action, const char *domain, const char *mailId) {
    if (g_workerBusy) return;
    g_workerBusy = 1;
    g_workerArgs.action = action;
    g_workerArgs.domain[0] = 0;
    g_workerArgs.mailId[0] = 0;
    if (domain) strncpy(g_workerArgs.domain, domain, sizeof(g_workerArgs.domain)-1);
    if (mailId) strncpy(g_workerArgs.mailId, mailId, sizeof(g_workerArgs.mailId)-1);
    HANDLE hThread = CreateThread(NULL, 0, tempMailWorker, &g_workerArgs, 0, NULL);
    if (hThread) CloseHandle(hThread);
    else g_workerBusy = 0;
}

static void populateDomainCombo(void) {
    SendMessageW(hTempDomain, CB_RESETCONTENT, 0, 0);
    if (g_provider == 0) {
        for (size_t i = 0; i < ARRSZ(GUERRILLA_DOMAINS); i++) {
            wchar_t dW[64]; utf8ToWide(GUERRILLA_DOMAINS[i], dW, 64);
            SendMessageW(hTempDomain, CB_ADDSTRING, 0, (LPARAM)dW);
        }
    } else if (g_provider == 1) {
        for (size_t i = 0; i < ARRSZ(SECMAIL_DOMAINS); i++) {
            wchar_t dW[64]; utf8ToWide(SECMAIL_DOMAINS[i], dW, 64);
            SendMessageW(hTempDomain, CB_ADDSTRING, 0, (LPARAM)dW);
        }
    } else {
        if (g_mailtmDomainCount == 0) {
            showMessage(hTempMsg, T(S_TEMP_FETCHING), clrMuted);
            mailtm_fetchDomains();
        }
        for (int i = 0; i < g_mailtmDomainCount; i++) {
            wchar_t dW[64]; utf8ToWide(g_mailtmDomains[i], dW, 64);
            SendMessageW(hTempDomain, CB_ADDSTRING, 0, (LPARAM)dW);
        }
    }
    SendMessageW(hTempDomain, CB_SETCURSEL, 0, 0);
}

static void doTempGetNew(void) {
    if (g_workerBusy) return;
    int dom = (int)SendMessageW(hTempDomain, CB_GETCURSEL, 0, 0);
    char domU[64] = "";
    if (dom >= 0) {
        wchar_t dW[64]; SendMessageW(hTempDomain, CB_GETLBTEXT, dom, (LPARAM)dW);
        wideToUtf8(dW, domU, sizeof(domU));
    }
    if (strncmp(domU, "(", 1) == 0) domU[0] = 0;
    if (g_tempRefreshActive) { KillTimer(hMain, ID_TIMER_REFRESH); g_tempRefreshActive = 0; }
    setText(hTempMsg, T(S_TEMP_LOADING));
    launchWorker(0, domU, NULL);
}

static void doTempRefresh(void) {
    if (g_workerBusy) return;
    if (!g_tempEmail[0]) { setText(hTempMsg, T(S_TEMP_GET)); return; }
    setText(hTempMsg, T(S_TEMP_LOADING));
    launchWorker(1, NULL, NULL);
}

static void doTempSelect(void) {
    if (g_workerBusy) return;
    int sel = (int)SendMessageW(hTempList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_mailCount) return;
    wchar_t fromW[160], subjW[200];
    utf8ToWide(g_mails[sel].from, fromW, 160);
    utf8ToWide(g_mails[sel].subject, subjW, 200);
    SetWindowTextW(hTempFrom, fromW);
    SetWindowTextW(hTempSubj, subjW);
    setText(hTempBody, T(S_TEMP_LOADING));
    launchWorker(2, NULL, g_mails[sel].id);
}

static void doTempCopyAddr(void) {
    wchar_t addrW[128]; GetWindowTextW(hTempAddr, addrW, 128);
    if (!addrW[0]) { setText(hTempMsg, T(S_TEMP_GET)); return; }
    copyToClipboard(addrW);
    showMessage(hTempMsg, T(S_MSG_COPIED), clrAccent);
}

static void doTempDel(void) {
    int sel = (int)SendMessageW(hTempList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_mailCount) return;
    for (int i = sel; i < g_mailCount - 1; i++) g_mails[i] = g_mails[i+1];
    g_mailCount--;
    rebuildTempList();
}

/* ===== Guest mode ===== */
static void doGuestLogin(void) {
    int r = MessageBoxW(hMain, T(S_GUEST_WARN), T(S_DLG_TITLE_CONFIRM),
                        MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2);
    if (r != IDOK) return;
    g_isGuest = 1;
    /* in-memory only "key" used by DPAPI for current session */
    SecureZeroMemory(g_master, sizeof(g_master));
    strncpy(g_master, "guest_session_only_no_persist", sizeof(g_master) - 1);
    SecureZeroMemory(g_username, sizeof(g_username));
    strncpy(g_username, "Guest", sizeof(g_username) - 1);
    freeVault();
    switchState(STATE_MAIN);
}

/* ===== Window procs ===== */
static LRESULT CALLBACK BarProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_PAINT) {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        HBRUSH bg = CreateSolidBrush(clrBorder);
        FillRect(hdc, &rc, bg); DeleteObject(bg);
        int pct = (h == hRegStrengthBar) ? g_regStrength : g_barPct;
        COLORREF col = (h == hRegStrengthBar) ?
            (g_regStrength >= 70 ? clrAccent : g_regStrength >= 40 ? clrWarn : clrError) :
            g_barColor;
        if (pct > 0) {
            RECT f = rc; f.right = (rc.right * pct) / 100;
            HBRUSH fb = CreateSolidBrush(col);
            FillRect(hdc, &f, fb); DeleteObject(fb);
        }
        EndPaint(h, &ps);
        return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

static void updateRegStrength(void) {
    wchar_t pw[128]; GetWindowTextW(hRegPwd, pw, 128);
    int level;
    g_regStrength = passwordStrength(pw, &level);
    InvalidateRect(hRegStrengthBar, NULL, TRUE);
    static const int strIds[] = {S_STR_VERY_WEAK, S_STR_WEAK, S_STR_OK, S_STR_GOOD, S_STR_STRONG};
    if (pw[0]) setText(hRegStrengthLbl, T(strIds[level]));
    else setText(hRegStrengthLbl, L"");
}

static void updateCapsLockIndicators(void) {
    int caps = isCapsLockOn();
    if (g_state == STATE_REGISTER) {
        ShowWindow(hRegCapsLbl, caps ? SW_SHOW : SW_HIDE);
        if (caps) setText(hRegCapsLbl, T(S_MSG_CAPS));
    } else if (g_state == STATE_LOGIN) {
        ShowWindow(hLogCapsLbl, caps ? SW_SHOW : SW_HIDE);
        if (caps) setText(hLogCapsLbl, T(S_MSG_CAPS));
    }
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_COMMAND: {
        int id = LOWORD(wp);
        WORD code = HIWORD(wp);
        if (id == ID_LANG_BTN) { g_lang = 1 - g_lang; applyLanguage(); InvalidateRect(hwnd, NULL, TRUE); return 0; }
        if (id == ID_LOGOUT_BTN) {
            SecureZeroMemory(g_master, sizeof(g_master));
            freeVault();
            g_isGuest = 0;
            switchState(STATE_LOGIN);
            return 0;
        }
        if (id == ID_LOG_GUEST_BTN || id == ID_REG_GUEST_BTN) { doGuestLogin(); return 0; }
        if (id == ID_REG_SHOW_PWD) {
            static int s = 0; s = !s;
            togglePasswordChar(hRegPwd, s);
            return 0;
        }
        if (id == ID_REG_SHOW_CONF) {
            static int s = 0; s = !s;
            togglePasswordChar(hRegConfirm, s);
            return 0;
        }
        if (id == ID_LOG_SHOW_PWD) {
            static int s = 0; s = !s;
            togglePasswordChar(hLogPwd, s);
            return 0;
        }
        if (id == ID_GEN_SHOW) {
            g_genRevealed = !g_genRevealed;
            togglePasswordChar(hGenOut, g_genRevealed);
            return 0;
        }
        if (g_state == STATE_REGISTER) {
            if ((HWND)lp == hRegPwd && code == EN_CHANGE) { updateRegStrength(); }
            if (id == ID_REG_BTN) {
                wchar_t uW[64], a[128], b[128];
                GetWindowTextW(hRegUser, uW, 64);
                GetWindowTextW(hRegPwd, a, 128);
                GetWindowTextW(hRegConfirm, b, 128);
                if (!uW[0]) { showMessage(hRegMsg, T(S_MSG_USER_EMPTY), clrError); return 0; }
                if (wcslen(a) < 6) { showMessage(hRegMsg, T(S_MSG_PWD_SHORT), clrError); return 0; }
                if (wcscmp(a, b) != 0) { showMessage(hRegMsg, T(S_MSG_PWD_MATCH), clrError); return 0; }
                char uU[64], au[128];
                wideToUtf8(uW, uU, 64);
                wideToUtf8(a, au, 128);
                if (registerNewMaster(uU, au)) {
                    strncpy(g_master, au, sizeof(g_master) - 1);
                    strncpy(g_username, uU, sizeof(g_username) - 1);
                    loadVaultFile();
                    switchState(STATE_MAIN);
                }
                return 0;
            }
        }
        if ((g_state == STATE_LOGIN || g_state == STATE_LOCKED) && id == ID_LOGIN_BTN) {
            wchar_t pw[128];
            GetWindowTextW(hLogPwd, pw, 128);
            char pu[128]; wideToUtf8(pw, pu, 128);
            int r = verifyMasterPassword(pu);
            if (r == 1) {
                strncpy(g_master, pu, sizeof(g_master) - 1);
                loadVaultFile();
                switchState(STATE_MAIN);
            } else if (r == -1) {
                wchar_t b[160]; swprintf(b, 160, T(S_MSG_LOCKED), g_lockoutSeconds);
                showMessage(hLogMsg, b, clrError);
                switchState(STATE_LOCKED);
            } else {
                showMessage(hLogMsg, T(S_MSG_WRONG), clrError);
            }
            return 0;
        }
        if (g_state == STATE_MAIN) {
            if (id == ID_TAB_GEN)      { switchSub(SUB_GEN);      return 0; }
            if (id == ID_TAB_USER)     { switchSub(SUB_USER);     return 0; }
            if (id == ID_TAB_EMAIL)    { switchSub(SUB_EMAIL);    return 0; }
            if (id == ID_TAB_VAULT)    { switchSub(SUB_VAULT);    return 0; }
            if (id == ID_TAB_SETTINGS) { switchSub(SUB_SETTINGS); return 0; }
            if (id == ID_GEN_BTN)   { doGenerate(); return 0; }
        if (id == ID_GEN_MODE && code == CBN_SELCHANGE) {
            int m = (int)SendMessageW(hGenMode, CB_GETCURSEL, 0, 0);
            /* show char options only for Classic and Pronounceable */
            int showOpts = (m == 0 || m == 2);
            /* show pattern only for Pattern mode */
            int showPat  = (m == 3);
            /* show numbers checkbox label for passphrase (add digits) */
            ShowWindow(hGenLblOpts,   showOpts ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenChkUpper,  (m == 0) ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenChkLower,  (m == 0) ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenChkNumber, (m == 0 || m == 1) ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenChkSpec,   (m == 0 || m == 2) ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenRadLimit,  (m == 0 || m == 2 || m == 3) ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenRadFull,   (m == 0 || m == 2 || m == 3) ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenLblPattern, showPat ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenPattern,    showPat ? SW_SHOW : SW_HIDE);
            ShowWindow(hGenPatternHint,showPat ? SW_SHOW : SW_HIDE);
            return 0;
        }
            if (id == ID_GEN_COPY)  { doCopyGen(); return 0; }
            if (id == ID_GEN_SAVE)  { doSavePassword(); return 0; }
            if (id == ID_USER_GEN)  { doGenerateUsername(); return 0; }
            if (id == ID_USER_COPY) { doCopyUser(); return 0; }
            if (id == ID_USER_SAVE) { doSaveUser(); return 0; }
            if (id == ID_EMAIL_GEN) { doGenerateEmail(); return 0; }
            if (id == ID_EMAIL_COPY){ doCopyEmail(); return 0; }
            if (id == ID_EMAIL_SAVE){ doSaveEmail(); return 0; }
            if (id == ID_VAULT_LIST && code == LBN_SELCHANGE) { onVaultSelect(); return 0; }
            if (id == ID_VAULT_SHOW)    { doVaultShow(); return 0; }
            if (id == ID_VAULT_COPY_PWD){ doVaultCopyPwd(); return 0; }
            if (id == ID_VAULT_COPY_USR){ doVaultCopyUsr(); return 0; }
            if (id == ID_VAULT_DEL)     { doDeleteVaultEntry(); return 0; }
            if (id == ID_VAULT_EDIT)    { doVaultEdit(); return 0; }
            if (id == ID_VAULT_SEARCH && code == EN_CHANGE) {
                wchar_t f[128]; GetWindowTextW(hVaultSearch, f, 128);
                rebuildVaultList(f); return 0;
            }
            if (id == ID_SET_CHANGE_BTN) { doChangeMaster(); return 0; }
            if (id == ID_TEMP_GET)     { doTempGetNew();   return 0; }
            if (id == ID_TEMP_REFRESH) { doTempRefresh();  return 0; }
            if (id == ID_TEMP_COPY)    { doTempCopyAddr(); return 0; }
            if (id == ID_TEMP_DEL)     { doTempDel();      return 0; }
            if (id == ID_TEMP_LIST && code == LBN_SELCHANGE) { doTempSelect(); return 0; }
            if (id == ID_TAB_TEMP)     { switchSub(SUB_TEMP); return 0; }
            if (id == ID_TEMP_PROVIDER && code == CBN_SELCHANGE) {
                g_provider = (int)SendMessageW(hTempProvider, CB_GETCURSEL, 0, 0);
                if (g_provider < 0) g_provider = 0;
                /* clear current session */
                g_tempEmail[0] = 0; g_sidToken[0] = 0;
                g_mailtmToken[0] = 0; g_1secLogin[0] = 0; g_1secDomain[0] = 0;
                g_mailCount = 0;
                SetWindowTextW(hTempAddr, L"");
                rebuildTempList();
                populateDomainCombo();
                return 0;
            }
        }
        if ((g_state == STATE_LOGIN || g_state == STATE_LOCKED) && id == ID_SET_RESET_BTN) {
            doResetApp(); return 0;
        }
        break;
    }
    case WM_HSCROLL:
        if ((HWND)lp == hGenSlider) {
            int v = (int)SendMessageW(hGenSlider, TBM_GETPOS, 0, 0);
            wchar_t b[8]; swprintf(b, 8, L"%d", v);
            SetWindowTextW(hGenLenVal, b);
        }
        break;
    case WM_TIMER:
        if (wp == ID_TIMER_MSG && g_msgTimerActive) {
            SetWindowTextW(hRegMsg, L"");
            SetWindowTextW(hLogMsg, L"");
            SetWindowTextW(hGenMsg, L"");
            SetWindowTextW(hUserMsg, L"");
            SetWindowTextW(hEmailMsg, L"");
            SetWindowTextW(hVaultMsg, L"");
            SetWindowTextW(hSetMsg, L"");
            KillTimer(hwnd, ID_TIMER_MSG);
            g_msgTimerActive = 0;
        }
        if (wp == ID_TIMER_CLIP && g_clipTimerActive) {
            maybeClearClipboard();
            KillTimer(hwnd, ID_TIMER_CLIP);
            g_clipTimerActive = 0;
        }
        if (wp == ID_TIMER_REFRESH && g_tempRefreshActive && g_subState == SUB_TEMP) {
            doTempRefresh();
        }
        break;
    case WM_KEYDOWN:
    case WM_KEYUP:
        if (wp == VK_CAPITAL) updateCapsLockIndicators();
        break;
    case WM_ACTIVATE:
        updateCapsLockIndicators();
        break;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp; HWND ctrl = (HWND)lp;
        SetBkMode(hdc, TRANSPARENT);
        if (ctrl == hRegMsg || ctrl == hLogMsg || ctrl == hGenMsg ||
            ctrl == hUserMsg || ctrl == hEmailMsg || ctrl == hVaultMsg || ctrl == hSetMsg ||
            ctrl == hRegCapsLbl || ctrl == hLogCapsLbl) {
            COLORREF c = (COLORREF)GetWindowLongPtrW(ctrl, GWLP_USERDATA);
            if (ctrl == hRegCapsLbl || ctrl == hLogCapsLbl) c = clrWarn;
            if (c == 0) c = clrAccent;
            SetTextColor(hdc, c);
            return (LRESULT)CreateSolidBrush(clrBg);
        }
        if (ctrl == hRegLblSub || ctrl == hLogLblSub || ctrl == hVaultEmpty || ctrl == hRegStrengthLbl) {
            SetTextColor(hdc, clrMuted);
            return (LRESULT)CreateSolidBrush(clrBg);
        }
        SetTextColor(hdc, clrText);
        return (LRESULT)CreateSolidBrush(clrBg);
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, clrText);
        SetBkColor(hdc, clrInputBg);
        return (LRESULT)CreateSolidBrush(clrInputBg);
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, clrText);
        SetBkColor(hdc, clrCard);
        return (LRESULT)CreateSolidBrush(clrCard);
    }
    case WM_TEMP_RESULT:
        if (wp) {
            wchar_t addrW[128]; utf8ToWide(g_tempEmail, addrW, 128);
            SetWindowTextW(hTempAddr, addrW);
            rebuildTempList();
            setText(hTempMsg, L"");
            SetTimer(hMain, ID_TIMER_REFRESH, 30000, NULL); g_tempRefreshActive = 1;
        } else setText(hTempMsg, T(S_TEMP_ERROR));
        return 0;
    case WM_TEMP_INBOX:
        if (wp) { rebuildTempList(); setText(hTempMsg, L""); }
        else setText(hTempMsg, T(S_TEMP_ERROR));
        return 0;
    case WM_TEMP_BODY:
        if (wp && lp) {
            wchar_t bodyW[65536];
            utf8ToWide((const char*)lp, bodyW, 65536);
            SetWindowTextW(hTempBody, bodyW);
        } else setText(hTempBody, T(S_TEMP_ERROR));
        return 0;
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp; RECT rc; GetClientRect(hwnd, &rc);
        HBRUSH br = CreateSolidBrush(clrBg);
        FillRect(hdc, &rc, br); DeleteObject(br);
        return 1;
    }
    case WM_DESTROY:
        SecureZeroMemory(g_master, sizeof(g_master));
        freeVault();
        maybeClearClipboard();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ===== Build all controls ===== */
static void buildAllControls(void) {
    HINSTANCE hI = GetModuleHandle(NULL);

    /* Top bar */
    hMainTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_LEFT, 20, 14, 230, 22, hMain, NULL, hI, NULL); setFont(hMainTitle, fBold);
    hLogoutBtn = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, 320, 12, 70, 26, hMain, (HMENU)(LONG_PTR)ID_LOGOUT_BTN, hI, NULL); setFont(hLogoutBtn, fSmall);
    hLangBtn   = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, 400, 12, 60, 26, hMain, (HMENU)(LONG_PTR)ID_LANG_BTN, hI, NULL); setFont(hLangBtn, fSmall);

    /* 5 tabs */
    int tabW = 70, tabX = 20, gap = 3;
    hTabGenBtn   = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, tabX,                50, tabW, 28, hMain, (HMENU)(LONG_PTR)ID_TAB_GEN, hI, NULL);
    hTabUserBtn  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, tabX+(tabW+gap)*1,   50, tabW, 28, hMain, (HMENU)(LONG_PTR)ID_TAB_USER, hI, NULL);
    hTabEmailBtn = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, tabX+(tabW+gap)*2,   50, tabW, 28, hMain, (HMENU)(LONG_PTR)ID_TAB_EMAIL, hI, NULL);
    hTabVaultBtn = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, tabX+(tabW+gap)*3,   50, tabW, 28, hMain, (HMENU)(LONG_PTR)ID_TAB_VAULT, hI, NULL);
    hTabSetBtn   = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, tabX+(tabW+gap)*4,   50, tabW, 28, hMain, (HMENU)(LONG_PTR)ID_TAB_SETTINGS, hI, NULL);
    hTabTempBtn  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON, tabX+(tabW+gap)*5,   50, tabW, 28, hMain, (HMENU)(LONG_PTR)ID_TAB_TEMP, hI, NULL);
    setFont(hTabGenBtn, fUI); setFont(hTabUserBtn, fUI); setFont(hTabEmailBtn, fUI);
    setFont(hTabVaultBtn, fUI); setFont(hTabSetBtn, fUI); setFont(hTabTempBtn, fUI);

    /* Register */
    hRegLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 50, 440, 26, hMain, NULL, hI, NULL); setFont(hRegLblTitle, fTitle);
    hRegLblSub   = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 82, 440, 36, hMain, NULL, hI, NULL); setFont(hRegLblSub, fSmall);
    hRegLblUser  = CreateWindowW(L"STATIC", L"", WS_CHILD, 60, 130, 360, 16, hMain, NULL, hI, NULL); setFont(hRegLblUser, fUI);
    hRegUser     = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 60, 150, 360, 28, hMain, NULL, hI, NULL); setFont(hRegUser, fUI);
    hRegLblPwd   = CreateWindowW(L"STATIC", L"", WS_CHILD, 60, 190, 360, 16, hMain, NULL, hI, NULL); setFont(hRegLblPwd, fUI);
    hRegPwd      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 60, 210, 320, 28, hMain, NULL, hI, NULL); setFont(hRegPwd, fUI);
    togglePasswordChar(hRegPwd, 0);
    hRegShowPwd  = CreateWindowW(L"BUTTON", L"👁", WS_CHILD | BS_PUSHBUTTON, 386, 210, 34, 28, hMain, (HMENU)(LONG_PTR)ID_REG_SHOW_PWD, hI, NULL); setFont(hRegShowPwd, fEmoji);
    hRegStrengthBar = CreateWindowW(L"BarClass", L"", WS_CHILD, 60, 244, 280, 4, hMain, NULL, hI, NULL);
    hRegStrengthLbl = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_RIGHT, 350, 240, 70, 16, hMain, NULL, hI, NULL); setFont(hRegStrengthLbl, fSmall);
    hRegLblConf  = CreateWindowW(L"STATIC", L"", WS_CHILD, 60, 258, 360, 16, hMain, NULL, hI, NULL); setFont(hRegLblConf, fUI);
    hRegConfirm  = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 60, 278, 320, 28, hMain, NULL, hI, NULL); setFont(hRegConfirm, fUI);
    togglePasswordChar(hRegConfirm, 0);
    hRegShowConf = CreateWindowW(L"BUTTON", L"👁", WS_CHILD | BS_PUSHBUTTON, 386, 278, 34, 28, hMain, (HMENU)(LONG_PTR)ID_REG_SHOW_CONF, hI, NULL); setFont(hRegShowConf, fEmoji);
    hRegBtn      = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 60, 320, 360, 36, hMain, (HMENU)(LONG_PTR)ID_REG_BTN, hI, NULL); setFont(hRegBtn, fBold);
    hRegCapsLbl  = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 365, 440, 18, hMain, NULL, hI, NULL); setFont(hRegCapsLbl, fSmall);
    hRegMsg      = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 385, 440, 20, hMain, NULL, hI, NULL); setFont(hRegMsg, fSmall);
    hRegGuestBtn = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 60, 480, 360, 28, hMain, (HMENU)(LONG_PTR)ID_REG_GUEST_BTN, hI, NULL); setFont(hRegGuestBtn, fSmall);

    /* Login */
    hLogLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 60, 440, 26, hMain, NULL, hI, NULL); setFont(hLogLblTitle, fTitle);
    hLogLblSub   = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 92, 440, 36, hMain, NULL, hI, NULL); setFont(hLogLblSub, fSmall);
    hLogLblPwd   = CreateWindowW(L"STATIC", L"", WS_CHILD, 60, 160, 360, 16, hMain, NULL, hI, NULL); setFont(hLogLblPwd, fUI);
    hLogPwd      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 60, 180, 320, 28, hMain, NULL, hI, NULL); setFont(hLogPwd, fUI);
    togglePasswordChar(hLogPwd, 0);
    hLogShowPwd  = CreateWindowW(L"BUTTON", L"👁", WS_CHILD | BS_PUSHBUTTON, 386, 180, 34, 28, hMain, (HMENU)(LONG_PTR)ID_LOG_SHOW_PWD, hI, NULL); setFont(hLogShowPwd, fEmoji);
    hLogBtn      = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 60, 230, 360, 36, hMain, (HMENU)(LONG_PTR)ID_LOGIN_BTN, hI, NULL); setFont(hLogBtn, fBold);
    hLogCapsLbl  = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 275, 440, 18, hMain, NULL, hI, NULL); setFont(hLogCapsLbl, fSmall);
    hLogMsg      = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, 295, 440, 20, hMain, NULL, hI, NULL); setFont(hLogMsg, fSmall);
    hLogGuestBtn = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 60, 440, 360, 28, hMain, (HMENU)(LONG_PTR)ID_LOG_GUEST_BTN, hI, NULL); setFont(hLogGuestBtn, fSmall);
    hLogResetBtn = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 60, 480, 360, 28, hMain, (HMENU)(LONG_PTR)ID_SET_RESET_BTN, hI, NULL); setFont(hLogResetBtn, fSmall);

    /* Password generator */
    int y = 90;
    hGenLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y, 440, 22, hMain, NULL, hI, NULL); setFont(hGenLblTitle, fBold); y += 28;
    hGenLblUser  = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y, 440, 16, hMain, NULL, hI, NULL); setFont(hGenLblUser, fSmall); y += 18;
    hGenUser     = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 20, y, 440, 26, hMain, NULL, hI, NULL); setFont(hGenUser, fUI); y += 32;
    /* Mode selector */
    hGenLblMode  = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y+4, 60, 18, hMain, NULL, hI, NULL); setFont(hGenLblMode, fSmall);
    hGenMode     = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_TABSTOP, 85, y, 200, 200, hMain, (HMENU)(LONG_PTR)ID_GEN_MODE, hI, NULL); setFont(hGenMode, fUI);
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)L"Classic");
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)L"Passphrase");
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)L"Pronounceable");
    SendMessageW(hGenMode, CB_ADDSTRING, 0, (LPARAM)L"Pattern");
    SendMessageW(hGenMode, CB_SETCURSEL, 0, 0); y += 32;
    /* Slider */
    hGenLblLen   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y, 200, 16, hMain, NULL, hI, NULL); setFont(hGenLblLen, fSmall);
    hGenLenVal   = CreateWindowW(L"STATIC", L"16", WS_CHILD | SS_RIGHT, 420, y, 40, 16, hMain, NULL, hI, NULL); setFont(hGenLenVal, fBold); y += 18;
    hGenSlider   = CreateWindowW(TRACKBAR_CLASSW, L"", WS_CHILD | TBS_HORZ | TBS_NOTICKS | WS_TABSTOP, 20, y, 440, 28, hMain, (HMENU)(LONG_PTR)ID_GEN_SLIDER, hI, NULL);
    SendMessageW(hGenSlider, TBM_SETRANGE, TRUE, MAKELONG(8, 2048));
    SendMessageW(hGenSlider, TBM_SETPOS, TRUE, 16); y += 32;
    /* Char options */
    hGenLblOpts  = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y, 440, 16, hMain, NULL, hI, NULL); setFont(hGenLblOpts, fSmall); y += 18;
    hGenChkUpper = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 30, y, 215, 22, hMain, (HMENU)(LONG_PTR)ID_GEN_CHK_UPPER, hI, NULL); setFont(hGenChkUpper, fUI); SendMessageW(hGenChkUpper, BM_SETCHECK, BST_CHECKED, 0);
    hGenChkLower = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 245, y, 215, 22, hMain, (HMENU)(LONG_PTR)ID_GEN_CHK_LOWER, hI, NULL); setFont(hGenChkLower, fUI); SendMessageW(hGenChkLower, BM_SETCHECK, BST_CHECKED, 0); y += 22;
    hGenChkNumber= CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 30, y, 215, 22, hMain, (HMENU)(LONG_PTR)ID_GEN_CHK_NUMBER, hI, NULL); setFont(hGenChkNumber, fUI); SendMessageW(hGenChkNumber, BM_SETCHECK, BST_CHECKED, 0);
    hGenChkSpec  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 245, y, 215, 22, hMain, (HMENU)(LONG_PTR)ID_GEN_CHK_SPEC, hI, NULL); setFont(hGenChkSpec, fUI); SendMessageW(hGenChkSpec, BM_SETCHECK, BST_CHECKED, 0); y += 26;
    hGenRadLimit = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 50, y, 200, 20, hMain, (HMENU)(LONG_PTR)ID_GEN_RAD_LIMIT, hI, NULL); setFont(hGenRadLimit, fSmall); SendMessageW(hGenRadLimit, BM_SETCHECK, BST_CHECKED, 0);
    hGenRadFull  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTORADIOBUTTON, 260, y, 200, 20, hMain, (HMENU)(LONG_PTR)ID_GEN_RAD_FULL, hI, NULL); setFont(hGenRadFull, fSmall); y += 24;
    /* Pattern controls (hidden by default) */
    hGenLblPattern  = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y, 440, 16, hMain, NULL, hI, NULL); setFont(hGenLblPattern, fSmall); y += 16;
    hGenPattern     = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Aa99!!Aa99!!", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 20, y, 440, 26, hMain, (HMENU)(LONG_PTR)ID_GEN_PATTERN, hI, NULL); setFont(hGenPattern, fMono); y += 28;
    hGenPatternHint = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, y, 440, 14, hMain, NULL, hI, NULL); setFont(hGenPatternHint, fSmall); y += 18;
    ShowWindow(hGenLblPattern,   SW_HIDE);
    ShowWindow(hGenPattern,      SW_HIDE);
    ShowWindow(hGenPatternHint,  SW_HIDE);
    /* Output */
    hGenLblOut   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, y, 440, 16, hMain, NULL, hI, NULL); setFont(hGenLblOut, fSmall); y += 18;
    hGenOut      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 20, y, 245, 30, hMain, NULL, hI, NULL); setFont(hGenOut, fMono); togglePasswordChar(hGenOut, 0);
    hGenShow     = CreateWindowW(L"BUTTON", L"👁", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 270, y, 30, 30, hMain, (HMENU)(LONG_PTR)ID_GEN_SHOW, hI, NULL); setFont(hGenShow, fEmoji);
    hGenCopy     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 305, y, 75, 30, hMain, (HMENU)(LONG_PTR)ID_GEN_COPY, hI, NULL); setFont(hGenCopy, fUI);
    hGenSave     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 385, y, 75, 30, hMain, (HMENU)(LONG_PTR)ID_GEN_SAVE, hI, NULL); setFont(hGenSave, fUI); y += 36;
    hGenBar      = CreateWindowW(L"BarClass", L"", WS_CHILD, 20, y, 440, 6, hMain, NULL, hI, NULL); y += 12;
    for (int i = 0; i < 6; i++) {
        int col = i % 2; int row = i / 2;
        hGenChk[i] = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_DISABLED, 30 + col * 215, y + row * 20, 215, 18, hMain, NULL, hI, NULL);
        setFont(hGenChk[i], fSmall);
    }
    y += 64;
    hGenGen = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 20, y, 440, 32, hMain, (HMENU)(LONG_PTR)ID_GEN_BTN, hI, NULL); setFont(hGenGen, fBold); y += 36;
    hGenMsg = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, y, 440, 18, hMain, NULL, hI, NULL); setFont(hGenMsg, fSmall);

    /* Username */
    int uy = 90;
    hUserLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, uy, 440, 22, hMain, NULL, hI, NULL); setFont(hUserLblTitle, fBold); uy += 30;
    hUserLblTheme = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, uy, 100, 18, hMain, NULL, hI, NULL); setFont(hUserLblTheme, fUI);
    hUserTheme    = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 130, uy - 2, 200, 200, hMain, (HMENU)(LONG_PTR)ID_USER_THEME, hI, NULL); setFont(hUserTheme, fUI); uy += 32;
    hUserLblStyle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, uy, 100, 18, hMain, NULL, hI, NULL); setFont(hUserLblStyle, fUI);
    hUserStyle    = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 130, uy - 2, 200, 200, hMain, (HMENU)(LONG_PTR)ID_USER_STYLE, hI, NULL); setFont(hUserStyle, fUI); uy += 32;
    hUserChkNum   = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 20, uy, 220, 22, hMain, (HMENU)(LONG_PTR)ID_USER_NUM, hI, NULL); setFont(hUserChkNum, fUI); SendMessageW(hUserChkNum, BM_SETCHECK, BST_CHECKED, 0);
    hUserChkBase  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 250, uy, 220, 22, hMain, (HMENU)(LONG_PTR)ID_USER_BASE, hI, NULL); setFont(hUserChkBase, fUI); uy += 32;
    hUserLblOut   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, uy, 440, 16, hMain, NULL, hI, NULL); setFont(hUserLblOut, fSmall); uy += 18;
    hUserOut      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 20, uy, 280, 30, hMain, NULL, hI, NULL); setFont(hUserOut, fMono);
    hUserCopy     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 305, uy, 75, 30, hMain, (HMENU)(LONG_PTR)ID_USER_COPY, hI, NULL); setFont(hUserCopy, fUI);
    hUserSave     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 385, uy, 75, 30, hMain, (HMENU)(LONG_PTR)ID_USER_SAVE, hI, NULL); setFont(hUserSave, fUI); uy += 40;
    hUserGen      = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 20, uy, 440, 36, hMain, (HMENU)(LONG_PTR)ID_USER_GEN, hI, NULL); setFont(hUserGen, fBold); uy += 42;
    hUserMsg      = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, uy, 440, 18, hMain, NULL, hI, NULL); setFont(hUserMsg, fSmall);

    /* Email */
    int ey = 90;
    hEmailLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ey, 440, 22, hMain, NULL, hI, NULL); setFont(hEmailLblTitle, fBold); ey += 30;
    hEmailLblTheme = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ey, 100, 18, hMain, NULL, hI, NULL); setFont(hEmailLblTheme, fUI);
    hEmailTheme    = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 130, ey - 2, 200, 200, hMain, (HMENU)(LONG_PTR)ID_EMAIL_THEME, hI, NULL); setFont(hEmailTheme, fUI); ey += 32;
    hEmailLblStyle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ey, 100, 18, hMain, NULL, hI, NULL); setFont(hEmailLblStyle, fUI);
    hEmailStyle    = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 130, ey - 2, 200, 200, hMain, (HMENU)(LONG_PTR)ID_EMAIL_STYLE, hI, NULL); setFont(hEmailStyle, fUI); ey += 32;
    hEmailLblDomain= CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ey, 100, 18, hMain, NULL, hI, NULL); setFont(hEmailLblDomain, fUI);
    hEmailDomain   = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 130, ey - 2, 200, 200, hMain, (HMENU)(LONG_PTR)ID_EMAIL_DOMAIN, hI, NULL); setFont(hEmailDomain, fUI);
    for (size_t i = 0; i < ARRSZ(EMAIL_DOMAINS); i++) {
        wchar_t dW[32]; utf8ToWide(EMAIL_DOMAINS[i], dW, 32);
        SendMessageW(hEmailDomain, CB_ADDSTRING, 0, (LPARAM)dW);
    }
    SendMessageW(hEmailDomain, CB_SETCURSEL, 0, 0); ey += 32;
    hEmailChkNum   = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 20, ey, 220, 22, hMain, (HMENU)(LONG_PTR)ID_EMAIL_NUM, hI, NULL); setFont(hEmailChkNum, fUI); SendMessageW(hEmailChkNum, BM_SETCHECK, BST_CHECKED, 0);
    hEmailChkBase  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 250, ey, 220, 22, hMain, (HMENU)(LONG_PTR)ID_EMAIL_BASE, hI, NULL); setFont(hEmailChkBase, fUI); ey += 32;
    hEmailLblOut   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ey, 440, 16, hMain, NULL, hI, NULL); setFont(hEmailLblOut, fSmall); ey += 18;
    hEmailOut      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 20, ey, 280, 30, hMain, NULL, hI, NULL); setFont(hEmailOut, fMono);
    hEmailCopy     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 305, ey, 75, 30, hMain, (HMENU)(LONG_PTR)ID_EMAIL_COPY, hI, NULL); setFont(hEmailCopy, fUI);
    hEmailSave     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 385, ey, 75, 30, hMain, (HMENU)(LONG_PTR)ID_EMAIL_SAVE, hI, NULL); setFont(hEmailSave, fUI); ey += 40;
    hEmailGen      = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 20, ey, 440, 36, hMain, (HMENU)(LONG_PTR)ID_EMAIL_GEN, hI, NULL); setFont(hEmailGen, fBold); ey += 42;
    hEmailMsg      = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, ey, 440, 18, hMain, NULL, hI, NULL); setFont(hEmailMsg, fSmall);

    /* Vault */
    int vy = 90;
    hVaultLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, vy, 440, 22, hMain, NULL, hI, NULL); setFont(hVaultLblTitle, fBold); vy += 30;
    hVaultLblSearch= CreateWindowW(L"STATIC", L"", WS_CHILD, 20, vy + 6, 60, 16, hMain, NULL, hI, NULL); setFont(hVaultLblSearch, fSmall);
    hVaultSearch   = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 80, vy, 380, 24, hMain, (HMENU)(LONG_PTR)ID_VAULT_SEARCH, hI, NULL); setFont(hVaultSearch, fUI); vy += 30;
    hVaultList     = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | LBS_NOTIFY | WS_VSCROLL | WS_TABSTOP, 20, vy, 440, 140, hMain, (HMENU)(LONG_PTR)ID_VAULT_LIST, hI, NULL); setFont(hVaultList, fUI);
    hVaultEmpty    = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 30, vy + 50, 420, 40, hMain, NULL, hI, NULL); setFont(hVaultEmpty, fSmall); vy += 150;
    hVaultLblUsr   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, vy, 440, 16, hMain, NULL, hI, NULL); setFont(hVaultLblUsr, fSmall); vy += 18;
    hVaultUsr      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 20, vy, 440, 26, hMain, NULL, hI, NULL); setFont(hVaultUsr, fMono); vy += 32;
    hVaultLblPwd   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, vy, 440, 16, hMain, NULL, hI, NULL); setFont(hVaultLblPwd, fSmall); vy += 18;
    hVaultPwd      = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 20, vy, 440, 26, hMain, NULL, hI, NULL); setFont(hVaultPwd, fMono); togglePasswordChar(hVaultPwd, 0); vy += 32;
    hVaultShow     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 20, vy, 80, 30, hMain, (HMENU)(LONG_PTR)ID_VAULT_SHOW, hI, NULL); setFont(hVaultShow, fUI);
    hVaultCopyPwd  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 105, vy, 100, 30, hMain, (HMENU)(LONG_PTR)ID_VAULT_COPY_PWD, hI, NULL); setFont(hVaultCopyPwd, fUI);
    hVaultCopyUsr  = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 210, vy, 100, 30, hMain, (HMENU)(LONG_PTR)ID_VAULT_COPY_USR, hI, NULL); setFont(hVaultCopyUsr, fUI);
    hVaultEdit     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 315, vy, 65, 30, hMain, (HMENU)(LONG_PTR)ID_VAULT_EDIT, hI, NULL); setFont(hVaultEdit, fUI);
    hVaultDel      = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 385, vy, 75, 30, hMain, (HMENU)(LONG_PTR)ID_VAULT_DEL, hI, NULL); setFont(hVaultDel, fUI); vy += 38;
    hVaultMsg      = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, vy, 440, 18, hMain, NULL, hI, NULL); setFont(hVaultMsg, fSmall);

    /* Settings */
    int sy = 90;
    hSetLblTitle = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, sy, 440, 22, hMain, NULL, hI, NULL); setFont(hSetLblTitle, fBold); sy += 36;
    hSetLblChange= CreateWindowW(L"STATIC", L"", WS_CHILD, 20, sy, 440, 18, hMain, NULL, hI, NULL); setFont(hSetLblChange, fUI); sy += 26;
    hSetLblCur   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, sy, 200, 16, hMain, NULL, hI, NULL); setFont(hSetLblCur, fSmall); sy += 18;
    hSetCurPwd   = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 20, sy, 440, 26, hMain, NULL, hI, NULL); setFont(hSetCurPwd, fUI); togglePasswordChar(hSetCurPwd, 0); sy += 34;
    hSetLblNew   = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, sy, 200, 16, hMain, NULL, hI, NULL); setFont(hSetLblNew, fSmall); sy += 18;
    hSetNewPwd   = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 20, sy, 440, 26, hMain, NULL, hI, NULL); setFont(hSetNewPwd, fUI); togglePasswordChar(hSetNewPwd, 0); sy += 34;
    hSetLblConf  = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, sy, 200, 16, hMain, NULL, hI, NULL); setFont(hSetLblConf, fSmall); sy += 18;
    hSetNewConf  = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, 20, sy, 440, 26, hMain, NULL, hI, NULL); setFont(hSetNewConf, fUI); togglePasswordChar(hSetNewConf, 0); sy += 34;
    hSetChangeBtn= CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 20, sy, 440, 36, hMain, (HMENU)(LONG_PTR)ID_SET_CHANGE_BTN, hI, NULL); setFont(hSetChangeBtn, fBold); sy += 42;
    hSetMsg      = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, sy, 440, 18, hMain, NULL, hI, NULL); setFont(hSetMsg, fSmall);

    /* Temp mail */
    int ty = 90;
    hTempLblTitle= CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ty, 440, 22, hMain, NULL, hI, NULL); setFont(hTempLblTitle, fBold); ty += 28;
    /* Provider row */
    hTempLblProvider = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ty+4, 70, 18, hMain, NULL, hI, NULL); setFont(hTempLblProvider, fSmall);
    hTempProvider= CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_TABSTOP, 95, ty, 170, 120, hMain, (HMENU)(LONG_PTR)ID_TEMP_PROVIDER, hI, NULL); setFont(hTempProvider, fUI);
    SendMessageW(hTempProvider, CB_ADDSTRING, 0, (LPARAM)L"Guerrilla Mail");
    SendMessageW(hTempProvider, CB_ADDSTRING, 0, (LPARAM)L"1SecMail");
    SendMessageW(hTempProvider, CB_ADDSTRING, 0, (LPARAM)L"Mail.tm");
    SendMessageW(hTempProvider, CB_SETCURSEL, 0, 0); ty += 30;
    /* Domain row */
    hTempLblDomain = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ty+4, 70, 18, hMain, NULL, hI, NULL); setFont(hTempLblDomain, fSmall);
    hTempDomain  = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 95, ty, 345, 300, hMain, NULL, hI, NULL); setFont(hTempDomain, fUI);
    /* populate Guerrilla domains initially */
    for (size_t i = 0; i < ARRSZ(GUERRILLA_DOMAINS); i++) {
        wchar_t dW[64]; utf8ToWide(GUERRILLA_DOMAINS[i], dW, 64);
        SendMessageW(hTempDomain, CB_ADDSTRING, 0, (LPARAM)dW);
    }
    SendMessageW(hTempDomain, CB_SETCURSEL, 0, 0); ty += 30;
    hTempLblAddr = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ty, 440, 16, hMain, NULL, hI, NULL); setFont(hTempLblAddr, fSmall); ty += 18;
    hTempAddr    = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 20, ty, 440, 28, hMain, NULL, hI, NULL); setFont(hTempAddr, fMono); ty += 34;
    hTempGet     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 20, ty, 210, 28, hMain, (HMENU)(LONG_PTR)ID_TEMP_GET, hI, NULL); setFont(hTempGet, fUI);
    hTempCopyAddr= CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 235, ty, 225, 28, hMain, (HMENU)(LONG_PTR)ID_TEMP_COPY, hI, NULL); setFont(hTempCopyAddr, fUI); ty += 34;
    hTempAuto    = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 20, ty, 440, 14, hMain, NULL, hI, NULL); setFont(hTempAuto, fSmall); ty += 18;
    hTempLblInbox= CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ty, 300, 18, hMain, NULL, hI, NULL); setFont(hTempLblInbox, fBold);
    hTempRefresh = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 360, ty-2, 100, 24, hMain, (HMENU)(LONG_PTR)ID_TEMP_REFRESH, hI, NULL); setFont(hTempRefresh, fSmall); ty += 24;
    hTempList    = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | LBS_NOTIFY | WS_VSCROLL | WS_TABSTOP, 20, ty, 440, 80, hMain, (HMENU)(LONG_PTR)ID_TEMP_LIST, hI, NULL); setFont(hTempList, fSmall);
    hTempEmpty   = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 30, ty + 25, 420, 30, hMain, NULL, hI, NULL); setFont(hTempEmpty, fSmall); ty += 88;
    hTempLblFrom = CreateWindowW(L"STATIC", L"", WS_CHILD, 20, ty, 50, 14, hMain, NULL, hI, NULL); setFont(hTempLblFrom, fSmall);
    hTempFrom    = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 75, ty-2, 385, 20, hMain, NULL, hI, NULL); setFont(hTempFrom, fSmall); ty += 24;
    hTempLblSubj = CreateWindowW(L"STATIC", L"Assunto:", WS_CHILD, 20, ty, 50, 14, hMain, NULL, hI, NULL); setFont(hTempLblSubj, fSmall);
    hTempSubj    = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_AUTOHSCROLL, 75, ty-2, 385, 20, hMain, NULL, hI, NULL); setFont(hTempSubj, fSmall); ty += 24;
    hTempBody    = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_READONLY | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL, 20, ty, 440, 130, hMain, NULL, hI, NULL); setFont(hTempBody, fSmall); ty += 136;
    hTempDel     = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 20, ty, 100, 26, hMain, (HMENU)(LONG_PTR)ID_TEMP_DEL, hI, NULL); setFont(hTempDel, fSmall);
    hTempMsg     = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER, 130, ty+4, 330, 18, hMain, NULL, hI, NULL); setFont(hTempMsg, fSmall);
}

/* ===== WinMain ===== */
int WINAPI wWinMain(HINSTANCE hI, HINSTANCE hP, LPWSTR cmd, int nShow) {
    (void)hP; (void)cmd;
    srand((unsigned)time(NULL) ^ (unsigned)GetTickCount());

    /* Default language by Windows locale */
    wchar_t loc[64] = L"";
    if (GetUserDefaultLocaleName(loc, 64) > 0) {
        if (loc[0] == L'p' && loc[1] == L't') g_lang = 0;
        else g_lang = 1;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    initPaths();

    fUI    = CreateFontW(16, 0, 0, 0, FW_NORMAL,   0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    fBold  = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    fTitle = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    fMono  = CreateFontW(16, 0, 0, 0, FW_BOLD,     0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Consolas");
    fSmall = CreateFontW(13, 0, 0, 0, FW_NORMAL,   0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    fEmoji = CreateFontW(14, 0, 0, 0, FW_NORMAL,   0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI Symbol");

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hI;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(clrBg);
    wc.lpszClassName = L"GeradorSenhaMain";
    wc.hIcon = LoadIconW(hI, MAKEINTRESOURCEW(1));
    wc.hIconSm = LoadIconW(hI, MAKEINTRESOURCEW(1));
    RegisterClassExW(&wc);

    WNDCLASSEXW wb = {0};
    wb.cbSize = sizeof(wb);
    wb.lpfnWndProc = BarProc;
    wb.hInstance = hI;
    wb.hbrBackground = CreateSolidBrush(clrBorder);
    wb.lpszClassName = L"BarClass";
    RegisterClassExW(&wb);

    hMain = CreateWindowExW(0, L"GeradorSenhaMain", L"Gerador de Senha",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 496, 740,
        NULL, NULL, hI, NULL);

    /* Block screen capture (passwords won't appear in screenshots/recordings) */
    SetWindowDisplayAffinity(hMain, WDA_EXCLUDEFROMCAPTURE);

    buildAllControls();

    /* Welcome message */
    MessageBoxW(hMain,
        L"Obrigado por testar este app!\n\n"
        L"Criado por Alessandro Dantas\n\n"
        L"Gerador de Senha v2 — Gerenciador de senhas seguro com:\n"
        L"  • Gerador clássico, passphrase, pronunciável e padrão\n"
        L"  • Cofre criptografado com PBKDF2\n"
        L"  • Email temporário real (Guerrilla Mail, 1SecMail, Mail.tm)\n"
        L"  • Modo visitante (sem dados salvos)\n\n"
        L"Bom uso!",
        L"Bem-vindo / Welcome",
        MB_OK | MB_ICONINFORMATION);

    if (hasConfigFile()) loadUsernameOnly();

    int initial = hasConfigFile() ? STATE_LOGIN : STATE_REGISTER;
    switchState(initial);

    ShowWindow(hMain, nShow);
    UpdateWindow(hMain);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(hMain, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
