use chrono::{DateTime, Local};
use goblin::elf::Elf;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

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

#[derive(Debug, Clone)]
pub struct InstrucaoSuspeita {
    pub endereco: u64,
    pub mnemonico: String,
    pub operandos: String,
    pub motivo: String,
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone)]
pub struct ResultadoAnalise {
    pub caminho: std::path::PathBuf,
    pub timestamp: DateTime<Local>,
    pub entropia: f64,
    pub tem_permissao_exec: bool,
    pub veio_da_internet: bool,
    pub iocs: Vec<String>,
    pub instrucoes_suspeitas: Vec<InstrucaoSuspeita>,
    pub eh_elf: bool,
    pub nivel_ameaca: NivelAmeaca,
    pub pontuacao: f64,
    /// true quando o arquivo é um container comprimido (ZIP/APK/JAR/GZip…);
    /// a entropia alta é esperada nesses formatos e não conta como indicador.
    pub formato_comprimido: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Ponto de entrada da análise
// ─────────────────────────────────────────────────────────────────────────────

pub fn analisar_arquivo(caminho: &Path) -> Result<ResultadoAnalise, Box<dyn std::error::Error>> {
    let dados = std::fs::read(caminho)?;
    let timestamp = Local::now();

    let entropia = calcular_entropia(&dados);
    let formato_comprimido = eh_formato_comprimido(&dados);
    let tem_permissao_exec = verificar_permissao_exec(caminho);
    let veio_da_internet = verificar_origem_internet(caminho);
    let iocs = varrer_iocs(&dados);

    let eh_elf = dados.len() >= 4 && dados[..4] == *b"\x7fELF";
    let instrucoes_suspeitas = if eh_elf {
        analisar_elf(&dados).unwrap_or_default()
    } else {
        vec![]
    };

    let (pontuacao, nivel_ameaca) = calcular_nivel_ameaca(
        entropia,
        &iocs,
        &instrucoes_suspeitas,
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
        eh_elf,
        nivel_ameaca,
        pontuacao,
        formato_comprimido,
    })
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
// Varredura de IoCs (IPv4 externos)
// ─────────────────────────────────────────────────────────────────────────────

fn varrer_iocs(dados: &[u8]) -> Vec<String> {
    let texto = String::from_utf8_lossy(dados);
    let texto_bytes = texto.as_bytes();
    let re = regex_ipv4();
    let mut iocs: Vec<String> = Vec::new();

    for m in re.find_iter(&texto) {
        let ip = m.as_str().to_string();

        if ip_privado(&ip) {
            continue;
        }

        // Filtro de contexto: se precedido por [-@a-zA-Z_] ou seguido por [-a-zA-Z_]
        // o match é parte de uma string de versão (ex: "pkg-1.24.0.38-linux"), não um IP real.
        let byte_antes = m.start().checked_sub(1).and_then(|i| texto_bytes.get(i).copied());
        let byte_depois = texto_bytes.get(m.end()).copied();

        let contexto_versao =
            // Precedido por letra/símbolo de versão → "pkg-1.2.3.4" ou "v1.2.3.4"
            matches!(byte_antes, Some(b) if b.is_ascii_alphabetic() || b == b'-' || b == b'@' || b == b'_')
            // Seguido por letra/símbolo de versão → "1.2.3.4-linux"
            || matches!(byte_depois, Some(b) if b.is_ascii_alphabetic() || b == b'-' || b == b'_')
            // Seguido por dígito → o último octeto é maior que 255 (ex: "1.24.0.388")
            || matches!(byte_depois, Some(b) if b.is_ascii_digit());

        if !contexto_versao {
            iocs.push(ip);
        }
    }

    iocs.sort();
    iocs.dedup();
    iocs
}

fn ip_privado(ip: &str) -> bool {
    ip == "0.0.0.0"
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Análise ELF: disassembly + heurísticas
// ─────────────────────────────────────────────────────────────────────────────

fn analisar_elf(dados: &[u8]) -> Result<Vec<InstrucaoSuspeita>, Box<dyn std::error::Error>> {
    let elf = Elf::parse(dados)?;
    let (base_addr, secao_text) = extrair_secao_text(dados, &elf)?;
    Ok(analisar_instrucoes(base_addr, secao_text))
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

fn analisar_instrucoes(endereco_base: u64, bytes_texto: &[u8]) -> Vec<InstrucaoSuspeita> {
    let mut decodificador =
        Decoder::with_ip(64, bytes_texto, endereco_base, DecoderOptions::NONE);
    let mut formatador = NasmFormatter::new();
    let mut instrucao = Instruction::default();
    let mut suspeitas: Vec<InstrucaoSuspeita> = Vec::new();
    let mut buffer = String::new();

    while decodificador.can_decode() {
        decodificador.decode_out(&mut instrucao);

        // Heurística 1: SYSCALL direta — padrão de shellcode / bypass libc
        if instrucao.mnemonic() == Mnemonic::Syscall {
            suspeitas.push(InstrucaoSuspeita {
                endereco: instrucao.ip(),
                mnemonico: "syscall".into(),
                operandos: String::new(),
                motivo: "Syscall direta ao kernel — padrão de shellcode/bypass libc".into(),
            });
        }

        // Heurística 2: XOR reg, reg — zeragem de registrador (evasão EDR)
        if instrucao.mnemonic() == Mnemonic::Xor && instrucao.op_count() == 2 {
            let op0 = instrucao.op0_register();
            let op1 = instrucao.op1_register();
            if op0 == op1 && op0 != iced_x86::Register::None && eh_registrador_64bits(op0) {
                buffer.clear();
                formatador.format(&instrucao, &mut buffer);
                let operandos = buffer
                    .splitn(2, ' ')
                    .nth(1)
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
    }

    suspeitas
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

fn calcular_nivel_ameaca(
    entropia: f64,
    iocs: &[String],
    instrucoes_suspeitas: &[InstrucaoSuspeita],
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

    // IoCs externos detectados no binário
    pontos += iocs.len() as f64 * 2.0;

    // Padrões heurísticos ELF
    for inst in instrucoes_suspeitas {
        if inst.mnemonico == "syscall" {
            pontos += 1.0;
        } else {
            // xor reg,reg: falso positivo mais comum, peso menor
            pontos += 0.5;
        }
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
