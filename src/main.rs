//! # Obscura
//!
//! Analisador estático heurístico para binários ELF x86_64.
//! Detecta padrões de shellcode e técnicas de evasão de EDR
//! através do disassembly da seção `.text`.

use std::env;
use std::fs;
use std::process;

use goblin::elf::Elf;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter};
use regex::Regex;

// --------------------------------------------------------------------------
// Estrutura que representa uma instrução suspeita identificada na análise.
// --------------------------------------------------------------------------
struct InstrucaoSuspeita {
    /// Endereço virtual da instrução no binário.
    endereco: u64,
    /// Mnemônico da instrução (ex: SYSCALL, XOR).
    mnemonico: String,
    /// Operandos formatados como texto (ex: "rax, rax").
    operandos: String,
    /// Descrição da heurística que disparou o alerta.
    motivo: String,
}

// --------------------------------------------------------------------------
// Ponto de entrada principal.
// Fluxo: validar args → ler binário → extrair IoCs → parsear ELF → localizar .text
//        → disassembly → varredura heurística → veredito.
// --------------------------------------------------------------------------
fn main() {
    if let Err(erro) = executar() {
        eprintln!("[ERRO FATAL] {}", erro);
        process::exit(1);
    }
}

/// Função principal de execução que encapsula toda a lógica e propaga erros
/// via `Result`. Nenhum `unwrap()` desprotegido aqui.
fn executar() -> Result<(), Box<dyn std::error::Error>> {
    let argumentos: Vec<String> = env::args().collect();

    if argumentos.len() < 2 {
        eprintln!("Uso: obscura <caminho_do_binario>");
        eprintln!("Exemplo: obscura /usr/bin/ls");
        process::exit(1);
    }

    let caminho = &argumentos[1];

    // --- Leitura do binário em memória ---
    let bytes_brutos = fs::read(caminho).map_err(|e| {
        format!("Falha ao ler o arquivo '{}': {}", caminho, e)
    })?;

    imprimir_cabecalho(caminho);

    // --- Varredura de Indicadores de Comprometimento (IoCs) ---
    varrer_iocs_binario(&bytes_brutos);

    // --- Parsing do cabeçalho ELF via goblin ---
    let elf = Elf::parse(&bytes_brutos).map_err(|e| {
        format!("Falha no parsing ELF: {}. O arquivo é um binário ELF válido?", e)
    })?;

    // --- Localizar a seção .text ---
    let (endereco_base, bytes_texto) = extrair_secao_text(&elf, &bytes_brutos)?;

    println!(
        "[INFO] Seção .text localizada | Endereço base: 0x{:016X} | Tamanho: {} bytes",
        endereco_base,
        bytes_texto.len()
    );
    println!("─────────────────────────────────────────────────────");

    // --- Disassembly e varredura heurística ---
    let suspeitas = analisar_instrucoes(endereco_base, bytes_texto);

    // --- Exibição dos resultados ---
    exibir_resultados(&suspeitas);

    Ok(())
}

/// Imprime o cabeçalho da ferramenta no terminal.
fn imprimir_cabecalho(caminho: &str) {
    println!();
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║          OBSCURA — Análise Heurística ELF        ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();
    println!("[ALVO] {}", caminho);
    println!("─────────────────────────────────────────────────────");
}

/// Varre o buffer bruto do arquivo em busca de Indicadores de Comprometimento (IoCs).
/// Implementa extração estática de endereços IPv4 embutidos no binário.
///
/// Filtra automaticamente IPs de loopback, rede local e rota padrão:
/// - `0.0.0.0` (rota padrão)
/// - `127.0.0.1` (loopback)
/// - Prefixo `192.168.` (rede privada classe C)
fn varrer_iocs_binario(bytes_brutos: &[u8]) {
    let texto_binario = String::from_utf8_lossy(bytes_brutos);
    
    // Expressão regular para capturar endereços IPv4 válidos.
    let padrao_ipv4 = Regex::new(
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    ).unwrap();

    let mut iocs_externos = Vec::new();

    for captura in padrao_ipv4.find_iter(&texto_binario) {
        let ip = captura.as_str();

        // Filtrar IPs de loopback, rede local e rota padrão.
        if ip == "0.0.0.0" || ip == "127.0.0.1" || ip.starts_with("192.168.") {
            continue;
        }

        // Evitar duplicatas.
        if !iocs_externos.contains(&ip) {
            iocs_externos.push(ip);
        }
    }

    // Exibir IoCs externos encontrados.
    if !iocs_externos.is_empty() {
        for ip in &iocs_externos {
            println!("[!] IoC Encontrado (Possível C2/Drop IP): {}", ip);
        }
        println!("─────────────────────────────────────────────────────");
    }
}

/// Extrai os bytes e o endereço virtual da seção `.text` do binário ELF.
///
/// # Erros
/// Retorna erro se a seção `.text` não for encontrada ou se os offsets
/// estiverem fora dos limites do arquivo.
fn extrair_secao_text<'a>(
    elf: &Elf,
    dados: &'a [u8],
) -> Result<(u64, &'a [u8]), Box<dyn std::error::Error>> {
    for secao in &elf.section_headers {
        let nome = elf.shdr_strtab.get_at(secao.sh_name).unwrap_or("");

        if nome == ".text" {
            let inicio = secao.sh_offset as usize;
            let tamanho = secao.sh_size as usize;
            let fim = inicio + tamanho;

            if fim > dados.len() {
                return Err(format!(
                    "Seção .text excede os limites do arquivo (offset: {}, tamanho: {})",
                    inicio, tamanho
                )
                .into());
            }

            return Ok((secao.sh_addr, &dados[inicio..fim]));
        }
    }

    Err("Seção .text não encontrada no binário ELF.".into())
}

/// Realiza o disassembly dos bytes da seção `.text` e aplica as heurísticas
/// de detecção de padrões suspeitos.
///
/// ## Heurísticas implementadas:
///
/// 1. **SYSCALL nua**: Identificação de instruções `syscall` diretas,
///    comuns em shellcode que bypassa a libc.
///
/// 2. **Limpeza de registrador via XOR**: Detecção do padrão `xor reg, reg`
///    onde ambos os operandos são o mesmo registrador de 64 bits, técnica
///    clássica de ofuscação para zerar registradores sem usar `mov reg, 0`.
fn analisar_instrucoes(endereco_base: u64, bytes_texto: &[u8]) -> Vec<InstrucaoSuspeita> {
    let mut decodificador = Decoder::with_ip(
        64, // Bitness: x86_64
        bytes_texto,
        endereco_base,
        DecoderOptions::NONE,
    );

    let mut formatador = NasmFormatter::new();
    let mut instrucao = Instruction::default();
    let mut suspeitas: Vec<InstrucaoSuspeita> = Vec::new();

    // Buffer reutilizável para formatação — evita alocações repetidas.
    let mut buffer_saida = String::new();

    while decodificador.can_decode() {
        decodificador.decode_out(&mut instrucao);

        // --- Heurística 1: SYSCALL nua ---
        if instrucao.mnemonic() == Mnemonic::Syscall {
            buffer_saida.clear();
            formatador.format(&instrucao, &mut buffer_saida);

            suspeitas.push(InstrucaoSuspeita {
                endereco: instrucao.ip(),
                mnemonico: "syscall".to_string(),
                operandos: String::new(),
                motivo: "Chamada de sistema direta (syscall nua) — padrão de shellcode"
                    .to_string(),
            });
        }

        // --- Heurística 2: XOR reg, reg (limpeza de registrador) ---
        if instrucao.mnemonic() == Mnemonic::Xor && instrucao.op_count() == 2 {
            // Verifica se os dois operandos são o mesmo registrador.
            let op0 = instrucao.op0_register();
            let op1 = instrucao.op1_register();

            // Só dispara para registradores de 64 bits válidos (não Register::None).
            if op0 == op1
                && op0 != iced_x86::Register::None
                && eh_registrador_64bits(op0)
            {
                buffer_saida.clear();
                formatador.format(&instrucao, &mut buffer_saida);

                let partes: Vec<&str> = buffer_saida.splitn(2, ' ').collect();
                let operandos_formatados = if partes.len() > 1 {
                    partes[1].to_string()
                } else {
                    String::new()
                };

                suspeitas.push(InstrucaoSuspeita {
                    endereco: instrucao.ip(),
                    mnemonico: "xor".to_string(),
                    operandos: operandos_formatados,
                    motivo: "Limpeza de registrador via XOR — técnica de ofuscação/evasão"
                        .to_string(),
                });
            }
        }
    }

    suspeitas
}

/// Verifica se o registrador informado é um registrador geral de 64 bits
/// (RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8–R15).
fn eh_registrador_64bits(reg: iced_x86::Register) -> bool {
    use iced_x86::Register::*;
    matches!(
        reg,
        RAX | RBX | RCX | RDX | RSI | RDI | RSP | RBP | R8 | R9 | R10 | R11 | R12 | R13
            | R14
            | R15
    )
}

/// Exibe os resultados da análise no terminal e emite o veredito final.
fn exibir_resultados(suspeitas: &[InstrucaoSuspeita]) {
    if suspeitas.is_empty() {
        println!();
        println!("  ✅ VEREDITO: LIMPO");
        println!("  Nenhum padrão suspeito identificado na seção .text.");
        println!();
        return;
    }

    println!();
    println!(
        "  ⚠  {} instrução(ões) suspeita(s) identificada(s):",
        suspeitas.len()
    );
    println!();

    for (indice, item) in suspeitas.iter().enumerate() {
        println!("  ┌─ Ocorrência #{}", indice + 1);
        println!("  │ Endereço:  0x{:016X}", item.endereco);
        if item.operandos.is_empty() {
            println!("  │ Instrução: {}", item.mnemonico);
        } else {
            println!("  │ Instrução: {} {}", item.mnemonico, item.operandos);
        }
        println!("  │ Motivo:    {}", item.motivo);
        println!("  └────────────────────────────────────────────");
    }

    println!();
    println!("  ❌ VEREDITO: REJEITADO");
    println!(
        "  O binário apresenta {} padrão(ões) heurístico(s) associado(s)",
        suspeitas.len()
    );
    println!("  a técnicas de shellcode ou evasão de EDR.");
    println!();
}
