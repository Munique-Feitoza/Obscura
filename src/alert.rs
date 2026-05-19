use crate::analysis::{NivelAmeaca, ResultadoAnalise};
use std::io::Write;
use std::path::Path;

// Cores ANSI
const RESET: &str = "\x1b[0m";
const VERDE: &str = "\x1b[32m";
const AMARELO: &str = "\x1b[33m";
const VERMELHO: &str = "\x1b[31m";
const VERMELHO_FORTE: &str = "\x1b[1;31m";
const CINZA: &str = "\x1b[90m";

pub fn emitir_alerta(resultado: &ResultadoAnalise, log_path: &Path, notif_desktop: bool) {
    imprimir_console(resultado);

    if let Err(e) = escrever_log(resultado, log_path) {
        eprintln!("{CINZA}[OBSCURA] Erro ao escrever log: {e}{RESET}");
    }

    if notif_desktop {
        enviar_notificacao_desktop(resultado);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Saída no terminal
// ─────────────────────────────────────────────────────────────────────────────

pub fn imprimir_resultado_completo(r: &ResultadoAnalise) {
    let cor = cor_nivel(&r.nivel_ameaca);
    let icone = icone_nivel(&r.nivel_ameaca);

    println!("\n{cor}╔══════════════════════════════════════════════════════════╗{RESET}");
    println!("{cor}║  {icone}  OBSCURA — RESULTADO DA ANÁLISE{RESET}");
    println!("{cor}╠══════════════════════════════════════════════════════════╣{RESET}");
    println!("{cor}║{RESET}  Alvo      : {}", r.caminho.display());
    println!(
        "{cor}║{RESET}  Tamanho   : {}{}",
        formatar_tamanho(r.tamanho_arquivo),
        if r.arquivo_truncado {
            format!(" {CINZA}[truncado para análise, primeiros {} MiB]{RESET}",
                crate::analysis::TAMANHO_MAXIMO_LEITURA / (1024 * 1024))
        } else {
            String::new()
        }
    );
    println!(
        "{cor}║{RESET}  Veredito  : {cor}{}{RESET}",
        r.nivel_ameaca.nome()
    );
    println!("{cor}║{RESET}  Pontuação : {:.1} pts", r.pontuacao);
    if r.formato_comprimido {
        println!(
            "{cor}║{RESET}  Entropia  : {:.4} bits/byte {CINZA}[container comprimido — normal]{RESET}",
            r.entropia
        );
    } else {
        println!(
            "{cor}║{RESET}  Entropia  : {:.4} bits/byte {}",
            r.entropia,
            rotulo_entropia(r.entropia, cor)
        );
    }
    println!(
        "{cor}║{RESET}  ELF       : {}",
        if r.eh_elf { "sim" } else { "não" }
    );
    println!(
        "{cor}║{RESET}  +exec     : {}",
        flag_str(r.tem_permissao_exec, cor)
    );
    println!(
        "{cor}║{RESET}  Internet  : {}",
        flag_str(r.veio_da_internet, cor)
    );

    if !r.iocs.is_empty() {
        println!("{cor}╠══════════════════════════════════════════════════════════╣{RESET}");
        println!(
            "{cor}║{RESET}  IoCs detectados ({}):",
            r.iocs.len()
        );
        for ioc in &r.iocs {
            println!(
                "{cor}║{RESET}    [{}] {VERMELHO}{}{RESET}",
                ioc.tipo.rotulo(),
                ioc.valor
            );
        }
    }

    if !r.secoes_anomalas.is_empty() {
        println!("{cor}╠══════════════════════════════════════════════════════════╣{RESET}");
        println!(
            "{cor}║{RESET}  Seções ELF não-padrão com entropia alta ({}):",
            r.secoes_anomalas.len()
        );
        for sec in &r.secoes_anomalas {
            println!(
                "{cor}║{RESET}    → {VERMELHO}{}{RESET} {CINZA}({:.3} bits, {} bytes){RESET}",
                sec.nome, sec.entropia, sec.tamanho
            );
        }
    }

    if !r.imports_suspeitos.is_empty() {
        println!("{cor}╠══════════════════════════════════════════════════════════╣{RESET}");
        println!(
            "{cor}║{RESET}  Imports suspeitos ({}):",
            r.imports_suspeitos.len()
        );
        for imp in &r.imports_suspeitos {
            println!(
                "{cor}║{RESET}    → {VERMELHO}{}{RESET} {CINZA}[{}]{RESET}",
                imp.nome,
                imp.categoria.rotulo()
            );
        }
    }

    if !r.instrucoes_suspeitas.is_empty() {
        println!("{cor}╠══════════════════════════════════════════════════════════╣{RESET}");
        println!(
            "{cor}║{RESET}  Padrões ELF ({} instrução(ões) suspeita(s)):",
            r.instrucoes_suspeitas.len()
        );
        for inst in &r.instrucoes_suspeitas {
            let instr = if inst.operandos.is_empty() {
                inst.mnemonico.clone()
            } else {
                format!("{} {}", inst.mnemonico, inst.operandos)
            };
            println!(
                "{cor}║{RESET}  ┌─ [0x{:016X}] {instr}",
                inst.endereco
            );
            println!("{cor}║{RESET}  └─ {CINZA}{}{RESET}", inst.motivo);
        }
    }

    println!("{cor}╚══════════════════════════════════════════════════════════╝{RESET}\n");
}

fn imprimir_console(r: &ResultadoAnalise) {
    let cor = cor_nivel(&r.nivel_ameaca);
    let icone = icone_nivel(&r.nivel_ameaca);
    let ts = r.timestamp.format("%H:%M:%S");

    println!("\n{cor}┌──────────────────────────────────────────────────────────┐{RESET}");
    println!("{cor}│  {icone} OBSCURA ALERTA  [{ts}]                             │{RESET}");
    println!("{cor}├──────────────────────────────────────────────────────────┤{RESET}");
    println!(
        "{cor}│{RESET}  {cor}{}{RESET}  —  {}",
        r.nivel_ameaca.nome(),
        r.caminho.file_name().unwrap_or_default().to_string_lossy()
    );
    let nota_entropia = if r.formato_comprimido { " (comprimido)" } else { "" };
    println!(
        "{cor}│{RESET}  Entropia {:.3}{nota_entropia}  |  Pontuação {:.1}  |  IoCs {}  |  ELF suspeitos {}",
        r.entropia,
        r.pontuacao,
        r.iocs.len(),
        r.instrucoes_suspeitas.len()
    );
    if r.veio_da_internet && r.tem_permissao_exec {
        println!("{VERMELHO_FORTE}│  [!!] Executável baixado da internet detectado!{RESET}");
    } else if r.veio_da_internet {
        println!("{cor}│{RESET}  [!] Arquivo de origem: Internet (xattr confirmado)");
    }
    if !r.iocs.is_empty() {
        let amostra: Vec<String> = r
            .iocs
            .iter()
            .take(5)
            .map(|i| format!("[{}] {}", i.tipo.rotulo(), i.valor))
            .collect();
        let sufixo = if r.iocs.len() > 5 {
            format!(" (+{} outros)", r.iocs.len() - 5)
        } else {
            String::new()
        };
        println!(
            "{cor}│{RESET}  [!] IoCs: {}{sufixo}",
            amostra.join(", ")
        );
    }
    println!("{cor}└──────────────────────────────────────────────────────────┘{RESET}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Log em arquivo (tail -f compatível)
// ─────────────────────────────────────────────────────────────────────────────

/// Tamanho máximo do log antes de rotacionar. Acima disso, o arquivo atual
/// é renomeado para `<log>.1` e uma nova trilha começa. Um nível de retenção.
const TAMANHO_MAXIMO_LOG: u64 = 5 * 1024 * 1024; // 5 MiB

fn escrever_log(r: &ResultadoAnalise, log_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    rotar_log_se_necessario(log_path)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    let ts = r.timestamp.format("%Y-%m-%d %H:%M:%S");
    writeln!(
        file,
        "[{ts}] [{nivel}] pontuacao={pts:.1} entropia={ent:.4} exec={exec} internet={inet} iocs={niocs} elf_suspeitos={nelf} arquivo={caminho}",
        nivel = r.nivel_ameaca.nome(),
        pts = r.pontuacao,
        ent = r.entropia,
        exec = r.tem_permissao_exec,
        inet = r.veio_da_internet,
        niocs = r.iocs.len(),
        nelf = r.instrucoes_suspeitas.len(),
        caminho = r.caminho.display(),
    )
}

/// Rotaciona o log quando ele excede [`TAMANHO_MAXIMO_LOG`]. Mantém uma única
/// cópia `<log>.1`; o histórico anterior é descartado.
fn rotar_log_se_necessario(log_path: &Path) -> std::io::Result<()> {
    let Ok(metadata) = std::fs::metadata(log_path) else {
        // Arquivo ainda não existe — primeira escrita, sem rotação.
        return Ok(());
    };
    if metadata.len() < TAMANHO_MAXIMO_LOG {
        return Ok(());
    }
    let rotacionado = log_path.with_extension(
        log_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!("{e}.1"))
            .unwrap_or_else(|| "1".into()),
    );
    // Em caso de falha (FS readonly, sem permissão), seguimos sem rotação
    // para não bloquear o alerta — só logamos no stderr.
    if let Err(e) = std::fs::rename(log_path, &rotacionado) {
        eprintln!(
            "[OBSCURA] aviso: falha ao rotacionar log '{}' → '{}': {e}",
            log_path.display(),
            rotacionado.display()
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Notificação desktop via libnotify / D-Bus
// ─────────────────────────────────────────────────────────────────────────────

fn enviar_notificacao_desktop(r: &ResultadoAnalise) {
    let urgencia = match r.nivel_ameaca {
        NivelAmeaca::Limpo | NivelAmeaca::Baixo => return,
        NivelAmeaca::Medio => notify_rust::Urgency::Normal,
        NivelAmeaca::Alto | NivelAmeaca::Critico => notify_rust::Urgency::Critical,
    };

    let titulo = format!(
        "OBSCURA — {} {}",
        icone_nivel(&r.nivel_ameaca),
        r.nivel_ameaca.nome()
    );

    let mut linhas: Vec<String> = Vec::new();
    linhas.push(format!(
        "{}",
        r.caminho.file_name().unwrap_or_default().to_string_lossy()
    ));
    linhas.push(format!(
        "Entropia: {:.2} | Pontuação: {:.1}",
        r.entropia, r.pontuacao
    ));
    if r.veio_da_internet && r.tem_permissao_exec {
        linhas.push("⚠ Executável baixado da internet!".into());
    }
    if !r.iocs.is_empty() {
        let amostra: Vec<String> = r
            .iocs
            .iter()
            .take(3)
            .map(|i| format!("[{}] {}", i.tipo.rotulo(), i.valor))
            .collect();
        let sufixo = if r.iocs.len() > 3 {
            format!(" (+{})", r.iocs.len() - 3)
        } else {
            String::new()
        };
        linhas.push(format!("IoCs: {}{sufixo}", amostra.join(", ")));
    }
    if !r.instrucoes_suspeitas.is_empty() {
        linhas.push(format!(
            "Padrões ELF: {} suspeito(s)",
            r.instrucoes_suspeitas.len()
        ));
    }

    let _ = notify_rust::Notification::new()
        .summary(&titulo)
        .body(&linhas.join("\n"))
        .urgency(urgencia)
        .timeout(notify_rust::Timeout::Milliseconds(8000))
        .show();
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers visuais
// ─────────────────────────────────────────────────────────────────────────────

fn cor_nivel(nivel: &NivelAmeaca) -> &'static str {
    match nivel {
        NivelAmeaca::Limpo => VERDE,
        NivelAmeaca::Baixo => AMARELO,
        NivelAmeaca::Medio => AMARELO,
        NivelAmeaca::Alto => VERMELHO,
        NivelAmeaca::Critico => VERMELHO_FORTE,
    }
}

fn icone_nivel(nivel: &NivelAmeaca) -> &'static str {
    match nivel {
        NivelAmeaca::Limpo => "✓",
        NivelAmeaca::Baixo => "△",
        NivelAmeaca::Medio => "⚠",
        NivelAmeaca::Alto => "✖",
        NivelAmeaca::Critico => "☠",
    }
}

fn rotulo_entropia(e: f64, cor: &str) -> String {
    if e > 7.5 {
        format!("{VERMELHO_FORTE}[MUITO ALTA — possível packer/crypt]{RESET}")
    } else if e > 7.0 {
        format!("{cor}[ALTA — suspeito]{RESET}")
    } else if e > 6.5 {
        format!("{AMARELO}[ELEVADA]{RESET}")
    } else {
        String::new()
    }
}

fn flag_str(valor: bool, cor: &str) -> String {
    if valor {
        format!("{cor}sim ⚠{RESET}")
    } else {
        "não".into()
    }
}

/// Formata bytes em unidade humana (B / KiB / MiB / GiB).
fn formatar_tamanho(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
