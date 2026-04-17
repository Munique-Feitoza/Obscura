use crate::alert::emitir_alerta;
use crate::analysis::analisar_arquivo;
use crate::config::Config;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

const RESET: &str = "\x1b[0m";
const VERDE: &str = "\x1b[32m";
const CINZA: &str = "\x1b[90m";

pub fn iniciar_daemon(config: &Config) {
    println!("{VERDE}[OBSCURA]{RESET} Daemon iniciado. Monitorando:");
    for dir in &config.diretorios_monitorados {
        if dir.exists() {
            println!("  {VERDE}→{RESET} {}", dir.display());
        } else {
            println!("  {CINZA}→ {} (não existe, ignorado){RESET}", dir.display());
        }
    }
    println!(
        "{VERDE}[OBSCURA]{RESET} Limiar entropia : {:.1} bits/byte",
        config.limiar_entropia
    );
    println!(
        "{VERDE}[OBSCURA]{RESET} Log             : {}",
        config.caminho_log.display()
    );
    println!("{VERDE}[OBSCURA]{RESET} Pressione Ctrl+C para parar.\n");

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(tx).expect("[OBSCURA] Falha ao criar inotify watcher");

    let mut algum_dir_ativo = false;
    for dir in &config.diretorios_monitorados {
        if dir.exists() {
            match watcher.watch(dir, RecursiveMode::Recursive) {
                Ok(()) => algum_dir_ativo = true,
                Err(e) => eprintln!(
                    "[OBSCURA] Aviso: não foi possível monitorar '{}': {e}",
                    dir.display()
                ),
            }
        }
    }

    if !algum_dir_ativo {
        eprintln!("[OBSCURA] Nenhum diretório monitorado existe. Encerrando.");
        return;
    }

    for evento in rx {
        match evento {
            Ok(ev) => processar_evento(&ev, config),
            Err(e) => eprintln!("[OBSCURA] Erro de watcher: {e}"),
        }
    }
}

fn processar_evento(evento: &Event, config: &Config) {
    let relevante = matches!(
        evento.kind,
        EventKind::Create(_) | EventKind::Modify(_)
    );
    if !relevante {
        return;
    }

    for caminho in &evento.paths {
        if !caminho.is_file() {
            continue;
        }
        if deve_ignorar(caminho, config) {
            continue;
        }

        // Aguarda o arquivo terminar de ser gravado antes de analisar.
        std::thread::sleep(Duration::from_millis(300));

        match analisar_arquivo(caminho) {
            Ok(resultado) => {
                let nivel_val = resultado.nivel_ameaca.valor();
                if nivel_val >= config.nivel_minimo_alerta {
                    emitir_alerta(
                        &resultado,
                        &config.caminho_log,
                        config.notificacoes_desktop,
                    );
                } else {
                    // Log silencioso para arquivos limpos
                    let ts = resultado.timestamp.format("%H:%M:%S");
                    println!(
                        "{CINZA}[{ts}] LIMPO  {}{RESET}",
                        caminho.display()
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "[OBSCURA] Erro ao analisar '{}': {e}",
                    caminho.display()
                );
            }
        }
    }
}

fn deve_ignorar(caminho: &Path, config: &Config) -> bool {
    let ext = caminho
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default()
        .to_lowercase();

    if config.extensoes_ignoradas.iter().any(|ign| *ign == ext) {
        return true;
    }

    // Prefixo de caminho ignorado (ex: /tmp/node-compile-cache)
    let caminho_str = caminho.to_string_lossy();
    config.caminhos_ignorados.iter().any(|ignorado| {
        caminho_str.starts_with(ignorado.to_string_lossy().as_ref())
    })
}
