use crate::alert::emitir_alerta;
use crate::analysis::analisar_arquivo;
use crate::config::Config;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const RESET: &str = "\x1b[0m";
const VERDE: &str = "\x1b[32m";
const CINZA: &str = "\x1b[90m";

/// Janela de dedupe — mesmo caminho dentro desta janela não é re-analisado.
const JANELA_DEDUPE: Duration = Duration::from_secs(3);

/// Polling para detectar que o arquivo terminou de ser gravado.
const POLLING_INTERVALO: Duration = Duration::from_millis(150);
/// Timeout máximo aguardando o arquivo estabilizar.
const POLLING_TIMEOUT: Duration = Duration::from_secs(8);

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

    let mut cache_dedupe: HashMap<PathBuf, Instant> = HashMap::new();

    for evento in rx {
        match evento {
            Ok(ev) => processar_evento(&ev, config, &mut cache_dedupe),
            Err(e) => eprintln!("[OBSCURA] Erro de watcher: {e}"),
        }
        // Faxina periódica do cache para evitar crescimento ilimitado.
        if cache_dedupe.len() > 1024 {
            limpar_cache_dedupe(&mut cache_dedupe);
        }
    }
}

fn processar_evento(
    evento: &Event,
    config: &Config,
    cache_dedupe: &mut HashMap<PathBuf, Instant>,
) {
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

        // Dedupe: Create + Modify do mesmo arquivo dispara dois eventos quase
        // simultâneos. Ignora se já analisamos este caminho recentemente.
        let agora = Instant::now();
        if let Some(quando) = cache_dedupe.get(caminho) {
            if agora.duration_since(*quando) < JANELA_DEDUPE {
                continue;
            }
        }

        // Espera o arquivo estabilizar antes de ler (em vez de sleep fixo).
        if !aguardar_arquivo_estavel(caminho) {
            // arquivo sumiu / nunca estabilizou — segue
            continue;
        }

        cache_dedupe.insert(caminho.clone(), agora);

        match analisar_arquivo(caminho) {
            Ok(resultado) => {
                let nivel_val = resultado.nivel_ameaca.valor();
                if nivel_val >= config.nivel_minimo_alerta {
                    emitir_alerta(
                        &resultado,
                        &config.caminho_log,
                        config.notificacoes_desktop,
                    );
                    if config.quarentena.ativa
                        && nivel_val >= config.quarentena.nivel_minimo
                    {
                        executar_quarentena(caminho, &config.quarentena);
                    }
                } else {
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

/// Move o arquivo para o diretório de quarentena e desarma o bit +x.
/// Falhas são logadas em stderr mas não abortam o daemon.
fn executar_quarentena(caminho: &Path, cfg: &crate::config::QuarentenaConfig) {
    use std::os::unix::fs::PermissionsExt;

    let nome = caminho.file_name().and_then(|n| n.to_str()).unwrap_or("arquivo");
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let destino = cfg.diretorio.join(format!("{ts}-{nome}"));

    if let Err(e) = std::fs::create_dir_all(&cfg.diretorio) {
        eprintln!(
            "[OBSCURA] quarentena: falha ao criar diretório '{}': {e}",
            cfg.diretorio.display()
        );
        return;
    }

    if cfg.remover_executavel {
        if let Ok(meta) = std::fs::metadata(caminho) {
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() & !0o111);
            if let Err(e) = std::fs::set_permissions(caminho, perms) {
                eprintln!(
                    "[OBSCURA] quarentena: falha ao remover +x de '{}': {e}",
                    caminho.display()
                );
            }
        }
    }

    match std::fs::rename(caminho, &destino) {
        Ok(()) => println!(
            "\x1b[1;31m[OBSCURA] QUARENTENA: '{}' → '{}'{RESET}",
            caminho.display(),
            destino.display()
        ),
        Err(e) => eprintln!(
            "[OBSCURA] quarentena: falha ao mover '{}' → '{}': {e}",
            caminho.display(),
            destino.display()
        ),
    }
}

/// Aguarda o arquivo parar de mudar de tamanho — robusto para downloads em
/// andamento. Retorna `true` se estabilizou, `false` em timeout ou se sumiu.
fn aguardar_arquivo_estavel(caminho: &Path) -> bool {
    let inicio = Instant::now();
    let mut tamanho_anterior: Option<u64> = None;
    while inicio.elapsed() < POLLING_TIMEOUT {
        std::thread::sleep(POLLING_INTERVALO);
        let Ok(metadata) = std::fs::metadata(caminho) else {
            return false; // arquivo sumiu (ex: download cancelado)
        };
        let tamanho = metadata.len();
        if Some(tamanho) == tamanho_anterior {
            return true;
        }
        tamanho_anterior = Some(tamanho);
    }
    // Timeout — analisa mesmo assim com o que temos (download muito lento).
    true
}

/// Remove entradas antigas do cache de dedupe (> 2x JANELA_DEDUPE).
fn limpar_cache_dedupe(cache: &mut HashMap<PathBuf, Instant>) {
    let agora = Instant::now();
    let limite = JANELA_DEDUPE * 2;
    cache.retain(|_, t| agora.duration_since(*t) < limite);
}

fn deve_ignorar(caminho: &Path, config: &Config) -> bool {
    let ext = caminho
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default()
        .to_lowercase();

    if config.extensoes_ignoradas.contains(&ext) {
        return true;
    }

    // Prefixo de caminho ignorado (ex: /tmp/node-compile-cache)
    let caminho_str = caminho.to_string_lossy();
    config.caminhos_ignorados.iter().any(|ignorado| {
        caminho_str.starts_with(ignorado.to_string_lossy().as_ref())
    })
}
