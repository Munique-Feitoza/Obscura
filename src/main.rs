mod alert;
mod analysis;
mod config;
mod daemon;

use alert::imprimir_resultado_completo;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process;

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "obscura",
    about = "Sentinela de segurança em tempo real para Linux",
    version = "0.2.0",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Comando>,

    /// Analisa um arquivo diretamente (equivale a `obscura analyze <arquivo>`)
    arquivo: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Comando {
    /// Analisa estaticamente um binário ELF
    Analyze {
        /// Caminho do arquivo a analisar
        arquivo: PathBuf,
        /// Emite o resultado em JSON (útil para integração com SIEM / pipelines)
        #[arg(long)]
        json: bool,
    },
    /// Inicia o daemon de monitoramento em tempo real via inotify
    Daemon {
        /// Caminho do arquivo de configuração JSON (opcional)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Instala o serviço systemd para o usuário atual
    Install,
    /// Gera o arquivo de configuração padrão em ~/.config/obscura/config.json
    InitConfig,
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────

const BANNER: &str = "\x1b[1;34m
  ██████╗ ██████╗ ███████╗ ██████╗██╗   ██╗██████╗  █████╗
 ██╔═══██╗██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔══██╗
 ██║   ██║██████╔╝███████╗██║     ██║   ██║██████╔╝███████║
 ██║   ██║██╔══██╗╚════██║██║     ██║   ██║██╔══██╗██╔══██║
 ╚██████╔╝██████╔╝███████║╚██████╗╚██████╔╝██║  ██║██║  ██║
  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
\x1b[0m\x1b[90m  Sentinela de Segurança — by Munique Feitoza — v0.2.0\x1b[0m
";

// ─────────────────────────────────────────────────────────────────────────────
// Ponto de entrada
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Comando::Analyze { arquivo, json }) => {
            if json {
                executar_analise_json(&arquivo);
            } else {
                println!("{BANNER}");
                executar_analise(&arquivo);
            }
        }
        Some(Comando::Daemon { config }) => {
            println!("{BANNER}");
            let cfg = config::Config::carregar_ou_padrao(config.as_ref());
            daemon::iniciar_daemon(&cfg);
        }
        Some(Comando::Install) => {
            instalar_servico();
        }
        Some(Comando::InitConfig) => {
            inicializar_config();
        }
        None => {
            // Compatibilidade retroativa: `obscura <arquivo>`
            if let Some(arquivo) = cli.arquivo {
                println!("{BANNER}");
                executar_analise(&arquivo);
            } else {
                println!("{BANNER}");
                eprintln!("Uso: obscura <arquivo>        — analisa um binário");
                eprintln!("     obscura daemon           — inicia o sentinel em tempo real");
                eprintln!("     obscura --help           — mais opções");
                process::exit(1);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Análise pontual
// ─────────────────────────────────────────────────────────────────────────────

fn executar_analise(caminho: &Path) {
    match analysis::analisar_arquivo(caminho) {
        Ok(resultado) => imprimir_resultado_completo(&resultado),
        Err(e) => {
            eprintln!("\x1b[31m[ERRO] Falha ao analisar '{}': {e}\x1b[0m", caminho.display());
            process::exit(1);
        }
    }
}

/// Emite o resultado em JSON na stdout. Sem banner, sem cores — destinado
/// a integração com pipelines, SIEM (Splunk/Loki/ELK) ou jq.
fn executar_analise_json(caminho: &Path) {
    match analysis::analisar_arquivo(caminho) {
        Ok(resultado) => match serde_json::to_string_pretty(&resultado) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!(r#"{{"erro":"falha ao serializar","detalhe":"{e}"}}"#);
                process::exit(1);
            }
        },
        Err(e) => {
            let msg = e.to_string().replace('"', "'");
            eprintln!(
                r#"{{"erro":"falha ao analisar","arquivo":"{}","detalhe":"{}"}}"#,
                caminho.display(),
                msg
            );
            process::exit(1);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instalação do serviço systemd
// ─────────────────────────────────────────────────────────────────────────────

fn instalar_servico() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/obscura"));
    let uid = libc_getuid();

    let service_dir = format!("{home}/.config/systemd/user");
    let service_path = format!("{service_dir}/obscura.service");

    let service_content = format!(
        r#"[Unit]
Description=Obscura — Sentinela de Segurança em Tempo Real
Documentation=https://github.com/muniquefeitoza/obscura
After=graphical-session.target

[Service]
Type=simple
ExecStart={bin}
Restart=on-failure
RestartSec=5
Environment=DISPLAY=:0
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus

[Install]
WantedBy=default.target
"#,
        bin = bin.display(),
        uid = uid,
    );

    if let Err(e) = std::fs::create_dir_all(&service_dir) {
        eprintln!("[ERRO] Falha ao criar diretório systemd: {e}");
        process::exit(1);
    }
    if let Err(e) = std::fs::write(&service_path, &service_content) {
        eprintln!("[ERRO] Falha ao escrever service file: {e}");
        process::exit(1);
    }

    println!("\x1b[32m[OBSCURA] Serviço instalado:\x1b[0m {service_path}");
    println!("\x1b[90mPróximos passos:\x1b[0m");
    println!("  systemctl --user daemon-reload");
    println!("  systemctl --user enable --now obscura");
    println!("  systemctl --user status obscura");
    println!("  journalctl --user -u obscura -f   # acompanhar logs");
}

fn libc_getuid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid() não tem pré-condições e é sempre seguro de chamar.
    unsafe { getuid() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Geração de config padrão
// ─────────────────────────────────────────────────────────────────────────────

fn inicializar_config() {
    let config_path = config::config_padrao_path();
    if config_path.exists() {
        println!(
            "\x1b[33m[OBSCURA] Config já existe em: {}\x1b[0m",
            config_path.display()
        );
        println!("  Remova ou edite manualmente para recriar.");
        return;
    }
    let cfg = config::Config::default();
    match cfg.salvar(&config_path) {
        Ok(()) => {
            println!(
                "\x1b[32m[OBSCURA] Configuração criada em: {}\x1b[0m",
                config_path.display()
            );
            println!("  Edite o arquivo JSON para personalizar diretórios e limiares.");
        }
        Err(e) => eprintln!("\x1b[31m[ERRO] {e}\x1b[0m"),
    }
}
