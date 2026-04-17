use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// Diretórios monitorados pelo daemon em tempo real.
    pub diretorios_monitorados: Vec<PathBuf>,
    /// Prefixos de caminho ignorados pelo daemon (ex: "/tmp/node-compile-cache").
    pub caminhos_ignorados: Vec<PathBuf>,
    /// Entropia mínima (bits/byte) para disparar alerta. Padrão: 7.0.
    pub limiar_entropia: f64,
    /// Caminho do arquivo de log.
    pub caminho_log: PathBuf,
    /// Enviar notificações desktop via libnotify.
    pub notificacoes_desktop: bool,
    /// Extensões ignoradas pelo daemon (imagens, vídeos, etc.).
    pub extensoes_ignoradas: Vec<String>,
    /// Nível mínimo de ameaça para alertar no daemon (0=todos, 1=baixo+, 2=médio+).
    pub nivel_minimo_alerta: u8,
}

impl Default for Config {
    fn default() -> Self {
        let home = home_dir();
        Config {
            diretorios_monitorados: vec![
                home.join("Downloads"),
                home.join(".local/bin"),
            ],
            caminhos_ignorados: vec![
                PathBuf::from("/tmp/node-compile-cache"),
                PathBuf::from("/tmp/python-languageserver-cancellation"),
                PathBuf::from("/tmp/.org.chromium"),
                PathBuf::from("/tmp/claude-"),
            ],
            limiar_entropia: 7.0,
            caminho_log: home.join(".local/share/obscura/obscura.log"),
            notificacoes_desktop: true,
            extensoes_ignoradas: vec![
                ".jpg".into(),
                ".jpeg".into(),
                ".png".into(),
                ".gif".into(),
                ".mp4".into(),
                ".mkv".into(),
                ".mp3".into(),
                ".flac".into(),
                ".ogg".into(),
                ".pdf".into(),
                ".txt".into(),
                ".md".into(),
            ],
            nivel_minimo_alerta: 2,
        }
    }
}

impl Config {
    pub fn carregar_ou_padrao(caminho: Option<&PathBuf>) -> Self {
        let config_path = caminho.cloned().unwrap_or_else(config_padrao_path);

        if config_path.exists() {
            match std::fs::read_to_string(&config_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                Some(cfg) => cfg,
                None => {
                    eprintln!(
                        "[OBSCURA] Aviso: config inválido em '{}', usando padrão.",
                        config_path.display()
                    );
                    Config::default()
                }
            }
        } else {
            Config::default()
        }
    }

    pub fn salvar(&self, caminho: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = caminho.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(caminho, json)?;
        Ok(())
    }
}

pub fn config_padrao_path() -> PathBuf {
    home_dir().join(".config/obscura/config.json")
}

pub fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
