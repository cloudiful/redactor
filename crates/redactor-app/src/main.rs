mod app_config;
mod cli;
mod commands;
mod git_apply;
mod io;
mod output;
mod settings;
mod support;

fn main() -> anyhow::Result<()> {
    cli::run()
}
