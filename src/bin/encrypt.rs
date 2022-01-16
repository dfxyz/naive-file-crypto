use std::path::PathBuf;

use clap::{AppSettings, Parser};

use naive_file_crypto as lib;

#[derive(Parser)]
#[clap(about = "A young, simple and naive file encryptor")]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
struct Args {
    #[clap(
        required = true,
        value_name = "FILE",
        help = "The file(s) to be encrypt"
    )]
    files: Vec<PathBuf>,

    #[clap(short = 'k', long, value_name = "KEY", help = "The secret key string")]
    secret_key: String,

    #[clap(
        short,
        long,
        value_name = "DIR",
        default_value = ".",
        help = "The directory to output the encrypted file(s)"
    )]
    output_dir: PathBuf,

    #[clap(
        short,
        long,
        value_name = "NAME",
        default_value = "encrypted",
        help = "The extension name of the encrypted file(s)"
    )]
    ext_name: String,

    #[clap(
    short,
    long,
    help = "Overwrite the file with same name"
    )]
    force: bool,

    #[clap(short='n', long, help = "Dry run (no output file)")]
    dry_run: bool,
}

fn main() {
    let args = Args::parse();
    lib::run(
        lib::Mode::Encrypt,
        args.files,
        args.secret_key,
        args.output_dir,
        args.ext_name,
        args.force,
        args.dry_run,
    )
}
