# naive-file-crypto

A young, simple and naive file crypto lib based on AES.
The MAC implementation is not standard GCM, so it may be vulnerable.

All cpu cores will be used to accelerate the processing.

## Basic Usage

1. build: `cargo build --all --release`
    * optional: pass `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` to ensure that AES-NI is always used
3. use the compiled results in `target/release`:
    * use `encrypt` or `encrypt.exe` to encrypt file(s)
    * use `decrypt` or `decrypt.exe` to decrypt file(s)

Example:
```
encrypt -k "test-key" example.txt example.md
decrypt -k "test-key" example.txt.encrypted example.md.encrypted

```
Run with `-h` flag for more options.
