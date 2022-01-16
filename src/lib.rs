//! A young, simple and naive file crypto lib based on AES.
//! The MAC implementation is not standard GCM, so it may be vulnerable.
//!
//! Some references:
//! * [Finite field arithmetic](https://en.wikipedia.org/wiki/Finite_field_arithmetic)
//! * [Galois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
//! * [Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

use std::cmp::min;
use std::fs::{metadata, File, OpenOptions};
use std::io::{stdin, stdout, ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem::transmute;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::thread::{spawn, JoinHandle};
use std::time::Instant;

use aes::{Aes128, BlockEncrypt, NewBlockCipher};
use crossbeam_channel::{Receiver, Sender};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 16;
const BLOCK_BIT_SIZE: usize = 128;
const PAGE_SIZE: usize = 4096;
const PENDING_DATA_MAX_SIZE: usize = 2 * 1024 * 1024 * 1024;
const REDUCING_POLYNOMIAL: u128 = 0b10000111; // (x**128) + x**7 + x**2 + x + 1

#[derive(PartialEq, Copy, Clone)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub fn run(
    mode: Mode,
    files: Vec<PathBuf>,
    secret_key: String,
    output_dir: PathBuf,
    ext_name: String,
    force: bool,
    dry_run: bool,
) {
    let cpu_num = num_cpus::get();
    let chunk_size = cpu_num * PAGE_SIZE;
    let bounded_channel_capacity = PENDING_DATA_MAX_SIZE / chunk_size + 1;

    let hash = sha256_hash(secret_key);
    let cipher = Aes128::new_from_slice(&hash[..BLOCK_SIZE]).unwrap();
    let hasher = Aes128::new_from_slice(&hash[BLOCK_SIZE..]).unwrap();

    // create reader task; bounded channel is used to control memory usage
    let (reader_req_tx, reader_req_rx) = crossbeam_channel::unbounded();
    let (reader_rsp_tx, reader_rsp_rx) = crossbeam_channel::bounded(bounded_channel_capacity);
    let reader_handle = spawn(move || run_reader(chunk_size, reader_req_rx, reader_rsp_tx));

    // create writer task; bounded channel is used to control memory usage
    let (writer_req_tx, writer_req_rx) = crossbeam_channel::bounded(bounded_channel_capacity);
    let (writer_rsp_tx, writer_rsp_rx) = crossbeam_channel::unbounded();
    let writer_handle = spawn(move || run_writer(writer_req_rx, writer_rsp_tx));

    // create crypto worker tasks
    let mut crypto_handles =
        create_crypto_handles(&cipher, &hasher, NonZeroUsize::new(cpu_num).unwrap());

    let mut rng = thread_rng();
    for input_path in files {
        // open the files
        let mut input_file = match File::open(&input_path) {
            Ok(f) => f,
            Err(e) => {
                let path = input_path.to_string_lossy();
                eprintln!("error: cannot open the input file \"{path}\": {e}");
                println!("warning: skip processing file \"{path}\"");
                continue;
            }
        };
        let output_path = get_output_path(&input_path, &output_dir, &ext_name);
        let mut output_file = if dry_run {
            None
        } else {
            let mut open_options = OpenOptions::new();
            open_options.create(true).write(true).truncate(true);
            if !force {
                match check_overwrite_output_file(&output_path) {
                    CheckOverwriteResult::CreateNew => {
                        open_options.create_new(true);
                    }
                    CheckOverwriteResult::OverwriteExisted => {}
                    CheckOverwriteResult::Skip => {
                        let path = input_path.to_string_lossy();
                        println!("warning: skip processing file \"{path}\"");
                        continue;
                    }
                }
            }
            match open_options.open(&output_path) {
                Ok(f) => Some(f),
                Err(e) => {
                    let path = output_path.to_string_lossy();
                    eprintln!("error: cannot open the output file \"{path}\": {e}");
                    let path = input_path.to_string_lossy();
                    println!("warning: skip processing file \"{path}\"");
                    continue;
                }
            }
        };

        let path = input_path.to_string_lossy();
        println!("info: processing file \"{path}\"...");
        let start_time = Instant::now();

        // prepare stage: initialize the iv and the MAC hash, feed the reader and writer
        let mut iv: u128;
        let mut hash = 0u128;
        let mut original_hash = 0u128;
        match mode {
            Mode::Encrypt => {
                // generate iv, write the iv and the hash placeholder
                iv = rng.gen();
                if !dry_run {
                    let output_file = output_file.as_mut().unwrap();
                    output_file.write_all(&iv.clone().to_le_bytes()).unwrap();
                    output_file.write_all(&[0u8; BLOCK_SIZE]).unwrap();
                }
            }
            Mode::Decrypt => {
                // load the iv and the hash
                let mut buf = [0u8; 2 * BLOCK_SIZE];
                let len = input_file.read(&mut buf).unwrap();
                if len != 2 * BLOCK_SIZE {
                    let path = input_path.to_string_lossy();
                    eprintln!("error: input file \"{path}\" is invalid: too short");
                    println!("warning: skip processing file \"{path}\"");
                    continue;
                }
                let (iv_bytes, hash_bytes) = unsafe { transmute(buf) };
                iv = u128::from_le_bytes(iv_bytes);
                original_hash = u128::from_le_bytes(hash_bytes);
            }
        }
        reader_req_tx
            .send(ReaderTaskReq { file: input_file })
            .unwrap();
        if !dry_run {
            writer_req_tx
                .send(WriterTaskReq::Prepare {
                    file: output_file.take().unwrap(),
                })
                .unwrap();
        }

        // process stage: read, process, then write the chunks
        loop {
            let ReaderTaskRsp { mut chunk } = reader_rsp_rx.recv().unwrap();
            if chunk.is_empty() {
                break;
            }
            let page_iter = chunk.chunks_mut(PAGE_SIZE);
            let page_num = page_iter.len();
            for (i, page) in page_iter.enumerate() {
                let page_num = page.chunks(BLOCK_SIZE).len() as u128;
                crypto_handles[i]
                    .req_tx
                    .send(CryptoTaskReq {
                        mode,
                        iv,
                        slice: unsafe { transmute(page) },
                    })
                    .unwrap();
                iv += page_num;
            }
            for i in 0..page_num {
                let CryptoTaskRsp { hash: h } = crypto_handles[i].rsp_rx.recv().unwrap();
                hash ^= h;
            }
            if !dry_run {
                writer_req_tx
                    .send(WriterTaskReq::Write { bytes: chunk })
                    .unwrap();
            }
        }

        // finish stage: handle the MAC hash
        match mode {
            Mode::Encrypt => {
                if !dry_run {
                    writer_req_tx
                        .send(WriterTaskReq::Write { bytes: vec![] })
                        .unwrap();
                    let WriterTaskRsp { mut file } = writer_rsp_rx.recv().unwrap();
                    file.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
                    file.write_all(&hash.to_le_bytes()).unwrap();
                }
            }
            Mode::Decrypt => {
                if hash != original_hash {
                    eprintln!(
                        "error: the MAC hash doesn't match; the secret key is invalid, or the input file is corrupted"
                    );
                }
            }
        }
        let duration = Instant::now() - start_time;
        let milliseconds = duration.as_millis() % 1000;
        let seconds = duration.as_secs() % 60;
        let minutes = duration.as_secs() / 60;
        let time_usage = format!("time usage: min={minutes}, sec={seconds}, ms={milliseconds}");
        let path = output_path.to_string_lossy();
        if dry_run {
            println!("info: dry run finished; {time_usage}") ;
        } else {
            println!("info: processing result has been saved to \"{path}\"; {time_usage}");
        }
    }

    drop(reader_req_tx);
    reader_handle.join().unwrap();
    drop(writer_req_tx);
    writer_handle.join().unwrap();
    while !crypto_handles.is_empty() {
        let handle = crypto_handles.swap_remove(0);
        drop(handle.req_tx);
        handle.join_handle.join().unwrap();
    }
}

fn sha256_hash(s: impl AsRef<[u8]>) -> [u8; 2 * BLOCK_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(s);
    unsafe { transmute(hasher.finalize()) }
}

struct ReaderTaskReq {
    file: File,
}
struct ReaderTaskRsp {
    chunk: Vec<u8>, // an empty chunk indicates eof has been reached
}
fn run_reader(chunk_size: usize, req_rx: Receiver<ReaderTaskReq>, rsp_tx: Sender<ReaderTaskRsp>) {
    for req in req_rx {
        let mut file = req.file;
        loop {
            let mut buf = vec![0; chunk_size];
            let len = file.read(&mut buf).unwrap();
            buf.truncate(len);
            rsp_tx.send(ReaderTaskRsp { chunk: buf }).unwrap();
            if len == 0 {
                break;
            }
        }
    }
}

enum WriterTaskReq {
    Prepare { file: File },
    Write { bytes: Vec<u8> }, // an empty bytes indicates the end of writing task
}
struct WriterTaskRsp {
    file: File,
}
fn run_writer(req_rx: Receiver<WriterTaskReq>, rsp_tx: Sender<WriterTaskRsp>) {
    let mut file = None;
    for req in req_rx {
        match req {
            WriterTaskReq::Prepare { file: f } => {
                file.replace(f);
            }
            WriterTaskReq::Write { bytes } => {
                if bytes.is_empty() {
                    // return the file
                    let f = file.take().unwrap();
                    rsp_tx.send(WriterTaskRsp { file: f }).unwrap();
                } else {
                    // write the given bytes
                    let f = file.as_mut().unwrap();
                    f.write_all(&bytes).unwrap();
                }
            }
        }
    }
}

struct CryptoHandle {
    req_tx: Sender<CryptoTaskReq>,
    rsp_rx: Receiver<CryptoTaskRsp>,
    join_handle: JoinHandle<()>,
}
fn create_crypto_handles(
    cipher: &Aes128,
    hasher: &Aes128,
    thread_num: NonZeroUsize,
) -> Vec<CryptoHandle> {
    let mut handles = vec![];
    for _ in 0..thread_num.get() {
        let cipher = cipher.clone();
        let hasher = hasher.clone();
        let (req_tx, req_rx) = crossbeam_channel::unbounded();
        let (rsp_tx, rsp_rx) = crossbeam_channel::unbounded();
        let join_handle = spawn(move || run_crypto(cipher, hasher, req_rx, rsp_tx));
        handles.push(CryptoHandle {
            req_tx,
            rsp_rx,
            join_handle,
        })
    }
    handles
}

struct CryptoTaskReq {
    mode: Mode,
    iv: u128,
    slice: [usize; 2],
}
struct CryptoTaskRsp {
    hash: u128,
}
fn run_crypto(
    cipher: Aes128,
    hasher: Aes128,
    req_rx: Receiver<CryptoTaskReq>,
    rsp_tx: Sender<CryptoTaskRsp>,
) {
    for req in req_rx {
        let slice: &mut [u8] = unsafe { transmute(req.slice) };
        let block_iter = slice.chunks_mut(BLOCK_SIZE);
        let block_num = block_iter.len();
        if block_num == 0 {
            rsp_tx.send(CryptoTaskRsp { hash: 0 }).unwrap();
            continue;
        }

        let (cipher_blocks, hasher_blocks) =
            create_cipher_hasher_blocks(&cipher, &hasher, req.iv, block_num);
        let mut hash = 0;
        for (i, block) in block_iter.enumerate() {
            if req.mode == Mode::Decrypt {
                hash ^= galois_multiply(&hasher_blocks[i], block);
            }

            for (j, byte) in block.iter_mut().enumerate() {
                *byte ^= cipher_blocks[i][j];
            }

            if req.mode == Mode::Encrypt {
                hash ^= galois_multiply(&hasher_blocks[i], block);
            }
        }

        rsp_tx.send(CryptoTaskRsp { hash }).unwrap();
    }
}

fn create_cipher_hasher_blocks(
    cipher: &Aes128,
    hasher: &Aes128,
    iv: u128,
    block_num: usize,
) -> (Vec<[u8; BLOCK_SIZE]>, Vec<[u8; BLOCK_SIZE]>) {
    let mut cipher_blocks = (iv..iv + block_num as u128)
        .map(|u| u.to_le_bytes().into())
        .collect::<Vec<_>>();
    let mut hasher_blocks = cipher_blocks.clone();
    cipher.encrypt_blocks(&mut cipher_blocks);
    hasher.encrypt_blocks(&mut hasher_blocks);
    unsafe { transmute((cipher_blocks, hasher_blocks)) }
}

fn galois_multiply(block: &[u8; BLOCK_SIZE], slice: &[u8]) -> u128 {
    let num1 = u128::from_le_bytes(block.clone());
    let num2 = slice_to_u128(slice);
    let mut lower128 = 0u128;
    let mut higher128 = 0u128;
    for i in 0..BLOCK_BIT_SIZE {
        let bit = get_u128_bit(num1, i);
        if bit == 0 {
            continue;
        }
        lower128 ^= num2 << i;
        higher128 ^= num2.checked_shr((BLOCK_BIT_SIZE - i) as u32).unwrap_or(0);
    }
    for i in (0..BLOCK_BIT_SIZE).rev() {
        let bit = get_u128_bit(higher128, i);
        if bit == 0 {
            continue;
        }
        set_u128_bit_zero(&mut higher128, i);
        higher128 ^= REDUCING_POLYNOMIAL
            .checked_shr((BLOCK_BIT_SIZE - i) as u32)
            .unwrap_or(0);
        lower128 ^= REDUCING_POLYNOMIAL.checked_shl(i as u32).unwrap_or(0);
    }
    lower128
}

#[inline]
fn slice_to_u128(slice: &[u8]) -> u128 {
    let mut block = [0u8; BLOCK_SIZE];
    for i in 0..min(slice.len(), BLOCK_SIZE) {
        block[i] = slice[i];
    }
    u128::from_le_bytes(block)
}

#[inline]
fn get_u128_bit(u: u128, i: usize) -> u8 {
    if u & 1u128.checked_shl(i as u32).unwrap_or(0) == 0 {
        0
    } else {
        1
    }
}

#[inline]
fn set_u128_bit_zero(u: &mut u128, i: usize) {
    *u &= u128::MAX - (1u128.checked_shl(i as u32).unwrap_or(0));
}

fn get_output_path(input_path: &PathBuf, output_dir: &PathBuf, ext_name: &str) -> PathBuf {
    let input_filename = input_path.file_name().unwrap().to_string_lossy();
    let output_filename = format!("{input_filename}.{ext_name}");
    output_dir.join(output_filename)
}

enum CheckOverwriteResult {
    CreateNew,
    OverwriteExisted,
    Skip,
}

fn check_overwrite_output_file(output_path: &PathBuf) -> CheckOverwriteResult {
    match metadata(output_path) {
        Ok(md) => {
            let path = output_path.to_string_lossy();
            if !md.is_file() {
                eprintln!("error: the output path \"{path}\" doesn't point to a normal file");
                CheckOverwriteResult::Skip
            } else {
                print!("question: overwrite the file at \"{path}\"? [y/N] ");
                stdout().flush().unwrap();
                let mut answer = String::new();
                stdin().read_line(&mut answer).unwrap();
                let answer = answer.trim();
                if answer == "y" || answer == "Y" {
                    println!("info: will overwrite the file at \"{path}\"");
                    CheckOverwriteResult::OverwriteExisted
                } else {
                    println!("info: will not overwrite the file at \"{path}\"");
                    CheckOverwriteResult::Skip
                }
            }
        }
        Err(e) if e.kind() != ErrorKind::NotFound => {
            let path = output_path.to_string_lossy();
            eprintln!("error: cannot check the status of the output file \"{path}\": {e}");
            CheckOverwriteResult::Skip
        }
        _ => CheckOverwriteResult::CreateNew,
    }
}
