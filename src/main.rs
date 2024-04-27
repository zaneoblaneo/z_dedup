use std::collections::HashMap;
use std::path::{ Path, PathBuf };
use std::hash::{ DefaultHasher, Hash, Hasher };

fn gen_dir_tree(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();

    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let mut additions = gen_dir_tree(&path)?;
                out.append(&mut additions);
            }
            out.push(path.to_path_buf());
        }
    }

    Ok(out)
}

#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::IoError(e) => {
                return write!(f, "IoError({e})");
            },
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(d: std::io::Error) -> Self {
        Self::IoError(d)
    }
}

#[derive(Hash)]
struct Data {
    data: Vec<u8>,
}

struct HashedPath {
    path: PathBuf,
    hash: u64,
}

// TODO: Implement a sha-256 hashsum rather than `std::hash::DefaultHasher`

fn main() -> Result<(), Error> {
    let mut hashes: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let p = Path::new("..");
    let files = gen_dir_tree(p)?;

    for file in files {
        if file.is_dir() { continue; }
        let data: Data = Data {
            data: std::fs::read(file.clone())?,
        };
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hashed_path = HashedPath {
            path: file,
            hash: hasher.finish(),
        };
        if hashes.contains_key(&hashed_path.hash) {
            let mut tmp = hashes.get(&hashed_path.hash).unwrap().clone();
            tmp.push(hashed_path.path);
            hashes.insert(hashed_path.hash, tmp);
        } else {
            let mut tmp: Vec<PathBuf> = Vec::new();
            tmp.push(hashed_path.path);
            hashes.insert(hashed_path.hash, tmp.to_vec());
        }
    }

    let keys: Vec<&u64> = hashes.keys().collect();

    for k in keys {
        let v: &Vec<PathBuf> = hashes.get(k).unwrap();
        if v.len() > 1 {
            println!("Hash: 0x{k:016X} {v:#?}");
        }
    }

    Ok(())
}
