
pub mod hashing {
    pub type Word = u32;

    pub struct Sha256Hasher {
        pub data: [u8; 64],
        pub datalen: Word,
        pub bitlen: u64,
        pub state: [Word; 8],
    }

    impl Sha256Hasher {
        const K: [Word; 64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
            0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
            0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
            0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
            0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
            0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
            0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
            0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
            0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];
        
        fn sha256_transform(&mut self, data: [u8; 64]) {
            let mut  i: Word       = 0;
            let mut  j: Word       = 0;
            let mut  m: [Word; 64] = [0u32; 64];

            for _ in 0..16 {
                m[i as usize] = ((data[(j + 0) as usize] as Word) << 24) | 
                                ((data[(j + 1) as usize] as Word) << 16) | 
                                ((data[(j + 2) as usize] as Word) << 8)  | 
                                ((data[(j + 3) as usize] as Word) << 0);
                i += 1;
                j += 4;
            }

            for _ in 16..64 {
                m[i as usize] = sig1(m[(i - 2)  as usize]) + 
                                     m[(i - 7)  as usize]  + 
                                sig0(m[(i - 15) as usize]) + 
                                     m[(i - 16) as usize];
                i += 1;
            }

            let mut  a: Word = self.state[0usize];
            let mut  b: Word = self.state[1usize];
            let mut  c: Word = self.state[2usize];
            let mut  d: Word = self.state[3usize];
            let mut  e: Word = self.state[4usize];
            let mut  f: Word = self.state[5usize];
            let mut  g: Word = self.state[6usize];
            let mut  h: Word = self.state[7usize];
            let mut t1: Word;
            let mut t2: Word;
            
            for i in 0..64 {
                t1 = h + ep1(e) + ch(e, f, g) + 
                     Self::K[i as usize] + m[i as usize];
                t2 = ep0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            self.state[0 as usize] += a;
            self.state[1 as usize] += b;
            self.state[2 as usize] += c;
            self.state[3 as usize] += d;
            self.state[4 as usize] += e;
            self.state[5 as usize] += f;
            self.state[6 as usize] += g;
            self.state[7 as usize] += h;
        }

        pub fn sha256_init() -> Self {
            Self {
                data: [0u8; 64],
                datalen: 0,
                bitlen: 0,
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                ],
            }
        }

        pub fn sha256_update(&mut self, data: Vec<u8>) {
            for i in 0..data.len() {
                self.data[self.datalen as usize] = data[i];
                self.datalen += 1;
                if self.datalen == 64 {
                    self.sha256_transform(self.data);
                    self.bitlen += 512;
                    self.datalen = 0;
                }
            }
        }

        pub fn sha256_final(&mut self) -> [u8; 32] {
            let mut i: Word = self.datalen;

            // Pad whatever data is left in the buffer.
            if self.datalen < 56 {
                self.data[i as usize] = 0x80;
                i += 1;
                while i < 64 {
                    self.data[i as usize] = 0x00;
                    i += 1;
                }
            } else {
                self.data[i as usize] = 0x80;
                i += 1;
                while i < 64 {
                    self.data[i as usize] = 0x00;
                    i += 1;
                }
                self.sha256_transform(self.data);
                for tmp in 0..56 {
                    self.data[tmp as usize] = 0x00;
                }
            }

            // Append to the padding the total message's length in bits
            // and transform
            self.bitlen += (self.datalen * 8) as u64;
            self.data[63usize] = ((self.bitlen >> 0 ) & 0xff) as u8;
            self.data[62usize] = ((self.bitlen >> 8 ) & 0xff) as u8;
            self.data[61usize] = ((self.bitlen >> 16) & 0xff) as u8;
            self.data[60usize] = ((self.bitlen >> 24) & 0xff) as u8;
            self.data[59usize] = ((self.bitlen >> 32) & 0xff) as u8;
            self.data[58usize] = ((self.bitlen >> 40) & 0xff) as u8;
            self.data[57usize] = ((self.bitlen >> 48) & 0xff) as u8;
            self.data[56usize] = ((self.bitlen >> 56) & 0xff) as u8;
            self.sha256_transform(self.data);

            // Fix the endian-ness in `hash` because sha uses big endian and 
            // we're using little endian.
            let mut hash: [u8; 32] = [0u8; 32];
            for tmp in 0..4 {
                hash[(tmp + 0 ) as usize] =
                    ((self.state[0usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 4 ) as usize] =
                    ((self.state[1usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 8 ) as usize] =
                    ((self.state[2usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 12) as usize] =
                    ((self.state[3usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 16) as usize] =
                    ((self.state[4usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 20) as usize] =
                    ((self.state[5usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 24) as usize] =
                    ((self.state[6usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
                hash[(tmp + 28) as usize] =
                    ((self.state[7usize] >> (24 - tmp * 8)) & 0x000000ff) as u8;
            }
            hash
        }
    }

    fn rot_left(a: Word, b: Word) -> Word {
        (a << b) | (a >> (32-b))
    }

    fn rot_right(a: Word, b: Word) -> Word {
        (a >> b) | (a << (32-b))
    }

    fn ch(x: Word, y: Word, z: Word) -> Word {
        (x & y) ^ (!x & z)
    }

    fn maj(x: Word, y: Word, z: Word) -> Word {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn ep0(x: Word) -> Word {
        rot_right(x, 2)  ^ 
        rot_right(x, 13) ^ 
        rot_right(x, 22)
    }

    fn ep1(x: Word) -> Word {
        rot_right(x, 6)  ^ 
        rot_right(x, 11) ^ 
        rot_right(x, 25)
    }

    fn sig0(x: Word) -> Word {
        rot_right(x, 7)  ^
        rot_right(x, 18) ^
        (x >> 3)
    }

    fn sig1(x: Word) -> Word {
        rot_right(x, 17) ^
        rot_right(x, 19) ^
        (x >> 10)
    }
}

use std::collections::HashMap;
use std::path::{ Path, PathBuf };

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
    HexifyError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::IoError(e) => {
                return write!(f, "IoError({e})");
            },
            Self::HexifyError(e) => {
                return write!(f, "HexifyError({e})");
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(d: std::io::Error) -> Self {
        Self::IoError(d)
    }
}

struct HashedPath {
    path: PathBuf,
    hash: [u8; 32],
}

// TODO: Implement a sha-256 hashsum rather than `std::hash::DefaultHasher`

use crate::hashing::Sha256Hasher;
use std::collections::VecDeque;

fn hexify(data: Vec<u8>) -> Option<String> {
    let mut data: VecDeque<u8> = data.clone().into();
    let mut out: String = String::with_capacity(2 + data.len() * 2);
    out += "0x";
    for i in 0..data.len() {
        let byte: u8 = data.pop_front()?;
        let vals: [u8; 2] = [
            byte / 0x10u8,
            byte % 0x10u8,
        ];
        for val in vals {
            out += match val {
                0x00 => {"0"},
                0x01 => {"1"},
                0x02 => {"2"},
                0x03 => {"3"},
                0x04 => {"4"},
                0x05 => {"5"},
                0x06 => {"6"},
                0x07 => {"7"},
                0x08 => {"8"},
                0x09 => {"9"},
                0x0A => {"A"},
                0x0B => {"B"},
                0x0C => {"C"},
                0x0D => {"D"},
                0x0E => {"E"},
                0x0F => {"F"},
                0x10..=0xFF => {unreachable!()},
            };
        }
    }
    Some(out)
}

fn main() -> Result<(), Error> {
    let mut new_hashes: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
    let p = Path::new(".");
    let files = gen_dir_tree(p)?;

    for file in files {
        if file.is_dir() { continue; }
        let data: Vec<u8> = std::fs::read(file.clone())?;
        let mut sha_hasher = Sha256Hasher::sha256_init();
        sha_hasher.sha256_update(data.clone());
        let sha_hashed_path = HashedPath {
            path: file.clone(),
            hash: sha_hasher.sha256_final(),
        };
        if new_hashes.contains_key(&sha_hashed_path.hash) {
            let mut tmp = new_hashes.get(&sha_hashed_path.hash).unwrap().clone();
            tmp.push(sha_hashed_path.path);
            new_hashes.insert(sha_hashed_path.hash, tmp);
        } else {
            let mut tmp: Vec<PathBuf> = Vec::new();
            tmp.push(sha_hashed_path.path);
            new_hashes.insert(sha_hashed_path.hash, tmp.to_vec());
        }
    }

    let sha_keys: Vec<&[u8; 32]> = new_hashes.keys().collect();
    for k in sha_keys {
        let v: &Vec<PathBuf> = new_hashes.get(k).unwrap();
        if v.len() > 1 {
            println!("Hash: {} {v:#?}", hexify(k.to_vec()).ok_or(
                     Error::HexifyError("Failed to Hexify key".to_owned()))?
            );
        }
    }

    Ok(())
}
