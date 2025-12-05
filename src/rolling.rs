use std::io::{self, Read, BufRead, BufReader};

use bitcoin_hashes::{sha256, HashEngine};

#[derive(Debug)]
pub struct RollingHasher<R> {
    src: R,
    buf: [u8; 64],
    buf_len: usize,
    hasher: sha256::HashEngine,
}

impl<R: Read> RollingHasher<R> {
    pub fn new(src: R) -> Self {
        Self {
            src,
            buf: [0u8; _],
            buf_len: 0,
            hasher: sha256::HashEngine::new(),
        }
    }

    pub fn hash_to_end(&mut self) -> io::Result<([u8; 32], u64, sha256::Hash)> {
        loop {
            loop {
                let mut dst = &mut self.buf[self.buf_len .. ];
                match self.src.read(dst) {
                    Ok(len) => {
                        self.buf_len += len;
                        break
                    },
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                        continue
                    },
                    Err(err) => {
                        return Err(err);
                    }
                }
            }

            let block = &self.buf[0 .. self.buf_len];

            if block.len() < 64 {
                let (midstate, _midstate_idx) = self.hasher.midstate().expect("block aligned")
                                                           .to_parts();

                let mut tail_hasher = self.hasher.clone();
                tail_hasher.input(block);

                let idx = tail_hasher.n_bytes_hashed();
                break Ok((
                    midstate,
                    idx,
                    tail_hasher.finalize()
                ))
            } else {
                // hash an entire block
                self.hasher.input(block);
                self.buf_len = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Write;

    use tempfile;

    #[test]
    fn test_empty_file() -> Result<(), Box<dyn std::error::Error>> {
        let empty_midstate = [106, 9, 230, 103, 187, 103, 174, 133, 60, 110, 243, 114, 165, 79, 245, 58, 81, 14, 82, 127, 155, 5, 104, 140, 31, 131, 217, 171, 91, 224, 205, 25];

        let (r, f) = tempfile::NamedTempFile::new()?.into_parts();
        let mut w = File::options().write(true).open(f)?;

        let mut hasher = RollingHasher::new(r);

        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, empty_midstate);
        assert_eq!(idx, 0);
        assert_eq!(digest, sha256::Hash::hash(b""));

        // repeated hash_to_end's return the same thing
        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, empty_midstate);
        assert_eq!(idx, 0);
        assert_eq!(digest, sha256::Hash::hash(b""));


        w.write_all(b"0")?;

        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, empty_midstate);
        assert_eq!(idx, 1);
        assert_eq!(digest, sha256::Hash::hash(b"0"));

        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, empty_midstate);
        assert_eq!(idx, 1);
        assert_eq!(digest, sha256::Hash::hash(b"0"));


        w.write_all(b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")?;

        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, empty_midstate);
        assert_eq!(idx, 63);
        assert_eq!(digest, sha256::Hash::hash(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"));

        w.write_all(b"f")?;
        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, [186, 92, 223, 108, 14, 107, 81, 146, 107, 129, 28, 181, 129, 167, 150, 15, 153, 147, 13, 7, 87, 133, 91, 142, 55, 111, 223, 217, 117, 142, 224, 87]);
        assert_eq!(idx, 64);
        assert_eq!(digest, sha256::Hash::hash(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

        w.write_all(b"0")?;
        let (midstate, idx, digest) = hasher.hash_to_end()?;
        assert_eq!(midstate, [186, 92, 223, 108, 14, 107, 81, 146, 107, 129, 28, 181, 129, 167, 150, 15, 153, 147, 13, 7, 87, 133, 91, 142, 55, 111, 223, 217, 117, 142, 224, 87]);
        assert_eq!(idx, 65);
        assert_eq!(digest, sha256::Hash::hash(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"));

        Ok(())
    }
}
