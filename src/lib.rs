use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

use breccia::{self, Breccia, BrecciaMut};
use bitcoin_hashes::{HashEngine, sha256};
use thiserror::Error;
use opentimestamps::timestamp::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The position within the source file that the timestamp corresponds to.
    idx: u64,

    /// The most recent midstate as of `idx`.
    ///
    /// SHA245 Midstates are only computed every 64 bytes, so this corresponds to the midstate at
    /// `idx % 64`.
    midstate: [u8; 32],

    /// The timestamp proof itself.
    ///
    /// The digest is serialized, allowing entries to be consistency checked.
    timestamp: Timestamp<sha256::Hash>,
}

impl Entry {
    pub fn serialize(&self, w: &mut impl io::Write) -> io::Result<()> {
        w.write_all(&self.idx.to_le_bytes())?;
        w.write_all(&self.midstate[..])?;
        w.write_all(self.timestamp.msg().as_ref())?;
        self.timestamp.serialize(w)
    }

    pub fn deserialize(r: &mut impl io::Read) -> io::Result<Self> {
        let mut idx = [0u8; 8];
        r.read_exact(&mut idx[..])?;
        let idx = u64::from_le_bytes(idx);

        if idx % 64 != 0 {
            todo!("handle index being not a multiple of 64");
        }

        let mut midstate = [0u8; 32];
        r.read_exact(&mut midstate[..])?;

        let mut digest = [0u8; 32];
        r.read_exact(&mut digest[..])?;
        let digest = sha256::Hash::from_byte_array(digest);

        let timestamp = Timestamp::deserialize(digest, r).expect("FIXME: handle timestamp deserialization error");
        Ok(Self { idx, midstate, timestamp })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct Header {
    // empty: only supported major version is 0
}

#[derive(Debug, Error)]
#[error("Unknown major version {major}")]
struct HeaderError {
    major: u8,
}

impl breccia::Header for Header {
    const MAGIC: &[u8] = b"\x00OpenTimestamps\x00Proof Log\x00\xc2\xa4\x31\x2e\xbb";
    const SERIALIZED_SIZE: usize = 1;

    fn serialize(&self, dst: &mut [u8]) {
        dst[0] = 0;
    }

    type DeserializeError = HeaderError;
    fn deserialize(src: &[u8]) -> Result<Self, HeaderError> {
        match src[0] {
            0 => Ok(Self {}),
            major => Err(HeaderError { major })
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Journal {
    breccia: Breccia<Header>,
}

#[derive(Debug)]
pub struct JournalMut {
    breccia: BrecciaMut<Header>,
}

impl std::ops::Deref for JournalMut {
    type Target = Journal;

    fn deref(&self) -> &Journal {
        // SAFETY: Journal is repr(transparent)
        unsafe {
            &*(&*self.breccia as *const Breccia<Header> as *const Journal)
        }
    }
}

pub enum GetEntryError {
}

impl Journal {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let breccia = Breccia::open(path)?;
        Ok(Self {
            breccia
        })
    }

    pub fn get_entry(&self, _idx: usize) -> Result<Entry, GetEntryError> {
        todo!()
    }
}

impl JournalMut {
    pub fn create_from_file(fd: File) -> io::Result<Self> {
        Ok(Self {
            breccia: BrecciaMut::create_from_file(fd, Header {})?,
        })
    }

    pub fn write_entry(&mut self, entry: &Entry) -> io::Result<()> {
        let mut blob = vec![];
        entry.serialize(&mut blob).expect("Write implementation on Vec can't fail");

        let _ = self.breccia.write_blob(&*blob)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct IncrementalHasher<F> {
    fd: F,
    midstate: [u8; 32],
    hasher: sha256::HashEngine,
}

impl<F> IncrementalHasher<F> {
    fn input(&mut self, buf: &[u8]) {
        let partial_block_len = self.hasher.n_bytes_hashed() % 64;
        let len_to_full_block = 64 - partial_block_len;

        if let Some((partial, remainder)) = buf.split_at_checked(len_to_full_block.try_into().expect("64 to fit in usize")) {
            self.hasher.input(partial);
            let (new_midstate, _) = self.hasher.midstate().expect("midstate available").to_parts();
            self.midstate = new_midstate;

            let blocks_in_remainder = remainder.len() / 64;
            let (full_blocks, remainder) = remainder.split_at(blocks_in_remainder * 64);

            if full_blocks.len() > 0 {
                self.hasher.input(full_blocks);
                let (new_midstate, _) = self.hasher.midstate().expect("midstate available").to_parts();
                self.midstate = new_midstate;
            }

            self.hasher.input(remainder);
        } else {
            self.hasher.input(buf);
        }
    }

    pub fn new(fd: F) -> Self {
        let hasher = sha256::HashEngine::new();
        let (midstate, _) = hasher.midstate().expect("midstate available").to_parts();
        Self {
            fd,
            midstate,
            hasher,
        }
    }

    pub fn n_bytes_hashed(&self) -> u64 {
        self.hasher.n_bytes_hashed()
    }

    pub fn finalize(&self) -> sha256::Hash {
        self.hasher.clone().finalize()
    }
}

impl<F: Read + Seek> IncrementalHasher<F> {
    pub fn from_fd_at_idx(mut fd: F, idx: u64, state: [u8; 32]) -> io::Result<Self> {
        let fd_len = fd.seek(SeekFrom::End(0))?;

        if fd_len > idx {
            todo!("fd was truncated");
        }

        let block_aligned_idx = (idx / 64) * 64;
        fd.seek(SeekFrom::Start(block_aligned_idx))?;

        let mut partial_block = [0u8; 64];
        let partial_block = &mut partial_block[0 .. (idx - block_aligned_idx).try_into().unwrap()];
        fd.read_exact(partial_block)?;

        let midstate = sha256::Midstate::new(state, block_aligned_idx);
        let mut hasher = sha256::HashEngine::from_midstate(midstate);
        hasher.input(partial_block);

        Ok(Self { fd, midstate: state, hasher, })
    }
}

impl<F: Read> IncrementalHasher<F> {
    pub const CHUNK_SIZE: usize = 8192;

    pub fn hash_next_chunk(&mut self) -> io::Result<Option<(sha256::Midstate, sha256::Hash, u64)>> {
        const N: usize = 8192;

        let mut chunk = [0u8; N];
        let mut remaining_chunk = &mut chunk[..];

        while remaining_chunk.len() > 0 {
            match self.fd.read(remaining_chunk) {
                Ok(0) => {
                    break
                },
                Ok(len_read) => {
                    remaining_chunk = &mut remaining_chunk[len_read .. ];
                },
                Err(err) if err.kind() == ErrorKind::Interrupted => {
                    continue
                },
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                    break
                },
                Err(err) => {
                    return Err(err);
                }
            }
        };

        let remaining_chunk_len = remaining_chunk.len();
        let chunk = &chunk[0 .. N - remaining_chunk_len];
        self.input(chunk);

        if remaining_chunk_len > 0 {
            let midstate = sha256::Midstate::new(self.midstate, (self.n_bytes_hashed() / 64) * 64);
            Ok(Some((midstate, self.finalize(), self.n_bytes_hashed())))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::OpenOptions;
    use std::io::Write;

    use tempfile::{tempfile, NamedTempFile};

    #[test]
    fn create() -> io::Result<()> {
        let journal = JournalMut::create_from_file(tempfile()?)?;

        dbg!(&journal);
        Ok(())
    }

    #[test]
    fn incremental_hasher_input() {
        for l in 0 .. 129 {
            let buf = vec![0; l];

            for j in 0 .. l {
                let mut hasher = IncrementalHasher::new(());
                assert_eq!(sha256::Hash::hash(&[]), hasher.finalize());

                let (first, last) = buf.split_at(j);

                hasher.input(first);
                assert_eq!(sha256::Hash::hash(first), hasher.finalize());

                hasher.input(last);
                assert_eq!(sha256::Hash::hash(&buf[..]), hasher.finalize());
            }
        }
    }

    #[test]
    fn incremental_hasher_on_file() -> io::Result<()> {
        let log_temp_file = NamedTempFile::new()?;

        let mut log_write_fd = OpenOptions::new().write(true).open(log_temp_file.path())?;

        let mut hasher = IncrementalHasher::new(File::open(log_temp_file.path())?);

        let mut expected = vec![];

        let empty_midstate = sha256::HashEngine::new().midstate().unwrap();
        let empty_hash = sha256::Hash::hash(&*expected);
        assert_eq!(hasher.hash_next_chunk()?,
                   Some((empty_midstate, empty_hash, 0)));
        assert_eq!(hasher.finalize(), empty_hash);

        expected.push(0u8);
        let _ = log_write_fd.write_all(&[0]);
        assert_eq!(hasher.hash_next_chunk()?,
                   Some((empty_midstate, sha256::Hash::hash(&*expected), 1)));

        expected.extend(&[1,2,3,4,5,6,7,8,9]);
        let _ = log_write_fd.write_all(&[1,2,3,4,5,6,7,8,9]);
        assert_eq!(hasher.hash_next_chunk()?,
                   Some((empty_midstate, sha256::Hash::hash(&*expected), 10)));

        expected.extend(vec![0; 54]);
        let _ = log_write_fd.write_all(&[0; 54]);
        let mut engine = sha256::HashEngine::new();
        engine.input(&*expected);
        let expected_midstate = engine.midstate().unwrap();

        assert_eq!(hasher.hash_next_chunk()?,
                   Some((expected_midstate, sha256::Hash::hash(&*expected), 64)));

        expected.push(1);
        let _ = log_write_fd.write_all(&[1]);
        assert_eq!(hasher.hash_next_chunk()?,
                   Some((expected_midstate, sha256::Hash::hash(&*expected), 65)));

        Ok(())
    }
}
