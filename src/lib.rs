use std::error;
use std::fs::File;
use std::io::{self, Read, BufRead, BufReader};
use std::path::Path;

use breccia::{self, Breccia, BrecciaMut};
use bitcoin_hashes::{HashEngine, sha256};
use thiserror::Error;
use opentimestamps::timestamp::Timestamp;

pub mod rolling;

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

    pub fn deserialiez(r: &mut impl io::Read) -> io::Result<Self> {
        let mut idx = [0u8; 8];
        r.read_exact(&mut idx[..])?;
        let idx = u64::from_le_bytes(idx);

        let mut midstate = [0u8; 32];
        r.read_exact(&mut midstate[..])?;

        let mut digest = [0u8; 32];
        r.read_exact(&mut digest[..])?;
        let digest = sha256::Hash::from_byte_array(digest);

        let timestamp = Timestamp::deserialize(digest, r).expect("FIXME");
        Ok(Self { idx, midstate, timestamp })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct Header {
}

#[derive(Debug, Error)]
#[error("Unknown major version {major}")]
struct HeaderError {
    major: u8,
}

impl breccia::Header for Header {
    const MAGIC: &[u8] = b"\x00OpenTimestamps\x00Proof Log";
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
}

/*
pub fn hash_file(reader: &mut impl Read) -> io::Result<(sha256::Midstate, ArrayVec<u8, 63>)> {
    let mut buf = BufReader::new(reader);

    let mut hasher = sha256::HashEngine::new();

    loop {
        if dbg!(buf.buffer().len()) < 64 {
            buf.fill_buf()?;
        };

        if dbg!(buf.buffer().len()) < 64 {
            // we are at the end of the file
            break Ok((
                hasher.midstate().expect("block aligned"),
                ArrayVec::try_from(buf.buffer()).expect("less than 64 bytes"),
            ))
        } else {
            // hash an entire block
            let mut block = [0u8; 64];
            buf.read_exact(&mut block)?;
            hasher.input(&block);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempfile;

    #[test]
    fn create() -> io::Result<()> {
        let journal = JournalMut::create_from_file(tempfile()?)?;

        dbg!(&journal);
        Ok(())
    }

    #[test]
    fn default_midstate() {
        let engine = sha256::HashEngine::new();
        dbg!(engine.midstate().unwrap().to_parts());

        dbg!(sha256::Midstate::default());
    }

    #[test]
    fn hash_file_fn() {
        let empty_midstate = sha256::HashEngine::new().midstate().unwrap();

        /*
        let mut buf: &[u8] = b"";
        let (midstate, remainder) = hash_file(&mut buf).unwrap();
        assert_eq!(midstate, empty_midstate);
        assert_eq!(&remainder[..], b"");

        let mut buf: &[u8] = b"a";
        let (midstate, remainder) = hash_file(&mut buf).unwrap();
        assert_eq!(midstate, empty_midstate);
        assert_eq!(&remainder[..], b"a");
        */

        let mut buf: &[u8] = b"0123456789abcdef0123456789abcdef";
        let (midstate, remainder) = hash_file(&mut buf).unwrap();
        assert_eq!(midstate, empty_midstate);
        assert_eq!(&remainder[..], b"0123456789abcdef0123456789abcdef");
    }
}
*/
