use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bls12_381::{G1Affine, G1Projective};
use group::Curve;

/// Current WAL record encoding is fixed-width and versionless (101 bytes).
///
/// Durability contract: append_entry returns only after syncing the file data.
/// Replay rejects torn trailing records rather than treating them as clean EOF.
/// A future format migration should add record versioning and checksums.
const RECORD_LEN: usize = 101;

pub struct WriteAheadLog {
    file: File,
    pub path: PathBuf,
    #[cfg(test)]
    fail_next_append: bool,
}

impl WriteAheadLog {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&path_buf)?;
        Ok(Self {
            file,
            path: path_buf,
            #[cfg(test)]
            fail_next_append: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_append_for_test(&mut self) {
        self.fail_next_append = true;
    }

    pub fn append_entry(
        &mut self,
        view: u64,
        seq: u64,
        phase: u8,
        sender_id: u32,
        digest: &[u8; 32],
        signature: &G1Projective,
    ) -> io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_append) {
            return Err(io::Error::new(io::ErrorKind::Other, "injected WAL append failure"));
        }

        let mut buf = Vec::with_capacity(RECORD_LEN);
        buf.extend_from_slice(&view.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.push(phase);
        buf.extend_from_slice(&sender_id.to_be_bytes());
        buf.extend_from_slice(digest);
        buf.extend_from_slice(&signature.to_affine().to_compressed());

        debug_assert_eq!(buf.len(), RECORD_LEN);
        self.file.write_all(&buf)?;
        self.file.sync_data()
    }

    pub fn replay_log<F>(&mut self, mut handler: F) -> io::Result<()>
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective),
    {
        let mut file = File::open(&self.path)?;
        let mut buf = [0u8; RECORD_LEN];

        loop {
            let mut read = 0;
            while read < buf.len() {
                match file.read(&mut buf[read..]) {
                    Ok(0) if read == 0 => return Ok(()),
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("truncated WAL record: read {read} of {RECORD_LEN} bytes"),
                        ));
                    }
                    Ok(n) => read += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            let view = u64::from_be_bytes(buf[0..8].try_into().expect("fixed-width slice"));
            let seq = u64::from_be_bytes(buf[8..16].try_into().expect("fixed-width slice"));
            let phase = buf[16];
            let sender_id = u32::from_be_bytes(buf[17..21].try_into().expect("fixed-width slice"));
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&buf[21..53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&buf[53..101]);
            let affine = Option::<G1Affine>::from(G1Affine::from_compressed(&sig_bytes))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid compressed WAL signature point"))?;

            handler(view, seq, phase, sender_id, digest, G1Projective::from(affine));
        }
    }

    pub fn prune_before(&mut self, min_seq: u64) -> io::Result<()> {
        // Sync pending appends before reading a stable file image.
        self.file.sync_data()?;

        let mut file = File::open(&self.path)?;
        let temp_path = self.path.with_extension("prune_tmp");
        let mut temp_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;

        let mut buf = [0u8; RECORD_LEN];
        loop {
            let mut read = 0;
            while read < buf.len() {
                match file.read(&mut buf[read..]) {
                    Ok(0) if read == 0 => break,
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("truncated WAL record while pruning: read {read} of {RECORD_LEN} bytes"),
                        ));
                    }
                    Ok(n) => read += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if read == 0 {
                break;
            }

            let seq = u64::from_be_bytes(buf[8..16].try_into().expect("fixed-width slice"));
            if seq >= min_seq {
                temp_file.write_all(&buf)?;
            }
        }

        temp_file.sync_all()?;
        drop(temp_file);
        drop(file);

        std::fs::rename(&temp_path, &self.path)?;

        // Reopen the replacement before directory sync. If syncing the directory
        // reports an error, future appends must still target the live WAL path,
        // not the old unlinked inode.
        self.file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        // Sync the parent directory so the rename is persisted on filesystems
        // that support directory fsync. Opening directories is supported on Unix.
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            File::open(parent)?.sync_all()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G1Projective;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("sovereign_lattice_wal_{label}_{}_{}.log", std::process::id(), nonce))
    }

    #[test]
    fn replay_round_trips_valid_record() {
        let path = temp_path("roundtrip");
        let digest = [0x42; 32];
        {
            let mut wal = WriteAheadLog::open(&path).unwrap();
            wal.append_entry(7, 9, 2, 3, &digest, &G1Projective::generator()).unwrap();
        }
        let mut seen = Vec::new();
        let mut wal = WriteAheadLog::open(&path).unwrap();
        wal.replay_log(|view, seq, phase, sender, got_digest, _sig| {
            seen.push((view, seq, phase, sender, got_digest));
        }).unwrap();
        assert_eq!(seen, vec![(7, 9, 2, 3, digest)]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn replay_rejects_torn_trailing_record() {
        let path = temp_path("truncated");
        std::fs::write(&path, [0u8; 17]).unwrap();
        let mut wal = WriteAheadLog::open(&path).unwrap();
        let err = wal.replay_log(|_, _, _, _, _, _| {}).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn replay_rejects_invalid_compressed_point() {
        let path = temp_path("invalid_point");
        let mut bytes = vec![0u8; RECORD_LEN];
        bytes[53..101].copy_from_slice(&[0xff; 48]);
        std::fs::write(&path, bytes).unwrap();
        let mut wal = WriteAheadLog::open(&path).unwrap();
        let err = wal.replay_log(|_, _, _, _, _, _| {}).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn prune_supports_relative_path_without_explicit_parent() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = PathBuf::from(format!(
            ".sovereign_lattice_wal_relative_{}_{}.log",
            std::process::id(),
            nonce
        ));
        {
            let mut wal = WriteAheadLog::open(&path).unwrap();
            wal.append_entry(1, 1, 1, 1, &[9; 32], &G1Projective::generator()).unwrap();
            wal.prune_before(1).unwrap();
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn prune_preserves_records_at_or_after_sequence() {
        let path = temp_path("prune");
        {
            let mut wal = WriteAheadLog::open(&path).unwrap();
            wal.append_entry(1, 1, 1, 1, &[1; 32], &G1Projective::generator()).unwrap();
            wal.append_entry(1, 2, 1, 1, &[2; 32], &G1Projective::generator()).unwrap();
            wal.append_entry(1, 3, 1, 1, &[3; 32], &G1Projective::generator()).unwrap();
            wal.prune_before(2).unwrap();
        }
        let mut seen = Vec::new();
        let mut wal = WriteAheadLog::open(&path).unwrap();
        wal.replay_log(|_, seq, _, _, digest, _| seen.push((seq, digest))).unwrap();
        assert_eq!(seen, vec![(2, [2; 32]), (3, [3; 32])]);
        std::fs::remove_file(path).unwrap();
    }
}
