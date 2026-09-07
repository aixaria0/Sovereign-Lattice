use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use bls12_381::{G1Affine, G1Projective};
use group::Curve;

pub struct WriteAheadLog {
    file: File,
    pub path: PathBuf,
}

impl WriteAheadLog {
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
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
        })
    }

    pub fn append_entry(
        &mut self,
        view: u64,
        seq: u64,
        phase: u8,
        sender_id: u32,
        digest: &[u8; 32],
        signature: &G1Projective,
    ) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(8 + 8 + 1 + 4 + 32 + 48);
        buf.extend_from_slice(&view.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.push(phase);
        buf.extend_from_slice(&sender_id.to_be_bytes());
        buf.extend_from_slice(digest);
        buf.extend_from_slice(&signature.to_affine().to_compressed());
        self.file.write_all(&buf)?;
        self.file.flush()
    }

    pub fn replay_log<F>(&mut self, mut handler: F) -> std::io::Result<()>
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective),
    {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        let mut buf = [0u8; 101];
        while file.read_exact(&mut buf).is_ok() {
            let view = u64::from_be_bytes(buf[0..8].try_into().unwrap());
            let seq = u64::from_be_bytes(buf[8..16].try_into().unwrap());
            let phase = buf[16];
            let sender_id = u32::from_be_bytes(buf[17..21].try_into().unwrap());
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&buf[21..53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&buf[53..101]);

            let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
            if let Some(aff) = affine_opt {
                handler(view, seq, phase, sender_id, digest, G1Projective::from(aff));
            }
        }
        Ok(())
    }

    pub fn prune_before(&mut self, min_seq: u64) -> std::io::Result<()> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        let temp_path = self.path.with_extension("prune_tmp");
        let mut temp_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;

        let mut buf = [0u8; 101];
        while file.read_exact(&mut buf).is_ok() {
            let seq = u64::from_be_bytes(buf[8..16].try_into().unwrap());
            if seq >= min_seq {
                temp_file.write_all(&buf)?;
            }
        }
        temp_file.flush()?;
        drop(temp_file);
        drop(file);

        std::fs::rename(&temp_path, &self.path)?;
        self.file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        Ok(())
    }
}
