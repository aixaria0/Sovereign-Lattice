use bls12_381::{G1Affine, G1Projective};
use group::Curve;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};

pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    pub fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
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
        let mut buf = Vec::with_capacity(101);
        buf.extend_from_slice(&view.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.push(phase);
        buf.extend_from_slice(&sender_id.to_be_bytes());
        buf.extend_from_slice(digest);
        buf.extend_from_slice(&signature.to_affine().to_compressed());

        let len = (buf.len() as u32).to_be_bytes();
        self.file.write_all(&len)?;
        self.file.write_all(&buf)?;
        
        self.file.sync_data()?;
        
        Ok(())
    }

    pub fn replay_log<F>(&mut self, mut callback: F) -> io::Result<()>
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective),
    {
        self.file.seek(io::SeekFrom::Start(0))?;

        loop {
            let mut len_bytes = [0u8; 4];
            match self.file.read_exact(&mut len_bytes) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            let len = u32::from_be_bytes(len_bytes) as usize;
            let mut buf = vec![0u8; len];
            self.file.read_exact(&mut buf)?;

            if len < 101 {
                continue;
            }

            let view = u64::from_be_bytes(buf[0..8].try_into().unwrap());
            let seq = u64::from_be_bytes(buf[8..16].try_into().unwrap());
            let phase = buf[16];
            let sender_id = u32::from_be_bytes(buf[17..21].try_into().unwrap());
            
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&buf[21..53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&buf[53..101]);
            let sig_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
            
            if let Some(aff) = sig_opt {
                callback(view, seq, phase, sender_id, digest, G1Projective::from(aff));
            }
        }
        
        self.file.seek(io::SeekFrom::End(0))?;
        Ok(())
    }
}
