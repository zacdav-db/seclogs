use seclog_core::event::Event;
use seclog_core::traits::EventWriter;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

pub struct JsonlWriter {
    dir: PathBuf,
    target_size_bytes: u64,
    current_size: u64,
    file_index: u64,
    file: BufWriter<File>,
}

impl JsonlWriter {
    pub fn new(dir: impl Into<PathBuf>, target_size_mb: u64) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let file_index = 1;
        let file = open_file(&dir, file_index)?;
        Ok(Self {
            dir,
            target_size_bytes: target_size_mb.saturating_mul(1024 * 1024),
            current_size: 0,
            file_index,
            file,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file_index += 1;
        self.file = open_file(&self.dir, self.file_index)?;
        self.current_size = 0;
        Ok(())
    }
}

impl EventWriter for JsonlWriter {
    fn write_event(&mut self, event: &Event) -> io::Result<u64> {
        let mut buffer =
            serde_json::to_vec(event).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        buffer.push(b'\n');

        if self.current_size > 0 && self.current_size + buffer.len() as u64 > self.target_size_bytes
        {
            self.rotate()?;
        }

        self.file.write_all(&buffer)?;
        self.current_size += buffer.len() as u64;
        Ok(buffer.len() as u64)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    fn close(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn open_file(dir: &Path, index: u64) -> io::Result<BufWriter<File>> {
    let path = dir.join(format!("events-{index:06}.jsonl"));
    let file = File::create(path)?;
    Ok(BufWriter::new(file))
}
