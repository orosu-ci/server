use crate::api::FileAttachment;
use anyhow::Context;
use glob::glob;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileChunk {
    pub offset: usize,
    pub data: Vec<u8>,
}

pub struct AttachedFiles {
    paths: Vec<PathBuf>,
}

pub struct FileChunkResult {
    pub chunks: Vec<FileChunk>,
    pub hash: Vec<u8>,
    pub size: usize,
}

impl From<&FileChunkResult> for FileAttachment {
    fn from(files: &FileChunkResult) -> Self {
        Self {
            hash: files.hash.clone(),
            size: files.size,
        }
    }
}

impl AttachedFiles {
    pub fn from_input(input: Vec<String>) -> Self {
        tracing::debug!("Creating archive from input: {:?}", input);
        let paths = {
            let input = input.iter().map(|e| e.trim()).filter(|e| !e.is_empty());
            let mut result = Vec::new();
            for arg in input {
                let paths = glob(arg);
                let Ok(paths) = paths else {
                    tracing::warn!("Cannot glob path: {}", arg);
                    continue;
                };
                for path in paths.flatten() {
                    result.push(path);
                }
            }
            tracing::debug!("Archive paths: {:?}", result);
            result
        };
        Self { paths }
    }

    fn archive(&self) -> anyhow::Result<File> {
        let file = NamedTempFile::with_suffix(".zip").context("cannot create temporary file")?;
        let mut writer = zip::ZipWriter::new(file);
        for path in &self.paths {
            let Some(file_name) = path.file_name() else {
                continue;
            };
            let file_name = file_name
                .to_str()
                .context("cannot convert file name to string")?;
            writer.start_file(String::from(file_name), SimpleFileOptions::default())?;
            let mut f = File::open(path).context("cannot open file")?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer).context("cannot read file")?;
            writer.write_all(&buffer).context("cannot write file")?;
        }
        let output = writer.finish().context("cannot finish writing archive")?;
        tracing::debug!("Archive saved to {output:?}");
        Ok(output.into_file())
    }

    pub fn chunks(&self, chunk_size_bytes: usize) -> anyhow::Result<FileChunkResult> {
        let mut archive = self.archive()?;
        let mut buffer = Vec::new();
        archive
            .seek(std::io::SeekFrom::Start(0))
            .context("cannot seek archive file")?;
        archive
            .read_to_end(&mut buffer)
            .context("cannot read archive file")?;

        let hasher = md5::compute(buffer.as_slice());
        let hash = hasher.0.to_vec();

        let mut chunks = Vec::new();
        let mut offset = 0;

        while offset < buffer.len() {
            let end = std::cmp::min(offset + chunk_size_bytes, buffer.len());
            let data = buffer[offset..end].to_vec();

            chunks.push(FileChunk { offset, data });

            offset = end;
        }

        tracing::debug!(
            "Archive chunks created, got {} chunks of {} bytes total",
            chunks.len(),
            buffer.len()
        );

        Ok(FileChunkResult {
            chunks,
            hash,
            size: buffer.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_file(dir: &std::path::Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn from_input_ignores_blank_and_whitespace_only_entries() {
        let attached = AttachedFiles::from_input(vec!["   ".to_string(), "".to_string()]);
        assert!(attached.paths.is_empty());
    }

    #[test]
    fn from_input_globs_and_flattens_matches() {
        let dir = tempfile::tempdir().unwrap();
        write_temp_file(dir.path(), "a.txt", b"a");
        write_temp_file(dir.path(), "b.txt", b"b");
        write_temp_file(dir.path(), "c.dat", b"c");

        let pattern = format!("{}/*.txt", dir.path().display());
        let attached = AttachedFiles::from_input(vec![pattern]);

        let names: Vec<_> = attached
            .paths
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
    }

    #[test]
    fn from_input_skips_a_pattern_that_matches_nothing_without_erroring() {
        let attached = AttachedFiles::from_input(vec!["/nonexistent/path/*.nope".to_string()]);
        assert!(attached.paths.is_empty());
    }

    #[test]
    fn chunks_hash_matches_an_independently_computed_md5_of_the_full_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_temp_file(
            dir.path(),
            "sample.txt",
            b"hello world, this is a test attachment",
        );
        let attached = AttachedFiles { paths: vec![file] };

        let result = attached.chunks(65536).unwrap();
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].offset, 0);
        assert_eq!(result.chunks[0].data.len(), result.size);

        let recomputed = md5::compute(&result.chunks[0].data).0.to_vec();
        assert_eq!(recomputed, result.hash);
    }

    #[test]
    fn chunks_are_contiguous_and_the_last_one_may_be_short() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_temp_file(dir.path(), "sample.txt", &[b'X'; 100]);
        let attached = AttachedFiles { paths: vec![file] };

        let result = attached.chunks(30).unwrap();
        assert!(result.chunks.len() > 1);

        let mut offset = 0;
        let mut rebuilt = Vec::new();
        for chunk in &result.chunks {
            assert_eq!(chunk.offset, offset);
            offset += chunk.data.len();
            rebuilt.extend_from_slice(&chunk.data);
        }
        assert_eq!(offset, result.size);
        assert_eq!(md5::compute(&rebuilt).0.to_vec(), result.hash);

        let last = result.chunks.last().unwrap();
        assert!(last.data.len() <= 30);
        for chunk in &result.chunks[..result.chunks.len() - 1] {
            assert_eq!(chunk.data.len(), 30);
        }
    }

    #[test]
    fn archive_flattens_paths_to_basenames_in_the_zip() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let file = write_temp_file(&nested, "deep.txt", b"content");

        let attached = AttachedFiles { paths: vec![file] };
        let result = attached.chunks(65536).unwrap();
        let full_buffer: Vec<u8> = result.chunks.iter().flat_map(|c| c.data.clone()).collect();

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(full_buffer)).unwrap();
        assert_eq!(archive.len(), 1);
        let entry = archive.by_index(0).unwrap();
        assert_eq!(entry.name(), "deep.txt");
    }

    // Unlike the JS action (client/src/files.js), which treats "no files
    // matched" as "no attachment at all" and never builds a zip, the
    // server-side archive() has no such short-circuit — a zero-file
    // AttachedFiles still produces a valid (if tiny) zip archive with just
    // end-of-central-directory overhead.
    #[test]
    fn chunks_on_zero_matched_files_still_produces_a_valid_small_archive() {
        let attached = AttachedFiles { paths: vec![] };
        let result = attached.chunks(65536).unwrap();
        assert_eq!(result.chunks.len(), 1);
        assert!(result.size > 0);
        let archive =
            zip::ZipArchive::new(std::io::Cursor::new(result.chunks[0].data.clone())).unwrap();
        assert_eq!(archive.len(), 0);
    }

    #[test]
    fn file_attachment_from_chunk_result_captures_hash_and_size() {
        let result = FileChunkResult {
            chunks: vec![],
            hash: vec![9, 9, 9],
            size: 123,
        };
        let attachment: FileAttachment = (&result).into();
        assert_eq!(attachment.hash, vec![9, 9, 9]);
        assert_eq!(attachment.size, 123);
    }
}
