#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileChunk {
    pub offset: usize,
    pub data: Vec<u8>,
}
