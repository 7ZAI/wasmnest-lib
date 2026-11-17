//! 模型目录：catalog 是宿主固定资产，不是插件可写配置
//!
//! 每个条目描述一个 whisper.cpp GGML 模型：文件名、下载 URL、SHA-256、体积、
//! 支持语种与推荐位。下载源只来自本目录（宿主可配镜像前缀），插件只拿 id。
//!
//! 模型来自 `ggerganov/whisper.cpp` 的官方 GGML 发布物；SHA-256 与发布方 LFS
//! 元数据一致，下载落盘前由宿主校验。

/// 模型条目（catalog 的只读投影）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelEntry {
    /// 稳定 id（catalog 键）
    pub id: &'static str,
    /// 人类可读名称
    pub name: &'static str,
    /// 一句话说明
    pub description: &'static str,
    /// 落盘文件名
    pub filename: &'static str,
    /// 下载 URL（镜像模式下只替换目录前缀）
    pub url: &'static str,
    /// 期望 SHA-256（小写十六进制）
    pub sha256: &'static str,
    /// 体积（字节，发布方元数据）
    pub size_bytes: u64,
    /// 支持语种（ISO 639-1；多语模型给常用集合）
    pub languages: &'static [&'static str],
    /// 是否推荐
    pub recommended: bool,
}

/// 多语 Whisper 的常用语种（catalog 展示用；不是能力上限）
const MULTILINGUAL: &[&str] = &[
    "zh", "en", "ja", "ko", "fr", "de", "es", "ru", "pt", "it", "ar", "hi",
];

/// 宿主固定模型目录
pub const CATALOG: &[ModelEntry] = &[
    ModelEntry {
        id: "base",
        name: "Whisper Base (multilingual)",
        description: "体积最小、速度最快；中文精度有限，仅建议低配设备试用。",
        filename: "ggml-base.bin",
        url: "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.bin",
        sha256: "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe",
        size_bytes: 147_951_465,
        languages: MULTILINGUAL,
        recommended: false,
    },
    ModelEntry {
        id: "small",
        name: "Whisper Small (multilingual)",
        description: "中英文的默认平衡档：精度与速度兼顾，约 0.5 GB。",
        filename: "ggml-small.bin",
        url: "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-small.bin",
        sha256: "1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b",
        size_bytes: 487_601_967,
        languages: MULTILINGUAL,
        recommended: true,
    },
    ModelEntry {
        id: "turbo",
        name: "Whisper Large v3 Turbo",
        description: "更高精度，CPU 推理明显更慢、体积约 1.6 GB；适合质量优先。",
        filename: "ggml-large-v3-turbo.bin",
        url: "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3-turbo.bin",
        sha256: "1fc70f774d38eb169993ac391eea357ef47c88757ef72ee5943879b7e8e2bc69",
        size_bytes: 1_624_555_275,
        languages: MULTILINGUAL,
        recommended: false,
    },
];

/// 默认推荐模型（catalog 里必须存在）
pub fn default_model() -> &'static ModelEntry {
    CATALOG
        .iter()
        .find(|entry| entry.recommended)
        .expect("catalog must contain a recommended model")
}

/// 按 id 查找模型
pub fn find_model(id: &str) -> Option<&'static ModelEntry> {
    CATALOG.iter().find(|entry| entry.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_ids_and_filenames_are_unique() {
        let mut ids = HashSet::new();
        let mut files = HashSet::new();
        for entry in CATALOG {
            assert!(ids.insert(entry.id), "duplicate model id: {}", entry.id);
            assert!(
                files.insert(entry.filename),
                "duplicate model filename: {}",
                entry.filename
            );
        }
    }

    #[test]
    fn hashes_are_lowercase_sha256() {
        for entry in CATALOG {
            assert_eq!(entry.sha256.len(), 64, "{}: bad sha256 length", entry.id);
            assert!(
                entry
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{}: sha256 must be lowercase hex",
                entry.id
            );
        }
    }

    #[test]
    fn default_model_is_recommended_and_findable() {
        let model = default_model();
        assert!(model.recommended);
        assert_eq!(find_model(model.id).map(|entry| entry.id), Some(model.id));
    }

    #[test]
    fn unknown_model_is_none() {
        assert!(find_model("does-not-exist").is_none());
    }
}
