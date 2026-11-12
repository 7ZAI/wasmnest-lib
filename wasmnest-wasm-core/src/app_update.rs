//! 应用更新源与 GitHub Release 判定（共享纯逻辑；双端宿主与 SDK 同源）
//!
//! 应用版本更新全链路里**不碰网络/不碰 UI** 的那一段：
//! - manifest `update` 声明的解析与来源自证（repo / tag 前缀 / 资产 slug）；
//! - GitHub `/releases` 响应里挑出该应用的最新正式 Release；
//! - Release 元数据 JSON 的身份 / 完整性校验；
//! - 下载参数自证（tag / 资产名 / sha256 三者必须互相吻合）。
//!
//! 网络 I/O、落盘与安装分别留在各端宿主（桌面 `plugin_updates.rs`、移动
//! `plugin/updates.rs`）；宿主应用管理页与 SDK 设置卡共用本模块给出的判定，
//! 避免「检查逻辑」在两端各写一份后漂移。
//!
//! 安全口径：**URL 永远由本模块从 repo + tag + 资产名拼出**，调用方传不进任意
//! URL；repo 只接受 GitHub 的 `owner/name` 形态，tag 前缀 / slug 只接受无路径
//! 分隔符的安全字符。这不是「信任 GitHub」，而是把 SSRF / 任意下载面收窄到
//! 「一个公开仓库的 Release 资产」。

use crate::{AppError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 官方应用仓（`update.repo` 缺省值）
///
/// 官方四个应用（ai-chatbox / bedcode / file-transfer / monitor）的 Release
/// 都发在这里：tag `<slug>-v<X.Y.Z>`，资产 `<slug>-<end>-v<X.Y.Z>.zip` +
/// 同名 `.json` 元数据。
pub const DEFAULT_UPDATE_REPO: &str = "7ZAI/wasmnest-apps";

/// manifest `update` 段（插件自主声明更新源）
///
/// 缺省字段都收敛到官方应用仓的命名约定；第三方应用只需声明自己的 `repo`，
/// 或连 `slug` / `tagPrefix` 一起声明成自己的发布形态。声明即表示应用**参与**
/// 更新检查（缺省无 `update` 段 = 不检查）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginUpdateDecl {
    /// 更新来源类型；当前只支持 `github-release`
    #[serde(default)]
    pub provider: UpdateProvider,
    /// GitHub 仓库 `owner/name`；缺省 = [`DEFAULT_UPDATE_REPO`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Release tag 前缀（完整形态 `<tagPrefix>v<X.Y.Z>`）；缺省 `<slug>-`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_prefix: Option<String>,
    /// Release 资产前缀（`<slug>-<end>-v<version>.zip`）；缺省 = 插件 id 末段
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
}

/// 更新来源类型（未知取值反序列化即拒：宁可装不上，也不静默忽略更新声明）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateProvider {
    /// GitHub Release（`/releases` 列表 + 资产下载）
    #[default]
    GithubRelease,
}

/// 解析后的更新源（repo / tag 前缀 / 资产 slug 都已自证）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUpdateSource {
    pub repo: String,
    pub tag_prefix: String,
    pub slug: String,
}

/// 兼容声明（应用仓构建期盖进 Release 元数据 `compat` 段）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatInfo {
    pub host_runtime: String,
    pub mount_contract: String,
    pub sdk_version: String,
    pub wit_version: String,
}

/// 一个 Release 资产（只保留判定需要的字段）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

/// 挑选出的最新 Release
#[derive(Debug, Clone)]
pub struct PickedRelease {
    pub tag: String,
    pub version: semver::Version,
    pub assets: Vec<ReleaseAsset>,
}

impl AppUpdateSource {
    /// GitHub Release 列表 API（公开仓匿名可读；限流 60 次/h/IP）
    pub fn releases_api_url(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/releases?per_page=100",
            self.repo
        )
    }

    /// 资产下载地址（只由 repo + tag + 已校验资产名拼出）
    pub fn release_download_url(&self, tag: &str, asset: &str) -> String {
        format!(
            "https://github.com/{}/releases/download/{}/{}",
            self.repo, tag, asset
        )
    }

    /// zip 资产名（发布链 `build-app.mjs` 的 `<slug>-<end>-v<version>.zip`）
    pub fn zip_asset_name(&self, end: &str, version: &str) -> String {
        format!("{}-{}-v{}.zip", self.slug, end, version)
    }

    /// 元数据资产名（与 zip 同名、扩展名 `.json`）
    pub fn metadata_asset_name(&self, end: &str, version: &str) -> String {
        format!("{}-{}-v{}.json", self.slug, end, version)
    }
}

/// 解析 manifest `update` 声明；`None` = 应用不参与更新检查
///
/// 校验口径（任一不过 = 显性错误，点名期望与实际）：
/// - repo 必须是 `owner/name`（GitHub 账户 / 仓库字符集），不含路径分隔符；
/// - slug 必须是小写字母数字 + 连字符（用于拼资产名，不能带路径）；
/// - tag 前缀非空、不含 `/`、不含 `..`（拼进下载 URL 的路径段）。
pub fn resolve_update_source(
    decl: Option<&PluginUpdateDecl>,
    plugin_id: &str,
) -> Result<Option<AppUpdateSource>> {
    let Some(decl) = decl else {
        return Ok(None);
    };
    if decl.provider != UpdateProvider::GithubRelease {
        return Err(AppError::Plugin(format!(
            "Plugin '{plugin_id}' declares unsupported update provider {:?}",
            decl.provider
        )));
    }
    let slug = match decl.slug.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(s) => s.trim().to_string(),
        None => plugin_id.rsplit('.').next().unwrap_or_default().to_string(),
    };
    if !is_safe_slug(&slug) {
        return Err(AppError::Plugin(format!(
            "Plugin '{plugin_id}' update.slug '{slug}' is invalid (lowercase alphanumeric / '-')"
        )));
    }
    let repo = decl
        .repo
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_UPDATE_REPO)
        .trim()
        .to_string();
    validate_repo(&repo).map_err(|e| {
        AppError::Plugin(format!(
            "Plugin '{plugin_id}' update.repo '{repo}' is invalid: {e}"
        ))
    })?;
    let tag_prefix = match decl.tag_prefix.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(s) => s.trim().to_string(),
        None => format!("{slug}-"),
    };
    if tag_prefix.contains('/')
        || tag_prefix.contains("..")
        || tag_prefix.chars().any(char::is_whitespace)
    {
        return Err(AppError::Plugin(format!(
            "Plugin '{plugin_id}' update.tagPrefix '{tag_prefix}' is invalid (no '/', '..' or whitespace)"
        )));
    }
    Ok(Some(AppUpdateSource {
        repo,
        tag_prefix,
        slug,
    }))
}

/// GitHub 仓库形态：`owner/name`（两段、非空、无路径分隔符/空白）
fn validate_repo(repo: &str) -> std::result::Result<(), String> {
    let mut parts = repo.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("expected 'owner/name'".to_string());
    };
    if owner.is_empty() || name.is_empty() {
        return Err("expected 'owner/name'".to_string());
    }
    for part in [owner, name] {
        if !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err("only alphanumeric, '-', '_' and '.' are allowed".to_string());
        }
        if part == "." || part == ".." {
            return Err("path segments '.' / '..' are not allowed".to_string());
        }
    }
    Ok(())
}

fn is_safe_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

/// Release tag → 语义化版本（严格 `<tagPrefix>v<X.Y.Z>`；其余 None）
pub fn parse_release_tag(tag: &str, source: &AppUpdateSource) -> Option<semver::Version> {
    let version = tag.strip_prefix(&source.tag_prefix)?.strip_prefix('v')?;
    semver::Version::parse(version).ok()
}

/// 解析版本字符串（manifest 版本 / 元数据版本；非法返回 None，调用方不猜）
pub fn parse_version(version: &str) -> Option<semver::Version> {
    semver::Version::parse(version).ok()
}

/// `candidate` 是否严格新于 `current`（任一形态非法返回 None = 无法判断）
pub fn version_is_newer(candidate: &str, current: &str) -> Option<bool> {
    let candidate = parse_version(candidate)?;
    let current = parse_version(current)?;
    Some(candidate > current)
}

/// 从 GitHub `/releases` 响应挑该应用的最新正式 Release
///
/// 跳过 draft / prerelease；同 slug 多版本取语义化版本最大者。没有任何命中 →
/// 显性错误（点名 slug，不返回空）。
pub fn pick_latest_release(releases: &Value, source: &AppUpdateSource) -> Result<PickedRelease> {
    let arr = releases.as_array().ok_or_else(|| {
        AppError::Internal("GitHub releases response is not an array".to_string())
    })?;
    let mut best: Option<(semver::Version, String, Vec<ReleaseAsset>)> = None;
    for release in arr {
        let Some(obj) = release.as_object() else {
            continue;
        };
        if obj.get("draft").and_then(Value::as_bool) == Some(true)
            || obj.get("prerelease").and_then(Value::as_bool) == Some(true)
        {
            continue;
        }
        let tag = obj
            .get("tag_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(version) = parse_release_tag(tag, source) else {
            continue;
        };
        if best.as_ref().is_some_and(|(v, _, _)| *v >= version) {
            continue;
        }
        let assets = obj
            .get("assets")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|a| {
                        let name = a.get("name")?.as_str()?.to_string();
                        let url = a.get("browser_download_url")?.as_str()?.to_string();
                        let size = a.get("size").and_then(Value::as_u64).unwrap_or(0);
                        Some(ReleaseAsset { name, url, size })
                    })
                    .collect()
            })
            .unwrap_or_default();
        best = Some((version, tag.to_string(), assets));
    }
    let (version, tag, assets) = best.ok_or_else(|| {
        AppError::Plugin(format!(
            "No release found for app '{}' in {} (tag form '{}v<X.Y.Z>')",
            source.slug, source.repo, source.tag_prefix
        ))
    })?;
    Ok(PickedRelease {
        tag,
        version,
        assets,
    })
}

/// 按名取资产；缺失 = 发布链残缺（显性错误，不猜别的资产）
pub fn asset_named<'a>(assets: &'a [ReleaseAsset], name: &str) -> Result<&'a ReleaseAsset> {
    assets.iter().find(|a| a.name == name).ok_or_else(|| {
        AppError::Plugin(format!(
            "Release is missing asset '{name}' (dist incomplete; re-publish the app release)"
        ))
    })
}

/// 64 位小写/大写十六进制 SHA-256
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Release 元数据 JSON 校验 + 字段提取（身份 / 完整性裁决单点）
///
/// 校验口径（任一不过 = 显性错误，点名期望与实际）：
/// - `schema == 1`；`plugin.id == 目标插件 id`；`end == 目标端`；
/// - `plugin.version == tag 解析出的版本`（tag 与包内容不一致 = 发布链被破坏）；
/// - `artifact.file == 期望 zip 资产名`；`artifact.sha256` 为 64 位 hex；
/// - `app` 段若存在必须等于 slug（防止跨应用元数据）；
/// - `compat` 段**缺省合法**（旧发布物）：返回 None，由上层判不兼容。
pub fn validate_release_metadata(
    meta: &Value,
    plugin_id: &str,
    end: &str,
    expected_version: &str,
    source: &AppUpdateSource,
) -> Result<(String, String, u64, Option<CompatInfo>)> {
    let obj = meta
        .as_object()
        .ok_or_else(|| AppError::Plugin("Release metadata is not a JSON object".to_string()))?;
    let get_str = |key: &str| -> Result<&str> {
        obj.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::Plugin(format!("Release metadata missing field '{key}'")))
    };
    if obj.get("schema").and_then(Value::as_i64) != Some(1) {
        return Err(AppError::Plugin(format!(
            "Release metadata schema {:?} is not supported (expected 1)",
            obj.get("schema")
        )));
    }
    if let Some(app) = obj.get("app").and_then(Value::as_str) {
        if app != source.slug {
            return Err(AppError::Plugin(format!(
                "Release metadata app '{app}' does not match expected '{}'",
                source.slug
            )));
        }
    }
    let (Some(plugin), Some(artifact)) = (
        obj.get("plugin").and_then(Value::as_object),
        obj.get("artifact").and_then(Value::as_object),
    ) else {
        return Err(AppError::Plugin(
            "Release metadata missing 'plugin' or 'artifact' section".to_string(),
        ));
    };
    let meta_id = plugin
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Plugin("Release metadata missing 'plugin.id'".to_string()))?;
    if meta_id != plugin_id {
        return Err(AppError::Plugin(format!(
            "Release metadata plugin.id '{meta_id}' does not match requested '{plugin_id}'"
        )));
    }
    if get_str("end")? != end {
        return Err(AppError::Plugin(format!(
            "Release metadata end '{}' is not '{end}'",
            get_str("end")?
        )));
    }
    let meta_version = plugin
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Plugin("Release metadata missing 'plugin.version'".to_string()))?;
    if meta_version != expected_version {
        return Err(AppError::Plugin(format!(
            "Release metadata version '{meta_version}' does not match release tag version '{expected_version}'"
        )));
    }
    let expect_zip = source.zip_asset_name(end, expected_version);
    let artifact_file = artifact
        .get("file")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Plugin("Release metadata missing 'artifact.file'".to_string()))?;
    if artifact_file != expect_zip {
        return Err(AppError::Plugin(format!(
            "Release metadata artifact.file '{artifact_file}' does not match expected '{expect_zip}'"
        )));
    }
    let sha256 = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Plugin("Release metadata missing 'artifact.sha256'".to_string())
        })?;
    if !is_hex64(sha256) {
        return Err(AppError::Plugin(format!(
            "Release metadata artifact.sha256 is not a 64-hex digest: '{sha256}'"
        )));
    }
    let bytes = artifact.get("bytes").and_then(Value::as_u64).unwrap_or(0);
    let compat = obj.get("compat").and_then(|c| {
        Some(CompatInfo {
            host_runtime: c.get("hostRuntime")?.as_str()?.to_string(),
            mount_contract: c.get("mountContract")?.as_str()?.to_string(),
            sdk_version: c.get("sdkVersion")?.as_str()?.to_string(),
            wit_version: c.get("witVersion")?.as_str()?.to_string(),
        })
    });
    Ok((expect_zip, sha256.to_string(), bytes, compat))
}

/// 下载参数自证：tag / 资产名 / 摘要必须两两吻合（URL 只由本模块拼）
pub fn validate_download_args(
    source: &AppUpdateSource,
    end: &str,
    tag: &str,
    zip_asset: &str,
    sha256: &str,
) -> Result<(String, String)> {
    let version = parse_release_tag(tag, source).ok_or_else(|| {
        AppError::InvalidInput(format!(
            "Release tag '{tag}' does not match expected form '{}v<X.Y.Z>'",
            source.tag_prefix
        ))
    })?;
    let expect_zip = source.zip_asset_name(end, &version.to_string());
    if zip_asset != expect_zip {
        return Err(AppError::InvalidInput(format!(
            "Asset name '{zip_asset}' does not match expected '{expect_zip}'"
        )));
    }
    if !is_hex64(sha256) {
        return Err(AppError::InvalidInput(format!(
            "sha256 is not a 64-hex digest: '{sha256}'"
        )));
    }
    Ok((tag.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source() -> AppUpdateSource {
        resolve_update_source(
            Some(&PluginUpdateDecl {
                provider: UpdateProvider::GithubRelease,
                repo: None,
                tag_prefix: None,
                slug: None,
            }),
            "com.wasmnest.file-transfer",
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn default_source_resolves_to_official_repo_and_slug() {
        let s = source();
        assert_eq!(s.repo, DEFAULT_UPDATE_REPO);
        assert_eq!(s.slug, "file-transfer");
        assert_eq!(s.tag_prefix, "file-transfer-");
        assert_eq!(
            s.zip_asset_name("desktop", "0.0.2"),
            "file-transfer-desktop-v0.0.2.zip"
        );
        assert_eq!(
            s.metadata_asset_name("mobile", "0.0.2"),
            "file-transfer-mobile-v0.0.2.json"
        );
    }

    #[test]
    fn custom_source_is_self_certified() {
        let s = resolve_update_source(
            Some(&PluginUpdateDecl {
                provider: UpdateProvider::GithubRelease,
                repo: Some("acme/widgets".to_string()),
                tag_prefix: Some("widgets-release-".to_string()),
                slug: Some("widgets".to_string()),
            }),
            "com.acme.widgets",
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.repo, "acme/widgets");
        assert_eq!(s.tag_prefix, "widgets-release-");
        assert_eq!(s.slug, "widgets");
        assert_eq!(
            parse_release_tag("widgets-release-v1.2.3", &s),
            Some(semver::Version::new(1, 2, 3))
        );
    }

    #[test]
    fn update_source_rejects_unsafe_shapes() {
        let base = PluginUpdateDecl {
            provider: UpdateProvider::GithubRelease,
            repo: None,
            tag_prefix: None,
            slug: None,
        };
        for decl in [
            PluginUpdateDecl {
                repo: Some("https://evil.example/x".to_string()),
                ..base.clone()
            },
            PluginUpdateDecl {
                repo: Some("owner/../name".to_string()),
                ..base.clone()
            },
            PluginUpdateDecl {
                slug: Some("../evil".to_string()),
                ..base.clone()
            },
            PluginUpdateDecl {
                tag_prefix: Some("x/../".to_string()),
                ..base.clone()
            },
        ] {
            assert!(
                resolve_update_source(Some(&decl), "com.wasmnest.x").is_err(),
                "decl must be rejected: {decl:?}"
            );
        }
        // 无声明 = 不参与更新（不是错误）
        assert!(resolve_update_source(None, "com.wasmnest.x")
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_release_tag_is_strict() {
        let s = source();
        assert_eq!(
            parse_release_tag("file-transfer-v0.0.2", &s),
            Some(semver::Version::new(0, 0, 2))
        );
        assert_eq!(parse_release_tag("bedcode-v0.0.2", &s), None);
        assert_eq!(parse_release_tag("file-transfer-v1", &s), None);
        assert_eq!(parse_release_tag("file-transfer-0.0.2", &s), None);
        assert!(parse_release_tag("file-transfer-v0.0.2-rc.1", &s).is_some());
    }

    fn release(tag: &str, draft: bool, prerelease: bool, assets: &[(&str, u64)]) -> Value {
        json!({
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "assets": assets.iter().map(|(n, s)| json!({
                "name": n, "browser_download_url": format!("https://example.com/{n}"), "size": s
            })).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn pick_latest_release_takes_highest_version_and_skips_drafts() {
        let releases = json!([
            release("file-transfer-v0.0.1", false, false, &[]),
            release("bedcode-v9.9.9", false, false, &[]),
            release("file-transfer-v0.0.9", true, false, &[]),
            release("file-transfer-v0.0.8", false, true, &[]),
            release(
                "file-transfer-v0.0.3",
                false,
                false,
                &[("file-transfer-desktop-v0.0.3.zip", 123)]
            ),
            release("apps-v1.0.0", false, false, &[]),
        ]);
        let picked = pick_latest_release(&releases, &source()).unwrap();
        assert_eq!(picked.tag, "file-transfer-v0.0.3");
        assert_eq!(picked.version, semver::Version::new(0, 0, 3));
        assert_eq!(picked.assets.len(), 1);
        assert_eq!(picked.assets[0].name, "file-transfer-desktop-v0.0.3.zip");
    }

    #[test]
    fn pick_latest_release_names_slug_when_nothing_matches() {
        let releases = json!([release("bedcode-v0.0.1", false, false, &[])]);
        let err = pick_latest_release(&releases, &source()).unwrap_err();
        assert!(err.to_string().contains("file-transfer"), "实际: {err}");
    }

    fn metadata(plugin_id: &str, version: &str, end: &str, compat: Value) -> Value {
        let slug = "file-transfer";
        json!({
            "schema": 1,
            "app": slug,
            "end": end,
            "plugin": { "id": plugin_id, "name": "X", "version": version, "pluginType": "full", "rustLibrary": "x" },
            "compat": compat,
            "artifact": { "file": format!("{slug}-{end}-v{version}.zip"), "bytes": 42, "sha256": "a".repeat(64) },
        })
    }

    #[test]
    fn validate_release_metadata_accepts_wellformed_with_compat() {
        let meta = metadata(
            "com.wasmnest.file-transfer",
            "0.0.2",
            "desktop",
            json!({ "hostRuntime": "0.0.1", "mountContract": "1", "sdkVersion": "0.0.1", "witVersion": "0.0.1" }),
        );
        let (zip, sha, bytes, compat) = validate_release_metadata(
            &meta,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.2",
            &source(),
        )
        .unwrap();
        assert_eq!(zip, "file-transfer-desktop-v0.0.2.zip");
        assert_eq!(sha, "a".repeat(64));
        assert_eq!(bytes, 42);
        assert_eq!(
            compat,
            Some(CompatInfo {
                host_runtime: "0.0.1".into(),
                mount_contract: "1".into(),
                sdk_version: "0.0.1".into(),
                wit_version: "0.0.1".into(),
            })
        );
    }

    #[test]
    fn validate_release_metadata_allows_missing_compat_as_none() {
        let mut raw = metadata(
            "com.wasmnest.file-transfer",
            "0.0.1",
            "desktop",
            Value::Null,
        );
        raw.as_object_mut().unwrap().remove("compat");
        let (_, _, _, compat) = validate_release_metadata(
            &raw,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.1",
            &source(),
        )
        .unwrap();
        assert_eq!(compat, None);
    }

    #[test]
    fn validate_release_metadata_rejects_identity_and_integrity_drift() {
        let base = metadata(
            "com.wasmnest.file-transfer",
            "0.0.2",
            "desktop",
            json!({ "hostRuntime": "0.0.1", "mountContract": "1", "sdkVersion": "0.0.1", "witVersion": "0.0.1" }),
        );
        let s = source();
        let mut m = base.clone();
        m["plugin"]["id"] = json!("com.wasmnest.bedcode");
        assert!(validate_release_metadata(
            &m,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.2",
            &s
        )
        .is_err());
        let mut m = base.clone();
        m["end"] = json!("mobile");
        assert!(validate_release_metadata(
            &m,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.2",
            &s
        )
        .is_err());
        assert!(validate_release_metadata(
            &base,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.3",
            &s
        )
        .is_err());
        let mut m = base.clone();
        m["schema"] = json!(2);
        assert!(validate_release_metadata(
            &m,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.2",
            &s
        )
        .is_err());
        let mut m = base.clone();
        m["artifact"]["sha256"] = json!("deadbeef");
        assert!(validate_release_metadata(
            &m,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.2",
            &s
        )
        .is_err());
        let mut m = base.clone();
        m["app"] = json!("bedcode");
        assert!(validate_release_metadata(
            &m,
            "com.wasmnest.file-transfer",
            "desktop",
            "0.0.2",
            &s
        )
        .is_err());
    }

    #[test]
    fn validate_download_args_self_certifies() {
        let s = source();
        let (tag, version) = validate_download_args(
            &s,
            "desktop",
            "file-transfer-v0.0.2",
            "file-transfer-desktop-v0.0.2.zip",
            &"a".repeat(64),
        )
        .unwrap();
        assert_eq!(tag, "file-transfer-v0.0.2");
        assert_eq!(version, "0.0.2");
        assert!(validate_download_args(
            &s,
            "desktop",
            "file-transfer-v0.0.2",
            "evil.zip",
            &"a".repeat(64)
        )
        .is_err());
        assert!(validate_download_args(
            &s,
            "desktop",
            "https://evil.example/x.zip",
            "file-transfer-desktop-v0.0.2.zip",
            &"a".repeat(64)
        )
        .is_err());
        assert!(validate_download_args(
            &s,
            "desktop",
            "file-transfer-v0.0.2",
            "file-transfer-desktop-v0.0.2.zip",
            "zz"
        )
        .is_err());
        // 端错位：mobile 资产名不能当 desktop 用
        assert!(validate_download_args(
            &s,
            "desktop",
            "file-transfer-v0.0.2",
            "file-transfer-mobile-v0.0.2.zip",
            &"a".repeat(64)
        )
        .is_err());
    }

    #[test]
    fn version_is_newer_is_strict() {
        assert_eq!(version_is_newer("0.0.2", "0.0.1"), Some(true));
        assert_eq!(version_is_newer("0.0.1", "0.0.1"), Some(false));
        assert_eq!(version_is_newer("0.0.1", "0.0.2"), Some(false));
        assert_eq!(version_is_newer("not-semver", "0.0.1"), None);
    }
}
