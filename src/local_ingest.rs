//! Bounded, offline import of an operator-selected local HTML directory.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use url::Url;

use crate::html::{self, ExtractedDocument};
use crate::page_policy::PageRestrictions;
use crate::storage::{Intent, PersistentIndex, StorageError};
use crate::url_key::UrlKey;

pub const MAX_HTML_DIRECTORY_ENTRIES: usize = 4096;
pub const MAX_HTML_DOCUMENTS: usize = 128;
pub const MAX_HTML_FILE_BYTES: usize = html::MAX_COMPRESSED_RESPONSE_BYTES;
pub const MAX_HTML_COLLECTION_BYTES: usize = 32 * 1024 * 1024;

const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestReport {
    pub indexed_documents: usize,
    pub skipped_noindex: usize,
    pub input_bytes: usize,
    pub generation_id: u64,
}

#[derive(Debug)]
pub enum IngestError {
    InvalidSourceDirectory,
    InvalidDestination,
    DestinationExists,
    DestinationInsideSource,
    InvalidUrlPrefix,
    TooManyDirectoryEntries,
    TooManyHtmlDocuments,
    FileTooLarge,
    CollectionTooLarge,
    SymlinkNotAllowed,
    PathEscapesSource,
    NonUtf8Path,
    UnsupportedFileType,
    InvalidUtf8Html,
    Html(html::HtmlError),
    Storage(StorageError),
}

impl fmt::Display for IngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSourceDirectory => "source directory is not a readable directory",
            Self::InvalidDestination => "store path must have an existing parent and a file name",
            Self::DestinationExists => "store destination already exists",
            Self::DestinationInsideSource => "store destination must be outside the source directory",
            Self::InvalidUrlPrefix => "URL prefix must be an HTTP(S) directory URL without credentials, query, or fragment",
            Self::TooManyDirectoryEntries => "source directory exceeds the entry limit",
            Self::TooManyHtmlDocuments => "source directory exceeds the HTML document limit",
            Self::FileTooLarge => "an HTML file exceeds the per-file byte limit",
            Self::CollectionTooLarge => "source collection exceeds the total byte limit",
            Self::SymlinkNotAllowed => "source directory contains a symbolic link",
            Self::PathEscapesSource => "source path escapes the selected directory",
            Self::NonUtf8Path => "source path is not valid UTF-8",
            Self::UnsupportedFileType => "source directory contains an unsupported file type",
            Self::InvalidUtf8Html => "an HTML file is not valid UTF-8",
            Self::Html(_) => "an HTML file failed bounded extraction",
            Self::Storage(_) => "the new index could not be written",
        })
    }
}

impl std::error::Error for IngestError {}

struct SourceFile {
    path: PathBuf,
    relative: String,
}

struct PreparedDocument {
    requested_url: UrlKey,
    effective_url: String,
    title: String,
    body: String,
}

pub fn ingest_html_directory(
    store_path: impl AsRef<Path>,
    directory: impl AsRef<Path>,
    url_prefix: &str,
) -> Result<IngestReport, IngestError> {
    let source_root = canonical_source_root(directory.as_ref())?;
    let destination = canonical_new_destination(store_path.as_ref(), &source_root)?;
    let url_prefix = parse_url_prefix(url_prefix)?;
    let source_files = collect_html_files(&source_root)?;

    let mut documents = Vec::with_capacity(source_files.len());
    let mut input_bytes = 0usize;
    let mut skipped_noindex = 0usize;
    for source in source_files {
        let bytes = read_html_file(&source.path, &source_root, input_bytes)?;
        input_bytes = input_bytes
            .checked_add(bytes.len())
            .ok_or(IngestError::CollectionTooLarge)?;
        let html_text = std::str::from_utf8(&bytes).map_err(|_| IngestError::InvalidUtf8Html)?;
        let requested_url = map_relative_path(&url_prefix, &source.relative)?;
        let extracted = html::extract_html(
            html_text.as_bytes(),
            HTML_CONTENT_TYPE,
            None,
            requested_url.clone(),
            requested_url.as_str(),
        )
        .map_err(IngestError::Html)?;
        if extracted.restrictions.noindex {
            skipped_noindex += 1;
            continue;
        }
        documents.push(prepared_document(extracted));
    }

    let store = PersistentIndex::create(&destination).map_err(IngestError::Storage)?;
    for document in documents.iter() {
        let lease = store
            .issue_fence(&document.requested_url)
            .map_err(IngestError::Storage)?;
        store
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: document.effective_url.clone(),
                    title: document.title.clone(),
                    body: document.body.clone(),
                },
            )
            .map_err(IngestError::Storage)?;
    }
    let generation_id = store
        .read_view()
        .map_err(IngestError::Storage)?
        .generation_id();

    Ok(IngestReport {
        indexed_documents: documents.len(),
        skipped_noindex,
        input_bytes,
        generation_id,
    })
}

fn prepared_document(extracted: ExtractedDocument) -> PreparedDocument {
    let ExtractedDocument {
        requested_url,
        effective_url,
        title,
        body,
        restrictions: PageRestrictions { .. },
        ..
    } = extracted;
    PreparedDocument {
        requested_url,
        effective_url,
        title,
        body,
    }
}

fn canonical_source_root(directory: &Path) -> Result<PathBuf, IngestError> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|_| IngestError::InvalidSourceDirectory)?;
    if metadata.file_type().is_symlink() {
        return Err(IngestError::SymlinkNotAllowed);
    }
    if !metadata.is_dir() {
        return Err(IngestError::InvalidSourceDirectory);
    }
    fs::canonicalize(directory).map_err(|_| IngestError::InvalidSourceDirectory)
}

fn canonical_new_destination(path: &Path, source_root: &Path) -> Result<PathBuf, IngestError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(IngestError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(IngestError::InvalidDestination),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or(IngestError::InvalidDestination)?;
    let parent = fs::canonicalize(parent).map_err(|_| IngestError::InvalidDestination)?;
    let destination = parent.join(name);
    if destination == source_root || destination.starts_with(source_root) {
        return Err(IngestError::DestinationInsideSource);
    }
    Ok(destination)
}

fn parse_url_prefix(value: &str) -> Result<Url, IngestError> {
    let url = Url::parse(value).map_err(|_| IngestError::InvalidUrlPrefix)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
        || url.cannot_be_a_base()
    {
        return Err(IngestError::InvalidUrlPrefix);
    }
    UrlKey::parse(url.as_str()).map_err(|_| IngestError::InvalidUrlPrefix)?;
    Ok(url)
}

fn collect_html_files(root: &Path) -> Result<Vec<SourceFile>, IngestError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut entries_seen = 0usize;

    while let Some(directory) = pending.pop() {
        let mut children = fs::read_dir(&directory)
            .map_err(|_| IngestError::InvalidSourceDirectory)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| IngestError::InvalidSourceDirectory)?;
        children.sort_by_key(|entry| entry.file_name());
        for entry in children {
            entries_seen += 1;
            if entries_seen > MAX_HTML_DIRECTORY_ENTRIES {
                return Err(IngestError::TooManyDirectoryEntries);
            }
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| IngestError::InvalidSourceDirectory)?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(IngestError::SymlinkNotAllowed);
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err(IngestError::UnsupportedFileType);
            }
            if !is_html_path(&path) {
                continue;
            }
            if files.len() == MAX_HTML_DOCUMENTS {
                return Err(IngestError::TooManyHtmlDocuments);
            }
            let canonical =
                fs::canonicalize(&path).map_err(|_| IngestError::InvalidSourceDirectory)?;
            if !canonical.starts_with(root) {
                return Err(IngestError::PathEscapesSource);
            }
            let relative_path = path
                .strip_prefix(root)
                .map_err(|_| IngestError::PathEscapesSource)?;
            let relative = relative_url_path(relative_path)?;
            files.push(SourceFile {
                path: canonical,
                relative,
            });
        }
    }
    files.sort_by(|left, right| left.relative.as_bytes().cmp(right.relative.as_bytes()));
    Ok(files)
}

fn is_html_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("html") || extension.eq_ignore_ascii_case("htm")
        })
}

fn relative_url_path(path: &Path) -> Result<String, IngestError> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                components.push(value.to_str().ok_or(IngestError::NonUtf8Path)?)
            }
            _ => return Err(IngestError::PathEscapesSource),
        }
    }
    if components.is_empty() {
        return Err(IngestError::PathEscapesSource);
    }
    Ok(components.join("/"))
}

fn map_relative_path(prefix: &Url, relative: &str) -> Result<UrlKey, IngestError> {
    let mut url = prefix.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| IngestError::InvalidUrlPrefix)?;
        segments.pop_if_empty();
        for component in relative.split('/') {
            if component.is_empty() {
                return Err(IngestError::PathEscapesSource);
            }
            segments.push(component);
        }
    }
    UrlKey::parse(url.as_str()).map_err(|_| IngestError::InvalidUrlPrefix)
}

fn read_html_file(
    path: &Path,
    source_root: &Path,
    bytes_before_file: usize,
) -> Result<Vec<u8>, IngestError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| IngestError::InvalidSourceDirectory)?;
    if metadata.file_type().is_symlink() {
        return Err(IngestError::SymlinkNotAllowed);
    }
    if !metadata.is_file() {
        return Err(IngestError::UnsupportedFileType);
    }
    let canonical = fs::canonicalize(path).map_err(|_| IngestError::InvalidSourceDirectory)?;
    if !canonical.starts_with(source_root) {
        return Err(IngestError::PathEscapesSource);
    }
    if metadata.len() > MAX_HTML_FILE_BYTES as u64 {
        return Err(IngestError::FileTooLarge);
    }

    let collection_remaining = MAX_HTML_COLLECTION_BYTES
        .checked_sub(bytes_before_file)
        .ok_or(IngestError::CollectionTooLarge)?;
    let read_limit = MAX_HTML_FILE_BYTES
        .min(collection_remaining)
        .saturating_add(1);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| IngestError::InvalidSourceDirectory)?;
    if !file
        .metadata()
        .map_err(|_| IngestError::InvalidSourceDirectory)?
        .is_file()
    {
        return Err(IngestError::UnsupportedFileType);
    }
    read_bounded(file, read_limit, collection_remaining)
}

fn read_bounded(
    file: File,
    read_limit: usize,
    collection_remaining: usize,
) -> Result<Vec<u8>, IngestError> {
    let mut bytes = Vec::with_capacity(read_limit.min(MAX_HTML_FILE_BYTES));
    file.take(read_limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IngestError::InvalidSourceDirectory)?;
    if bytes.len() > MAX_HTML_FILE_BYTES {
        return Err(IngestError::FileTooLarge);
    }
    if bytes.len() > collection_remaining {
        return Err(IngestError::CollectionTooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{IngestError, ingest_html_directory};
    use crate::storage::PersistentIndex;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TempDirectory(std::path::PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ley-ingest-test-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn imports_sorted_utf8_documents_and_skips_noindex() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(
            source.join("nested/naïve guide.html"),
            "<html><head><title>Unicode guide</title></head><body>Crème brûlée retrieval</body></html>",
        )
        .unwrap();
        fs::write(
            source.join("private.html"),
            "<html><head><meta name=robots content=noindex><title>Private</title></head><body>hidden text</body></html>",
        )
        .unwrap();
        let store_path = temp.path().join("store");
        let report =
            ingest_html_directory(&store_path, &source, "https://docs.example.invalid/local/")
                .unwrap();

        assert_eq!(report.indexed_documents, 1);
        assert_eq!(report.skipped_noindex, 1);
        assert!(report.input_bytes > 0);
        let store = PersistentIndex::open(&store_path).unwrap();
        let response = store
            .retrieve(crate::retrieval::RetrievalRequest::question("crème brûlée"))
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(
            response.hits[0].requested_url,
            "https://docs.example.invalid/local/nested/na%C3%AFve%20guide.html"
        );
        assert!(response.hits[0].passage.text.contains("Crème brûlée"));
    }

    #[test]
    fn rejects_invalid_utf8_and_existing_destinations_without_touching_them() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("bad.html"),
            [b'<', b'p', b'>', 0xFF, b'<', b'/', b'p', b'>'],
        )
        .unwrap();
        let destination = temp.path().join("store");
        assert!(matches!(
            ingest_html_directory(&destination, &source, "https://docs.example.invalid/local/"),
            Err(IngestError::InvalidUtf8Html)
        ));
        assert!(!destination.exists());

        fs::remove_file(source.join("bad.html")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), b"preserve").unwrap();
        assert!(matches!(
            ingest_html_directory(&destination, &source, "https://docs.example.invalid/local/"),
            Err(IngestError::DestinationExists)
        ));
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"preserve");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_store_paths_inside_source() {
        use std::os::unix::fs::symlink;

        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("page.html"),
            "<html><body>page text</body></html>",
        )
        .unwrap();
        let outside = temp.path().join("outside.html");
        fs::write(&outside, "<html><body>outside text</body></html>").unwrap();
        symlink(outside, source.join("link.html")).unwrap();
        assert!(matches!(
            ingest_html_directory(
                temp.path().join("store"),
                &source,
                "https://docs.example.invalid/local/"
            ),
            Err(IngestError::SymlinkNotAllowed)
        ));
        assert!(matches!(
            ingest_html_directory(
                source.join("store"),
                temp.path().join("source"),
                "https://docs.example.invalid/local/"
            ),
            Err(IngestError::DestinationInsideSource)
        ));
    }
}
