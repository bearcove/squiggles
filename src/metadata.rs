//! Cargo workspace metadata for resolving crate paths.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cargo_metadata::MetadataCommand;

/// Cached workspace metadata for resolving crate-relative paths.
#[derive(Debug, Clone)]
pub struct WorkspaceMetadata {
    /// Workspace root directory
    pub workspace_root: PathBuf,
    /// Map from crate name (underscores, e.g. "facet_styx") to crate root directory
    by_name: HashMap<String, PathBuf>,
}

impl WorkspaceMetadata {
    /// Load workspace metadata by running `cargo metadata`.
    pub fn load(workspace_root: &Path) -> Option<Self> {
        let metadata = MetadataCommand::new()
            .manifest_path(workspace_root.join("Cargo.toml"))
            .no_deps()
            .exec()
            .ok()?;

        let mut by_name = HashMap::new();

        for package in metadata.packages {
            // Get the directory containing Cargo.toml
            let manifest_path = package.manifest_path.as_std_path();
            let crate_root = manifest_path.parent()?;

            // Store by crate name with underscores (as it appears in backtraces)
            let name_underscored = package.name.replace('-', "_");
            by_name.insert(name_underscored, crate_root.to_path_buf());

            crate::diagnostics::debug_log(&format!(
                "WorkspaceMetadata: {} -> {}",
                package.name,
                crate_root.display()
            ));
        }

        Some(Self {
            workspace_root: metadata.workspace_root.as_std_path().to_path_buf(),
            by_name,
        })
    }

    /// Resolve a crate-relative path (like `./src/error.rs`) given the crate name.
    ///
    /// The crate name should be in underscore form (e.g., `facet_styx`).
    pub fn resolve_path(&self, crate_name: &str, relative_path: &str) -> Option<PathBuf> {
        let crate_root = self.by_name.get(crate_name)?;
        let clean = relative_path.strip_prefix("./").unwrap_or(relative_path);
        let resolved = crate_root.join(clean);

        if resolved.exists() {
            Some(resolved)
        } else {
            None
        }
    }

    /// Extract the crate name from a fully qualified function path.
    ///
    /// E.g., `facet_styx::error::tests::test_foo` -> `facet_styx`
    pub fn extract_crate_name(function: &str) -> Option<&str> {
        function.split("::").next()
    }

    /// Resolve a path from a backtrace frame, using the function name to identify the crate.
    pub fn resolve_frame_path(&self, function: &str, relative_path: &str) -> Option<PathBuf> {
        let crate_name = Self::extract_crate_name(function)?;
        self.resolve_path(crate_name, relative_path)
    }

    /// Find the package name containing the given file path.
    ///
    /// Returns the package name with hyphens (as used by cargo/nextest).
    pub fn package_for_file(&self, file_path: &Path) -> Option<String> {
        // Canonicalize the file path for consistent comparison
        let file_path = file_path.canonicalize().ok()?;

        // Find the package whose root is a prefix of the file path
        for (name_underscored, crate_root) in &self.by_name {
            let crate_root = match crate_root.canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if file_path.starts_with(&crate_root) {
                // Convert back from underscores to hyphens for cargo/nextest
                return Some(name_underscored.replace('_', "-"));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_crate_name() {
        assert_eq!(
            WorkspaceMetadata::extract_crate_name("facet_styx::error::tests::test_foo"),
            Some("facet_styx")
        );
        assert_eq!(
            WorkspaceMetadata::extract_crate_name("my_crate::module::func"),
            Some("my_crate")
        );
        assert_eq!(
            WorkspaceMetadata::extract_crate_name("single"),
            Some("single")
        );
    }
}
