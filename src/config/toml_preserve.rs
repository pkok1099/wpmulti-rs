//! Comment-preserving `wpmulti.toml` serialization.
//!
//! Saving a config used to rewrite the whole file from the parsed
//! model (`toml::to_string_pretty`), silently destroying every comment
//! the user wrote in it — header warnings, contact names, reasons for
//! a value. This module overlays the new config onto the existing file
//! text instead, so comments survive a save.

use toml_edit::{DocumentMut, Item, Table};

use super::toml_config::MainConfig;

/// Merge `fresh_serialized` — a full `toml::to_string_pretty` dump of the
/// new config — onto `existing_text`, preserving the existing file's
/// comments and formatting where possible.
///
/// The new config's values are overlaid key by key: tables are merged
/// recursively (so comments above `[section]` headers survive), values
/// are replaced in place keeping the old value's decor (so a trailing
/// `# comment` stays attached to its key), and keys the new config no
/// longer contains are removed so the file cannot drift from the model.
/// Whole `[[shared_listener]]` arrays are replaced wholesale — comments
/// inside a replaced array do not survive.
///
/// Returns the merged text, or `None` if the existing text cannot be
/// merged safely (unparsable, or the merged text no longer parses back
/// to exactly the new config). The caller must then use
/// `fresh_serialized` as-is, so a save never fails because of comment
/// preservation.
pub fn merge_config_preserving_comments(
    existing_text: &str,
    fresh_serialized: &str,
) -> Option<String> {
    let mut old_doc: DocumentMut = existing_text.parse().ok()?;
    let new_doc: DocumentMut = fresh_serialized.parse().ok()?;
    merge_table(old_doc.as_table_mut(), new_doc.as_table());
    let merged = old_doc.to_string();
    // Safety net: the merged text must describe exactly the new config.
    // If the merge corrupted anything (or the old file carried a key
    // the model cannot represent), fall back to the plain dump.
    let merged_cfg: MainConfig = toml::from_str(&merged).ok()?;
    let fresh_cfg: MainConfig = toml::from_str(fresh_serialized).ok()?;
    if merged_cfg != fresh_cfg {
        tracing::debug!("comment-preserving config merge changed semantics; using plain dump");
        return None;
    }
    Some(merged)
}

/// Overlay `new` onto `old`, key by key.
fn merge_table(old: &mut Table, new: &Table) {
    // Drop keys the new config no longer contains (a removed listener
    // or override), so the file cannot drift from the model.
    let old_keys: Vec<String> = old.iter().map(|(key, _)| key.to_owned()).collect();
    for key in old_keys {
        if !new.contains_key(&key) {
            old.remove(&key);
        }
    }
    for (key, new_item) in new {
        match (old.get_mut(key), new_item) {
            (Some(Item::Table(old_table)), Item::Table(new_table)) => {
                merge_table(old_table, new_table);
            }
            (Some(old_item), _) => {
                let mut replacement = new_item.clone();
                preserve_value_decor(old_item, &mut replacement);
                *old_item = replacement;
            }
            (None, _) => {
                old.insert(key, new_item.clone());
            }
        }
    }
}

/// Copy the old value's decor (spacing and trailing comment) onto its
/// replacement, so `# keep at info in prod` stays attached to its key.
/// Only plain values carry this decor; tables are merged recursively
/// and arrays of tables are replaced wholesale.
fn preserve_value_decor(old_item: &Item, replacement: &mut Item) {
    if let (Some(old_value), Some(new_value)) = (old_item.as_value(), replacement.as_value_mut()) {
        *new_value.decor_mut() = old_value.decor().clone();
    }
}
