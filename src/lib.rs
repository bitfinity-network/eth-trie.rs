mod nibbles;
mod node;
mod tests;

mod db;
mod errors;
mod trie;

pub use db::{MemoryDB, DB, DBMut, versioned::VersionedDB};
pub use errors::{MemDBError, TrieError};
pub use trie::{EthTrie, Trie, TrieMut, TrieCommit};

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
