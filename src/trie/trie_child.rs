use std::sync::Arc;

use hashbrown::{HashMap, HashSet};
use keccak_hash::H256;

use crate::{node::Node, DB};



#[derive(Debug)]
pub struct TrieChild<'a, D>
where
    D: DB,
{
    root: Node,
    root_hash: H256,

    db: Arc<D>,

    // The batch of pending new nodes to write
    cache: &'a HashMap<H256, Vec<u8>>,
    passing_keys: &'a HashSet<H256>,
    gen_keys: &'a HashSet<H256>,
}

impl<'a, D> TrieChild<'a, D>
where
    D: DB,
{
    pub fn new(
        root_hash: H256,
        db: Arc<D>,
        cache: &'a HashMap<H256, Vec<u8>>,
        passing_keys: &'a HashSet<H256>,
        gen_keys: &'a HashSet<H256>,
    ) -> Self {
        TrieChild {
            root: Node::from_hash(root_hash),
            root_hash,
            db,
            cache,
            passing_keys,
            gen_keys,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{trie, EthTrie, MemoryDB};

    #[test]
    fn test_trie_child() {
        let db = Arc::new(MemoryDB::new(false));
        let mut trie = EthTrie::new(db.clone());
        
        let child_hash = H256::from_low_u64_be(1242412);
        let mut trie_child = trie.trie_at_root_mut(child_hash);
        
        let mut_cow = Cow::Borrowed(&mut trie_child);

    }
}