use std::borrow::BorrowMut;

use ethereum_types::H256;
use hashbrown::{HashMap, HashSet};
use keccak_hash::KECCAK_NULL_RLP;
use log::warn;

use crate::db::DB;
use crate::errors::TrieError;
use crate::nibbles::Nibbles;
use crate::node::Node;

use self::ops::TrieOps;
use self::trie_ref::TrieRef;

pub type TrieResult<T> = Result<T, TrieError>;
const HASHED_LENGTH: usize = 32;

mod ops;
mod trie_ref;

pub trait Trie<D: DB> {

    /// Returns the temporary root hash of the trie.
    /// This root hash is not saved in the db until commit is called.
    fn uncommitted_root(&self) -> H256;

    /// Returns an iterator over the trie.
    fn iter(&self) -> TrieIterator<D>;

    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>>;

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool>;

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: H256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>>;

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<()>;

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool>;

    /// Removes all existing (key, value) pairs from the trie.
    /// Returns the number of removed pairs.
    fn remove_all(&mut self) -> TrieResult<usize>;

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    fn get_proof(&mut self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>>;

}

pub trait TrieCommit<D: DB> {

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn commit(&mut self) -> TrieResult<H256>;

}

pub type TrieCache = HashMap<H256, Vec<u8>>;
pub type TrieKeys = HashSet<H256>;

#[derive(Debug)]
pub struct EthTrie<D: DB>
{
    root: Node,
    root_hash: H256,

    db: D,

    // The batch of pending new nodes to write
    cache: TrieCache,
    passing_keys: TrieKeys,
    gen_keys: TrieKeys,
}

enum EncodedNode {
    Hash(H256),
    Inline(Vec<u8>),
}

#[derive(Clone, Debug)]
enum TraceStatus {
    Start,
    Doing,
    Child(u8),
    End,
}

#[derive(Clone, Debug)]
struct TraceNode {
    node: Node,
    status: TraceStatus,
}

impl TraceNode {
    fn advance(&mut self) {
        self.status = match &self.status {
            TraceStatus::Start => TraceStatus::Doing,
            TraceStatus::Doing => match self.node {
                Node::Branch(_) => TraceStatus::Child(0),
                _ => TraceStatus::End,
            },
            TraceStatus::Child(i) if *i < 15 => TraceStatus::Child(i + 1),
            _ => TraceStatus::End,
        }
    }
}

impl From<Node> for TraceNode {
    fn from(node: Node) -> TraceNode {
        TraceNode {
            node,
            status: TraceStatus::Start,
        }
    }
}

pub struct TrieIterator<'a, D>
where
    D: DB,
{
    db: &'a D,
    nibble: Nibbles,
    nodes: Vec<TraceNode>,
}

impl<'a, D> Iterator for TrieIterator<'a, D>
where
    D: DB,
{
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - leaf.key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble
                                    .truncate(cur_len - ext.read().prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble.extend(&ext.read().prefix);
                        self.nodes.push((ext.read().node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend(&leaf.key);
                        return Some((self.nibble.encode_raw().0, leaf.value.clone()));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value_option = branch.read().value.clone();
                        if let Some(value) = value_option {
                            return Some((self.nibble.encode_raw().0, value));
                        } else {
                            continue;
                        }
                    }

                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        let node_hash = hash_node.hash;
                        if let Ok(n) = TrieOps::recover_from_db(self.db, &node_hash) {
                            self.nodes.pop();
                            match n {
                                Some(node) => self.nodes.push(node.into()),
                                None => {
                                    warn!("Trie node with hash {:?} is missing from the database. Skipping...", &node_hash);
                                    continue;
                                }
                            }
                        } else {
                            //error!();
                            return None;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((branch.read().children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}

impl<D: DB> EthTrie<D> {

pub fn new(db: D) -> EthTrie<D> {
    EthTrie {
        root: Node::Empty,
        root_hash: KECCAK_NULL_RLP.as_fixed_bytes().into(),
        
        cache: TrieCache::new(),
        passing_keys: TrieKeys::new(),
        gen_keys: TrieKeys::new(),
        
        db,
    }
}

    pub fn with_root(db: D, root_hash: H256) -> EthTrie<D> {
        EthTrie {
            root: Node::from_hash(root_hash),
            root_hash,

            cache: TrieCache::new(),
            passing_keys: TrieKeys::new(),
            gen_keys: TrieKeys::new(),

            db,
        }
    }
    
    pub fn ref_with_root(&mut self, root_hash: H256) -> TrieRef<&mut TrieCache, &mut TrieKeys, &mut D, D> {
        TrieRef::new(Node::from_hash(root_hash), root_hash, self.db.borrow_mut(), &mut self.cache, &mut self.passing_keys, &mut self.gen_keys)
    }

}
    
impl<D: DB> Trie<D> for EthTrie<D> {

    fn uncommitted_root(&self) -> H256 {
        self.root_hash
    }

    fn iter(&self) -> TrieIterator<D> {
        let nodes = vec![(self.root.clone()).into()];
        TrieIterator {
            db: &self.db,
            nibble: Nibbles::from_raw(&[], false),
            nodes,
        }
    }

    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>> {
        TrieOps::get(key, &self.root_hash, &self.db, &self.root)
    }

    fn contains(&self, key: &[u8]) -> TrieResult<bool> {
        TrieOps::contains(key, &self.root_hash, &self.db, &self.root)
    }

    fn verify_proof(
        &self,
        root_hash: H256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        TrieOps::verify_proof(root_hash, key, proof)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<()> {
        let node = TrieOps::insert(key, value, &self.root_hash, self.db.borrow_mut(), &mut self.root, &mut self.passing_keys)?;
        self.root = node;
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> TrieResult<bool> {
        let (root, res) = TrieOps::remove(key, &self.root_hash, self.db.borrow_mut(), &mut self.root, &mut self.passing_keys)?;
        self.root = root;
        Ok(res)
    }

    fn remove_all(&mut self) -> TrieResult<usize> {
        let keys: Vec<_> = self.iter().map(|(k, _)| k).collect();
        let keys_len = keys.len();
        for key in keys {
            self.remove(&key)?;
        }
        Ok(keys_len)
    }

    fn get_proof(&mut self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>> {
        TrieOps::get_proof(key, &self.root_hash, self.db.borrow_mut(), &self.root, &mut self.gen_keys, &mut self.cache)
    }

}

impl<D: DB> TrieCommit<D> for EthTrie<D> {

    fn commit(&mut self) -> TrieResult<H256> {
        let (root_hash, root) = TrieOps::commit(&self.root,  self.db.borrow_mut(), &mut self.gen_keys, &mut self.cache, &mut self.passing_keys)?;
        self.root = root;
        self.root_hash = root_hash;
        Ok(root_hash)
    }

}

#[cfg(test)]
mod tests {
    use parking_lot::lock_api::RwLock;
    use rand::distributions::Alphanumeric;
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use ethereum_types::H256;
    use keccak_hash::KECCAK_NULL_RLP;

    use super::*;
    use crate::db::{MemoryDB, DB};
    use crate::errors::TrieError;
    use crate::nibbles::Nibbles;
    use crate::VersionedDB;

    #[test]
    fn test_trie_insert() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(b"test", b"test").unwrap();
    }

    #[test]
    fn test_trie_get() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"test").unwrap();

        assert_eq!(Some(b"test".to_vec()), v)
    }

    #[test]
    fn test_trie_get_missing() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"no-val").unwrap();

        assert_eq!(None, v)
    }

    fn corrupt_trie(db: &mut MemoryDB) -> (EthTrie<&mut MemoryDB>, H256, H256) {

        // let corruptor_db = db.clone();
        let actual_root_hash = {
            let mut trie = EthTrie::new(db.borrow_mut());
            trie.insert(b"test1-key", b"really-long-value1-to-prevent-inlining")
                .unwrap();
            trie.insert(b"test2-key", b"really-long-value2-to-prevent-inlining")
                .unwrap();
            trie.commit().unwrap()
        };

        // Manually corrupt the database by removing a trie node
        // This is the hash for the leaf node for test2-key
        let node_hash_to_delete = H256::from_slice(b"\xcb\x15v%j\r\x1e\te_TvQ\x8d\x93\x80\xd1\xa2\xd1\xde\xfb\xa5\xc3hJ\x8c\x9d\xb93I-\xbd");
        assert_ne!(db.get(&node_hash_to_delete).unwrap(), None);
        db.remove(&node_hash_to_delete).unwrap();
        assert_eq!(db.get(&node_hash_to_delete).unwrap(), None);

        (
            EthTrie::with_root(db, actual_root_hash),
            actual_root_hash,
            node_hash_to_delete,
        )
    }

    #[test]
    /// When a database entry is missing, get returns a MissingTrieNode error
    fn test_trie_get_corrupt() {
        let mut memdb = MemoryDB::new(true);
        let (trie, actual_root_hash, deleted_node_hash) = corrupt_trie(&mut memdb);

        let result = trie.get(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, delete returns a MissingTrieNode error
    fn test_trie_delete_corrupt() {
        let mut memdb = MemoryDB::new(true);
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie(&mut memdb);

        let result = trie.remove(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, delete returns a MissingTrieNode error
    fn test_trie_delete_refactor_corrupt() {
        let mut memdb = MemoryDB::new(true);
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie(&mut memdb);

        let result = trie.remove(b"test1-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: None,
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test1-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, get_proof returns a MissingTrieNode error
    fn test_trie_get_proof_corrupt() {
        let mut memdb = MemoryDB::new(true);
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie(&mut memdb);

        let result = trie.get_proof(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: None,
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, insert returns a MissingTrieNode error
    fn test_trie_insert_corrupt() {
        let mut memdb = MemoryDB::new(true);
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie(&mut memdb);

        let result = trie.insert(b"test2-neighbor", b"any");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-neighbor".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    fn test_trie_random_insert() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let v = trie.get(val).unwrap();
            assert_eq!(v.map(|v| v.to_vec()), Some(val.to_vec()));
        }
    }

    #[test]
    fn test_trie_contains() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(b"test", b"test").unwrap();
        assert!(trie.contains(b"test").unwrap());
        assert!(!trie.contains(b"test2").unwrap());
    }

    #[test]
    fn test_trie_remove() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(b"test", b"test").unwrap();
        let removed = trie.remove(b"test").unwrap();
        assert!(removed)
    }

    #[test]
    fn test_trie_random_remove() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let removed = trie.remove(val).unwrap();
            assert!(removed);
        }
    }

    #[test]
    fn test_trie_at_root_six_keys() {
        let mut memdb = MemoryDB::new(true);
        let root = {
            let mut trie = EthTrie::new(&mut memdb);
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.commit().unwrap()
        };

        let mut trie = EthTrie::with_root(&mut memdb,root);
        let v1 = trie.get(b"test33").unwrap();
        assert_eq!(Some(b"test".to_vec()), v1);
        let v2 = trie.get(b"test44").unwrap();
        assert_eq!(Some(b"test".to_vec()), v2);
        let root2 = trie.commit().unwrap();
        assert_eq!(hex::encode(root), hex::encode(root2));
    }

    #[test]
    fn test_trie_at_root_and_insert() {
        let mut memdb = MemoryDB::new(true);
        let root = {
            let mut trie = EthTrie::new(&mut memdb);
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.commit().unwrap()
        };

        let mut trie = EthTrie::with_root(&mut memdb,root);
        trie.insert(b"test55", b"test55").unwrap();
        trie.commit().unwrap();
        let v = trie.get(b"test55").unwrap();
        assert_eq!(Some(b"test55".to_vec()), v);
    }

    #[test]
    fn test_trie_at_root_and_delete() {
        let mut memdb = MemoryDB::new(true);
        let root = {
            let mut trie = EthTrie::new(&mut memdb);
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.commit().unwrap()
        };

        let mut trie = EthTrie::with_root(&mut memdb,root);
        let removed = trie.remove(b"test44").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test33").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test23").unwrap();
        assert!(removed);
    }

    #[test]
    fn test_multiple_trie_roots() {
        let k0: ethereum_types::H256 = ethereum_types::H256::zero();
        let k1: ethereum_types::H256 = ethereum_types::H256::random();
        let v: ethereum_types::H256 = ethereum_types::H256::random();

        let root1 = {
            let mut memdb = MemoryDB::new(true);
            let mut trie = EthTrie::new(&mut memdb);
            trie.insert(k0.as_bytes(), v.as_bytes()).unwrap();
            trie.commit().unwrap()
        };

        let root2 = {
            let mut memdb = MemoryDB::new(true);
            let mut trie = EthTrie::new(&mut memdb);
            trie.insert(k0.as_bytes(), v.as_bytes()).unwrap();
            trie.insert(k1.as_bytes(), v.as_bytes()).unwrap();
            trie.commit().unwrap();
            trie.remove(k1.as_ref()).unwrap();
            trie.commit().unwrap()
        };

        let root3 = {
            let mut memdb = MemoryDB::new(true);
            let mut trie1 = EthTrie::new(&mut memdb);
            trie1.insert(k0.as_bytes(), v.as_bytes()).unwrap();
            trie1.insert(k1.as_bytes(), v.as_bytes()).unwrap();
            trie1.commit().unwrap();
            let root = trie1.commit().unwrap();
            let mut trie2 = EthTrie::with_root(&mut memdb, root);
            trie2.remove(k1.as_bytes()).unwrap();
            trie2.commit().unwrap()
        };

        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn test_delete_stale_keys_with_random_insert_and_delete() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);

        let mut rng = rand::thread_rng();
        let mut keys = vec![];
        for _ in 0..100 {
            let random_bytes: Vec<u8> = (0..rng.gen_range(2..30))
                .map(|_| rand::random::<u8>())
                .collect();
            trie.insert(&random_bytes, &random_bytes).unwrap();
            keys.push(random_bytes.clone());
        }
        trie.commit().unwrap();
        let slice = &mut keys;
        slice.shuffle(&mut rng);

        for key in slice.iter() {
            trie.remove(key).unwrap();
        }
        trie.commit().unwrap();

        let empty_node_key = KECCAK_NULL_RLP;
        let value = trie.db.get(&
            empty_node_key).unwrap().unwrap();
        assert_eq!(value, &rlp::NULL_RLP)
    }

    #[test]
    fn insert_full_branch() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);

        trie.insert(b"test", b"test").unwrap();
        trie.insert(b"test1", b"test").unwrap();
        trie.insert(b"test2", b"test").unwrap();
        trie.insert(b"test23", b"test").unwrap();
        trie.insert(b"test33", b"test").unwrap();
        trie.insert(b"test44", b"test").unwrap();
        trie.commit().unwrap();

        let v = trie.get(b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), v);
    }

    #[test]
    fn iterator_trie() {
        let mut memdb = MemoryDB::new(true);
        let root1: H256;
        let mut kv = HashMap::new();
        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());

        {
            let mut trie = EthTrie::new(&mut memdb);
            let mut kv = kv.clone();
            kv.iter().for_each(|(k, v)| {
                trie.insert(k, v).unwrap();
            });
            root1 = trie.commit().unwrap();

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
            assert!(kv.is_empty());
        }

        {
            let mut trie = EthTrie::new(&mut memdb);
            let mut kv2 = HashMap::new();
            kv2.insert(b"test".to_vec(), b"test11".to_vec());
            kv2.insert(b"test1".to_vec(), b"test12".to_vec());
            kv2.insert(b"test14".to_vec(), b"test13".to_vec());
            kv2.insert(b"test22".to_vec(), b"test14".to_vec());
            kv2.insert(b"test9".to_vec(), b"test15".to_vec());
            kv2.insert(b"test16".to_vec(), b"test16".to_vec());
            kv2.insert(b"test2".to_vec(), b"test17".to_vec());
            kv2.iter().for_each(|(k, v)| {
                trie.insert(k, v).unwrap();
            });

            trie.commit().unwrap();

            let mut kv_delete = HashSet::new();
            kv_delete.insert(b"test".to_vec());
            kv_delete.insert(b"test1".to_vec());
            kv_delete.insert(b"test14".to_vec());

            kv_delete.iter().for_each(|k| {
                trie.remove(k).unwrap();
            });

            kv2.retain(|k, _| !kv_delete.contains(k));

            trie.commit().unwrap();
            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv2.remove(&k).unwrap(), v));
            assert!(kv2.is_empty());
        }

        let trie = EthTrie::with_root(&mut memdb,root1);
        trie.iter()
            .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
        assert!(kv.is_empty());
    }

    #[test]
    fn test_small_trie_at_root() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(b"key", b"val").unwrap();
        let new_root_hash = trie.commit().unwrap();

        let mut empty_trie = EthTrie::new(&mut memdb);
        // Can't find key in new trie at empty root
        assert_eq!(empty_trie.get(b"key").unwrap(), None);

        let trie_view = empty_trie.ref_with_root(new_root_hash);
        assert_eq!(&trie_view.get(b"key").unwrap().unwrap(), b"val");

        // Previous trie was not modified
        assert_eq!(empty_trie.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_large_trie_at_root() {
        let mut memdb = MemoryDB::new(true);
        let mut trie = EthTrie::new(&mut memdb);
        trie.insert(
            b"pretty-long-key",
            b"even-longer-val-to-go-more-than-32-bytes",
        )
        .unwrap();
        let new_root_hash = trie.commit().unwrap();

        let mut empty_trie = EthTrie::new(&mut memdb);
        // Can't find key in new trie at empty root
        assert_eq!(empty_trie.get(b"pretty-long-key").unwrap(), None);

        let trie_view = empty_trie.ref_with_root(new_root_hash);
        assert_eq!(
            &trie_view.get(b"pretty-long-key").unwrap().unwrap(),
            b"even-longer-val-to-go-more-than-32-bytes"
        );

        // Previous trie was not modified
        assert_eq!(empty_trie.get(b"pretty-long-key").unwrap(), None);
    }

    #[test]
    fn test_remove_all_from_root() {
        let mut memdb = VersionedDB::new(10);

        let root_hash_1 = {
            let mut trie = EthTrie::new(&mut memdb);
            trie.insert(b"key", b"val").unwrap();
            let root_hash = trie.commit().unwrap();
    
            // println!("root_hash : {:?}", root_hash);
            // println!("memdb.len() : {}", memdb.len().unwrap());
            assert_eq!(memdb.len().unwrap(), 1);
            root_hash
        };

        let root_hash_2 =  {
            let mut trie = EthTrie::with_root(&mut memdb,root_hash_1);

            trie.insert(b"key", b"val_inner").unwrap();
            trie.insert(b"key2", b"val_inner").unwrap();
            trie.insert(b"key3", b"val_inner").unwrap();
            
            assert_eq!(&trie.get(b"key").unwrap().unwrap(), b"val_inner");
            let root_hash = trie.commit().unwrap();
    
            // println!("root_hash : {:?}", root_hash);
            // println!("memdb.len() : {}", memdb.len().unwrap());
            assert_eq!(memdb.len().unwrap(), 4);
            root_hash
        };

        let _root_hash_3 =  {
            let mut trie = EthTrie::with_root(&mut memdb, root_hash_2);

            let removed = trie.remove_all().unwrap();
            assert_eq!(removed, 3);

            let root_hash = trie.commit().unwrap();

            // println!("root_hash : {:?}", root_hash);
            // println!("memdb.len() : {}", memdb.len().unwrap());

            root_hash
        };

        {
            let trie = EthTrie::with_root(&mut memdb, root_hash_1);
            assert_eq!(b"val".to_vec() , trie.get(b"key").unwrap().unwrap());

            memdb.commit_version(Some(11));

            let trie = EthTrie::with_root(&mut memdb, root_hash_1);
            assert!(trie.get(b"key").is_err());
            assert_eq!(1, memdb.len().unwrap());
        };

    }

    // #[test]
    // fn test_ref_child_trie() {
    //     let mut memdb = Arc::new(RwLock::new(VersionedDB::new(10)));
    //     let mut trie = EthTrie::new(memdb.clone());

    //     let root_hash_1 = {
    //         trie.insert(b"key", b"val").unwrap();
    //         let root_hash = trie.commit().unwrap();
    //         root_hash
    //     };

    //     let child_ref_root_hash =  {
    //         let mut trie = trie.ref_with_root(root_hash_1);

    //         trie.insert(b"key", b"val_inner").unwrap();
    //         trie.insert(b"key2", b"val_inner").unwrap();
    //         trie.insert(b"key3", b"val_inner").unwrap();
            
    //         assert_eq!(&trie.get(b"key").unwrap().unwrap(), b"val_inner");
    
    //         trie.uncommitted_root()
    //     };

    //     println!("root_hash_1 : {:?}", root_hash_1);
    //     println!("child_ref_root_hash : {:?}", child_ref_root_hash);

    //     // Data of the child is not saved in the database until commit is called on the root trie.    
    //     {
    //         assert_eq!(memdb.len().unwrap(), 1);
    //         let mut trie = EthTrie::with_root(memdb.clone(), child_ref_root_hash);
    //         assert!(!trie.contains(&child_ref_root_hash.0).unwrap());
    //     }

    //     // Commit the root trie
    //         {
    //             let mut trie = trie.ref_with_root(root_hash_1);
    //             assert_eq!(&trie.get(b"key").unwrap().unwrap(), b"val");
    //         }
    //         {
    //             let mut trie = trie.ref_with_root(child_ref_root_hash);
    //             assert_eq!(&trie.get(b"key").unwrap().unwrap(), b"val_inner");
    //             // assert!(trie.contains(&child_ref_root_hash.0).unwrap());
    //         }

    // }

}
