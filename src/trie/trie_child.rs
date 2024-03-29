use std::{borrow::{Borrow, BorrowMut}, sync::Arc};

use hashbrown::{HashMap, HashSet};
use keccak_hash::H256;

use crate::{nibbles::Nibbles, node::Node, Trie, TrieMut, DB};

use super::{ops::TrieOps, TrieIterator, TrieResult};

#[derive(Debug)]
pub struct TrieRef<C, GP, D>
where
    D: DB,
{
    root: Node,
    root_hash: H256,

    db: Arc<D>,

    // The batch of pending new nodes to write
    cache: C,
    passing_keys: GP,
    gen_keys: GP,
}

impl <C: Borrow<HashMap<H256, Vec<u8>>>, GP: Borrow<HashSet<H256>>, D: DB> Trie<D> for TrieRef<C, GP, D> {

    fn iter(&self) -> TrieIterator<D> {
        let nodes = vec![(self.root.clone()).into()];
        TrieIterator {
            db: self.db.as_ref(),
            nibble: Nibbles::from_raw(&[], false),
            nodes,
        }
    }
    
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>> {
        TrieOps::get(key, &self.root_hash, self.db.as_ref(), &self.root)
    }

    fn contains(&self, key: &[u8]) -> TrieResult<bool> {
        TrieOps::contains(key, &self.root_hash, self.db.as_ref(), &self.root)
    }

    fn verify_proof(
        &self,
        root_hash: H256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        TrieOps::verify_proof(root_hash, key, proof)
    }
}

impl <C: BorrowMut<HashMap<H256, Vec<u8>>>, GP: BorrowMut<HashSet<H256>>, D: DB> TrieMut<D> for TrieRef<C, GP, D> {

    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<()> {
        let node = TrieOps::insert(key, value, &self.root_hash, self.db.as_ref(), &mut self.root, self.passing_keys.borrow_mut())?;
        self.root = node;
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> TrieResult<bool> {
        let (root, res) = TrieOps::remove(key, &self.root_hash, self.db.as_ref(), &mut self.root, self.passing_keys.borrow_mut())?;
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

    fn commit(&mut self) -> TrieResult<H256> {
        let (root_hash, root) = TrieOps::commit(&self.root,  self.db.as_ref(), self.gen_keys.borrow_mut(), self.cache.borrow_mut(), self.passing_keys.borrow_mut())?;
        self.root = root;
        self.root_hash = root_hash;
        Ok(root_hash)
    }

    fn get_proof(&mut self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>> {
        TrieOps::get_proof(key, &self.root_hash, self.db.as_ref(), &self.root, self.gen_keys.borrow_mut(), self.cache.borrow_mut())
    }
}