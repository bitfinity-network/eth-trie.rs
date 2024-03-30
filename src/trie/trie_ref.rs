use std::borrow::BorrowMut;

use keccak_hash::H256;

use crate::{nibbles::Nibbles, node::Node, Trie, DB};

use super::{ops::TrieOps, TrieCache, TrieIterator, TrieKeys, TrieResult};

#[derive(Debug)]
pub struct TrieRef<C, GP, R, D: DB>
{
    root: Node,
    root_hash: H256,

    db: R,

    cache: C,
    passing_keys: GP,
    gen_keys: GP,
    phantom_d: std::marker::PhantomData<D>,
}

impl <C, GP, R, D: DB> TrieRef<C, GP, R, D> {
    pub fn new(root: Node, root_hash: H256, db: R, cache: C, passing_keys: GP, gen_keys: GP) -> Self {
        Self {
            root,
            root_hash,
            db,
            cache,
            passing_keys,
            gen_keys,
            phantom_d: std::marker::PhantomData,
        }
    }
}

impl <C: BorrowMut<TrieCache>, GP: BorrowMut<TrieKeys>, R: BorrowMut<D>, D: DB> Trie<D> for TrieRef<C, GP, R, D> {

    fn uncommitted_root(&self) -> H256 {
        self.root_hash
    }

    fn iter(&self) -> TrieIterator<D> {
        let nodes = vec![(self.root.clone()).into()];
        TrieIterator {
            db: self.db.borrow(),
            nibble: Nibbles::from_raw(&[], false),
            nodes,
        }
    }
    
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>> {
        TrieOps::get(key, &self.root_hash, self.db.borrow(), &self.root)
    }

    fn contains(&self, key: &[u8]) -> TrieResult<bool> {
        TrieOps::contains(key, &self.root_hash, self.db.borrow(), &self.root)
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
        let node = TrieOps::insert(key, value, &self.root_hash, self.db.borrow_mut(), &mut self.root, self.passing_keys.borrow_mut())?;
        self.root = node;
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> TrieResult<bool> {
        let (root, res) = TrieOps::remove(key, &self.root_hash, self.db.borrow_mut(), &mut self.root, self.passing_keys.borrow_mut())?;
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
        TrieOps::get_proof(key, &self.root_hash, self.db.borrow_mut(), &self.root, self.gen_keys.borrow_mut(), self.cache.borrow_mut())
    }
    
}