use std::{collections::HashMap, sync::{atomic::{AtomicU64, Ordering}, Arc}};

use keccak_hash::H256;
use parking_lot::RwLock;

use crate::{MemDBError, DB};

/// A database that stores a fixed number of versions of the data.
pub struct VersionedDB {
    current_version: AtomicU64,
    version_size: u64,
    storage: Arc<RwLock<HashMap<H256, Vec<u8>>>>,
    deleted_at_version: Arc<RwLock<HashMap<H256, u64>>>,
}

impl VersionedDB {
    /// Create a new versioned database with the given version size.
    pub fn new(version_size: u64) -> Self {
        VersionedDB {
            current_version: AtomicU64::new(0),
            version_size,
            storage: Arc::new(RwLock::new(HashMap::new())),
            deleted_at_version: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Commit the current version and remove all data that is older than the current version minus the version size.
    pub fn commit_version(&self, new_version: Option<u64>) {
        let mut storage = self.storage.write();
        let mut deleted_at_version = self.deleted_at_version.write();
        let mut deleted_keys = Vec::new();

        let current_version = if let Some(new_version) = new_version {
            self.current_version.store(new_version, Ordering::Relaxed);
            new_version
        } else {
            let add = 1;
            self.current_version.fetch_add(add, Ordering::Relaxed) + add
        };

        for (key, version) in deleted_at_version.iter() {
            if (*version + self.version_size) < current_version {
                storage.remove(key);
                deleted_keys.push(*key);
            }
        }

        for key in deleted_keys {
            deleted_at_version.remove(&key);
        }
    }

    // returns the current version
    pub fn get_version(&self) -> u64 {
        self.current_version.load(Ordering::Relaxed)
    }

    // returns the number of versions stored
    pub fn get_version_size(&self) -> u64 {
        self.version_size
    }
}

impl DB for VersionedDB {
    type Error = MemDBError;

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        let storage = self.storage.read();
        Ok(storage.get(key).cloned())
    }

    fn insert(&self, key: H256, value: Vec<u8>) -> Result<(), Self::Error> {
        let mut storage = self.storage.write();
        if let Some(_) = storage.insert(key.clone(), value) {
            self.deleted_at_version.write().remove(&key);
        }
        Ok(())
    }

    fn remove(&self, key: &H256) -> Result<(), Self::Error> {
        self.deleted_at_version.write().insert(*key, self.current_version.load(Ordering::Relaxed));
        Ok(())
    }

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.storage.try_read().unwrap().len())
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.storage.try_read().unwrap().is_empty())
    }

}

#[cfg(test)]
mod test {

    use crate::{EthTrie, Trie};

    use super::*;

    // Test that entries are not deleted before the version is committed
    #[test]
    fn test_versioned_db() {
        let db = VersionedDB::new(10);
        assert_eq!(db.get_version(), 0);
        assert_eq!(db.get_version_size(), 10);

        let key = H256::zero();
        let value = vec![1, 2, 3, 4];
        db.insert(key, value.clone()).unwrap();
        assert_eq!(db.get(&key).unwrap().unwrap(), value);

        db.remove(&key).unwrap();
        assert!(db.get(&key).unwrap().is_some());

        db.commit_version(None);
        assert_eq!(db.get_version(), 1);
        assert_eq!(db.get_version_size(), 10);
        assert!(db.get(&key).unwrap().is_some());

        db.commit_version(Some(10));
        assert!(db.get(&key).unwrap().is_some());

        db.commit_version(Some(11));
        assert_eq!(db.get_version(), 11);
        assert_eq!(db.get_version_size(), 10);
        assert!(db.get(&key).unwrap().is_none());

    }



    #[test]
    fn test_versioned_db_should_enter_delete_enter_fine() {
        let db = VersionedDB::new(1);

        let key = H256::zero();
        let value = vec![1, 2, 3, 4];

        db.insert(key, value.clone()).unwrap();
        assert_eq!(db.get(&key).unwrap().unwrap(), value);
        db.remove(&key).unwrap();
        assert!(db.get(&key).unwrap().is_some());

        db.commit_version(None);
        assert!(db.get(&key).unwrap().is_some());

        db.insert(key, value.clone()).unwrap();

        db.commit_version(Some(2));
        assert!(db.get(&key).unwrap().is_some());

    }

    #[test]
    fn versioned_db_should_keep_fixed_number_of_versions() {
        let db = Arc::new(VersionedDB::new(10));

        let mut trie = EthTrie::new(db.clone());
        trie.insert(b"test", b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), trie.get(b"test").unwrap());

        // Committed at version 0
        let root_zero = trie.root_hash().unwrap();
        db.commit_version(None);

        let mut trie = EthTrie::new(db.clone()).at_root(root_zero);
        assert_eq!(Some(b"test".to_vec()), trie.get(b"test").unwrap());
        trie.remove(b"test").unwrap();

        // Committed at version 1
        let root_one = trie.root_hash().unwrap();
        db.commit_version(None);

        let mut trie = EthTrie::new(db.clone()).at_root(root_one);
        assert_eq!(None, trie.get(b"test").unwrap());
        trie.insert(b"test", b"test_2").unwrap();

        // Committed at version 2
        let root_two = trie.root_hash().unwrap();
        db.commit_version(None);

        let trie = EthTrie::new(db.clone()).at_root(root_zero);
        assert_eq!(Some(b"test".to_vec()), trie.get(b"test").unwrap());

        let trie = EthTrie::new(db.clone()).at_root(root_two);
        assert_eq!(Some(b"test_2".to_vec()), trie.get(b"test").unwrap());

        db.commit_version(Some(12));

        // This should have been removed
        let trie = EthTrie::new(db.clone()).at_root(root_zero);
        assert!(trie.get(b"test").is_err());

        let trie = EthTrie::new(db.clone()).at_root(root_one);
        assert_eq!(None, trie.get(b"test").unwrap());

        let trie = EthTrie::new(db.clone()).at_root(root_two);
        assert_eq!(Some(b"test_2".to_vec()), trie.get(b"test").unwrap());

        db.commit_version(Some(100));
      
        let trie = EthTrie::new(db.clone()).at_root(root_two);
        assert_eq!(Some(b"test_2".to_vec()), trie.get(b"test").unwrap());

    }
}