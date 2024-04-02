use std::borrow::Cow;

use hashbrown::HashMap;
use keccak_hash::H256;

use crate::{MemDBError, DB};

/// A database that stores a fixed number of versions of the data.
pub struct VersionedDB {
    current_version: u64,
    version_size: u64,
    storage: HashMap<H256, Vec<u8>>,
    deleted_at_version: HashMap<H256, u64>,
}

impl VersionedDB {
    /// Create a new versioned database with the given version size.
    pub fn new(version_size: u64) -> Self {
        VersionedDB {
            current_version: 0,
            version_size,
            storage: HashMap::new(),
            deleted_at_version: HashMap::new(),
        }
    }

    /// Commit the current version and remove all data that is older than the current version minus the version size.
    pub fn commit_version(&mut self, new_version: Option<u64>) {
        
        let mut deleted_keys = Vec::new();

        self.current_version = if let Some(new_version) = new_version {
            new_version
        } else {
            self.current_version + 1
        };

        for (key, version) in self.deleted_at_version.iter() {
            if (*version + self.version_size) < self.current_version {
                self.storage.remove(key);
                deleted_keys.push(*key);
            }
        }

        for key in deleted_keys {
            self.deleted_at_version.remove(&key);
        }
    }

    // returns the current version
    pub fn get_version(&self) -> u64 {
        self.current_version
    }

    // returns the number of versions stored
    pub fn get_version_size(&self) -> u64 {
        self.version_size
    }
}

impl DB for VersionedDB {
    type Error = MemDBError;

    fn contains(&self, key: &H256) -> Result<bool, Self::Error> {
        Ok(self.storage.contains_key(key))
    }
    
    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.storage.get(key).cloned())
    }

    fn insert(&mut self, key: H256, value: Cow<[u8]>) -> Result<(), Self::Error> {
        if let Some(_) = self.storage.insert(key.clone(), value.into_owned()) {
            self.deleted_at_version.remove(&key);
        }
        Ok(())
    }

    fn remove(&mut self, key: &H256) -> Result<(), Self::Error> {
        self.deleted_at_version.insert(*key, self.current_version);
        Ok(())
    }

    fn len(&self) -> Result<u64, Self::Error> {
        Ok(self.storage.len() as u64)
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.storage.is_empty())
    }

}

#[cfg(test)]
mod test {

    use crate::*;
    use super::*;

    // Test that entries are not deleted before the version is committed
    #[test]
    fn test_versioned_db() {
        let mut db = VersionedDB::new(10);
        assert_eq!(db.get_version(), 0);
        assert_eq!(db.get_version_size(), 10);

        let key = H256::zero();
        let value = vec![1, 2, 3, 4];
        db.insert(key, value.clone().into()).unwrap();
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
        let mut db = VersionedDB::new(1);

        let key = H256::zero();
        let value = vec![1, 2, 3, 4];

        db.insert(key, value.clone().into()).unwrap();
        assert_eq!(db.get(&key).unwrap().unwrap(), value);
        db.remove(&key).unwrap();
        assert!(db.get(&key).unwrap().is_some());

        db.commit_version(None);
        assert!(db.get(&key).unwrap().is_some());

        db.insert(key, value.clone().into()).unwrap();

        db.commit_version(Some(2));
        assert!(db.get(&key).unwrap().is_some());

    }

    #[test]
    fn versioned_db_should_keep_fixed_number_of_versions() {
        let mut db = VersionedDB::new(10);

        let mut trie = EthTrie::new(&mut db);
        trie.insert(b"test", b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), trie.get(b"test").unwrap());

        // Committed at version 0
        let root_zero = trie.commit().unwrap();
        db.commit_version(None);

        let mut trie = EthTrie::with_root(&mut db,root_zero);
        assert_eq!(Some(b"test".to_vec()), trie.get(b"test").unwrap());
        trie.remove(b"test").unwrap();

        // Committed at version 1
        let root_one = trie.commit().unwrap();
        db.commit_version(None);

        let mut trie = EthTrie::with_root(&mut db,root_one);
        assert_eq!(None, trie.get(b"test").unwrap());
        trie.insert(b"test", b"test_2").unwrap();

        // Committed at version 2
        let root_two = trie.commit().unwrap();
        db.commit_version(None);

        let trie = EthTrie::with_root(&mut db, root_zero);
        assert_eq!(Some(b"test".to_vec()), trie.get(b"test").unwrap());

        let trie = EthTrie::with_root(&mut db, root_two);
        assert_eq!(Some(b"test_2".to_vec()), trie.get(b"test").unwrap());

        db.commit_version(Some(12));

        // This should have been removed
        let trie = EthTrie::with_root(&mut db, root_zero);
        assert!(trie.get(b"test").is_err());

        let trie = EthTrie::with_root(&mut db, root_one);
        assert_eq!(None, trie.get(b"test").unwrap());

        let trie = EthTrie::with_root(&mut db, root_two);
        assert_eq!(Some(b"test_2".to_vec()), trie.get(b"test").unwrap());

        db.commit_version(Some(100));
      
        let trie = EthTrie::with_root(&mut db, root_two);
        assert_eq!(Some(b"test_2".to_vec()), trie.get(b"test").unwrap());

    }
}