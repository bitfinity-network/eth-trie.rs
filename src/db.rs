use std::collections::HashMap;
use std::error::Error;
use ethereum_types::H256;

pub mod versioned;

use crate::errors::MemDBError;

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait DB {
    type Error: Error;

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Insert data into the cache.
    fn insert(&mut self, key: H256, value: Vec<u8>) -> Result<(), Self::Error>;

    /// Remove data with given key.
    fn remove(&mut self, key: &H256) -> Result<(), Self::Error>;

    /// Insert a batch of data into the cache.
    fn insert_batch(&mut self, mut keys: Vec<H256>, mut values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        while let (Some(key), Some(value)) = (keys.pop(), values.pop()) {
            self.insert(key, value)?;
        }
        Ok(())
    }

    /// Remove a batch of data into the cache.
    fn remove_batch(&mut self, keys: &[&H256]) -> Result<(), Self::Error> {
        for key in keys {
            self.remove(key)?;
        }
        Ok(())
    }

    fn len(&self) -> Result<usize, Self::Error>;

    fn is_empty(&self) -> Result<bool, Self::Error>;

}

#[derive(Default, Debug)]
pub struct MemoryDB {
    // If "light" is true, the data is deleted from the database at the time of submission.
    light: bool,
    storage: HashMap<H256, Vec<u8>>,
}

impl MemoryDB {
    pub fn new(light: bool) -> Self {
        MemoryDB {
            light,
            storage: HashMap::new(),
        }
    }
}

impl DB for MemoryDB {
    type Error = MemDBError;

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(value) = self.storage.get(key) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        }
    }

    fn insert(&mut self, key: H256, value: Vec<u8>) -> Result<(), Self::Error> {
        self.storage.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &H256) -> Result<(), Self::Error> {
        if self.light {
            self.storage.remove(key);
        }
        Ok(())
    }

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.storage.len())
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.storage.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_get() {
        let mut memdb = MemoryDB::new(true);
        let key = H256::from_low_u64_be(123654);
        memdb.insert(key, b"test-value".to_vec()).unwrap();
        let v = memdb.get(&key).unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_memdb_remove() {
        let mut memdb = MemoryDB::new(true);
        let key = H256::from_low_u64_be(3244);
        memdb.insert(key, b"test".to_vec()).unwrap();

        memdb.remove(&key).unwrap();
        let contains = memdb.get(&key).unwrap();
        assert_eq!(contains, None)
    }
}
