use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use ethereum_types::H256;
use parking_lot::RwLock;

pub mod versioned;

use crate::errors::MemDBError;

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait DB {
    type Error: Error;

    fn contains(&self, key: &H256) -> Result<bool, Self::Error>;

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error>;

    fn len(&self) -> Result<u64, Self::Error>;

    fn is_empty(&self) -> Result<bool, Self::Error>;

}

pub trait DBMut: DB {
    /// Insert data into the cache.
    fn insert(&mut self, key: H256, value: Cow<[u8]>) -> Result<(), Self::Error>;

    /// Remove data with given key.
    fn remove(&mut self, key: &H256) -> Result<(), Self::Error>;
}

impl <D: DB> DB for Arc<RwLock<D>> {
    type Error = D::Error;

    fn contains(&self, key: &H256) -> Result<bool, Self::Error> {
        self.read().contains(key)
    }

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        self.read().get(key)
    }

    fn len(&self) -> Result<u64, Self::Error> {
        self.read().len()
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        self.read().is_empty()
    }
}

impl <D: DBMut> DBMut for Arc<RwLock<D>> {

    fn insert(&mut self, key: H256, value: Cow<[u8]>) -> Result<(), Self::Error> {
        self.write().insert(key, value)
    }

    fn remove(&mut self, key: &H256) -> Result<(), Self::Error> {
        self.write().remove(key)
    }
}

impl <D: DB> DB for &D {
    type Error = D::Error;

    fn contains(&self, key: &H256) -> Result<bool, Self::Error> {
        D::contains(*self, key)
    }

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        D::get(*self, key)
    }

    fn len(&self) -> Result<u64, Self::Error> {
        D::len(*self)
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        D::is_empty(*self)
    }

}

impl <D: DB> DB for &mut D {
    type Error = D::Error;

    fn contains(&self, key: &H256) -> Result<bool, Self::Error> {
        D::contains(*self, key)
    }

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        D::get(*self, key)
    }

    fn len(&self) -> Result<u64, Self::Error> {
        D::len(*self)
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        D::is_empty(*self)
    }

}

impl <D: DBMut> DBMut for &mut D {

    fn insert(&mut self, key: H256, value: Cow<[u8]>) -> Result<(), Self::Error> {
        D::insert(*self, key, value)
    }

    fn remove(&mut self, key: &H256) -> Result<(), Self::Error> {
        D::remove(*self, key)
    }

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

    fn contains(&self, key: &H256) -> Result<bool, Self::Error> {
        Ok(self.storage.contains_key(key))
    }

    fn get(&self, key: &H256) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(value) = self.storage.get(key) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        }
    }

    fn len(&self) -> Result<u64, Self::Error> {
        Ok(self.storage.len() as u64)
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.storage.is_empty())
    }
}

impl DBMut for MemoryDB {

    fn insert(&mut self, key: H256, value: Cow<[u8]>) -> Result<(), Self::Error> {
        self.storage.insert(key, value.into_owned());
        Ok(())
    }

    fn remove(&mut self, key: &H256) -> Result<(), Self::Error> {
        if self.light {
            self.storage.remove(key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_by_value() {
        let db = MemoryDB::new(true);
        assert_db_get(db);

        let db = MemoryDB::new(true);
        assert_db_remove(db);

        let db = MemoryDB::new(true);
        assert_db_len(db, true);
    }

    #[test]
    fn test_db_by_reference() {
        let mut db = MemoryDB::new(true);
        assert_db_get(&mut db);
        assert_db_remove(&mut db);
        assert_db_len(&mut db, false);
    }

    #[test]
    fn test_db_arc_by_ref() {
        let mut db = Arc::new(RwLock::new(MemoryDB::new(true)));
        assert_db_get(&mut db);
        assert_db_remove(&mut db);
        assert_db_len(&mut db, false);
    }

    #[test]
    fn test_db_arc_by_value() {
        let db = Arc::new(RwLock::new(MemoryDB::new(true)));
        assert_db_get(db.clone());
        assert_db_remove(db.clone());
        assert_db_len(db.clone(), false);
    }

    fn assert_db_get(mut db: impl DBMut) {
        let key = H256::from_low_u64_be(123654);
        db.insert(key, b"test-value".to_vec().into()).unwrap();
        let v = db.get(&key).unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    fn assert_db_remove(mut db: impl DBMut) {
        let key = H256::from_low_u64_be(3244);
        db.insert(key, b"test".to_vec().into()).unwrap();

        db.remove(&key).unwrap();
        let contains = db.get(&key).unwrap();
        assert_eq!(contains, None)
    }

    fn assert_db_len(db: impl DB, empty: bool) {
        if empty {
            assert_eq!(db.len().unwrap(), 0);
            assert!(db.is_empty().unwrap());
        } else {
            assert!(db.len().unwrap() > 0);
            assert!(!db.is_empty().unwrap());
        }
    }
}
