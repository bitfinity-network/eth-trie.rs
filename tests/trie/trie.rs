use std::sync::Arc;
use std::time::Instant;

use did::keccak::KECCAK_NULL_RLP;
use eth_trie::{EthTrie, MemoryDB, Trie};
use trie::hashed_storage::{CommittableHashStorage, MutableTransactionHashStorage};
use trie::storage_trie::{MutableTrie, PatriciaMerkleTrie, Trie as _};
use uuid::Uuid;

use super::hashed_storage_mock::MockPersistentStorage;
use super::trie_utils::{for_all_combinations, trie_test_with_actions, TrieAction};

pub fn with_trie<R>(f: impl FnOnce(&mut dyn MutableTrie) -> R) -> R {
    let mut persistent_storage = MockPersistentStorage::default();
    let transactional_storage = CommittableHashStorage::new(&mut persistent_storage);
    f(&mut PatriciaMerkleTrie::new(&transactional_storage, KECCAK_NULL_RLP).unwrap())
}

#[test]
fn empty_trie() {
    with_trie(|trie| {
        // Assert
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[0]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[0, 1]).unwrap(), None);
    });
}

#[test]
fn get_root() {
    with_trie(|trie| {
        // Arrange
        let value = [2, 3];

        // Act
        trie.set(&[], &value).unwrap();

        // Assert
        assert_eq!(trie.get(&[]).unwrap(), Some(&value[..]));
        assert_eq!(trie.get(&[0]).unwrap(), None);
        assert_eq!(trie.get(&[0, 1]).unwrap(), None);
    });
}

#[test]
fn get_single_byte() {
    with_trie(|trie| {
        // Arrange
        let value = [2, 3];

        // Act
        trie.set(&[1], &value).unwrap();

        // Assert
        assert_eq!(trie.get(&[1]).unwrap(), Some(&value[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[0]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2]).unwrap(), None);
    });
}

#[test]
fn get_two_bytes() {
    with_trie(|trie| {
        // Arrange
        let value = [2, 3];

        // Act
        trie.set(&[1, 2], &value).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2]).unwrap(), Some(&value[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 3]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), None);
    });
}

#[test]
fn get_three_bytes() {
    with_trie(|trie| {
        // Arrange
        let value = [2, 3];

        // Act
        trie.set(&[1, 2, 3], &value).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2]).unwrap(), None);
        assert_eq!(trie.get(&[1, 3, 3]).unwrap(), None);
        assert_eq!(trie.get(&[1, 3, 4]).unwrap(), None);
    });
}

#[test]
fn get_overwrite() {
    with_trie(|trie| {
        // Arrange
        let value = [2, 3];

        // Act
        trie.set(&[1, 2, 3], &[1, 2]).unwrap();
        trie.set(&[1, 2, 3], &value).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2]).unwrap(), None);
        assert_eq!(trie.get(&[1, 3, 3]).unwrap(), None);
        assert_eq!(trie.get(&[1, 3, 4]).unwrap(), None);
    });
}

#[test]
fn get_other_branch() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];

        // Act
        trie.set(&[1, 2, 3], &value_1).unwrap();
        trie.set(&[1, 4, 5], &value_2).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 4, 5]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2]).unwrap(), None);
    });
}

#[test]
fn get_child() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];

        // Act
        trie.set(&[1, 2, 3], &value_1).unwrap();
        trie.set(&[1, 2, 3, 4], &value_2).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 2, 3, 4]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 4]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 3, 5]).unwrap(), None);
    });
}

#[test]
fn get_parent() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];

        // Act
        trie.set(&[1, 2, 3, 4], &value_2).unwrap();
        trie.set(&[1, 2, 3], &value_1).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 2, 3, 4]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 4]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 3, 5]).unwrap(), None);
    });
}

#[test]
fn get_second_child() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];
        let value_3 = [6, 7];

        // Act
        trie.set(&[1, 2, 3], &value_1).unwrap();
        trie.set(&[1, 2, 3, 4], &value_2).unwrap();
        trie.set(&[1, 2, 3, 6, 7], &value_3).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 2, 3, 4]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[1, 2, 3, 6, 7]).unwrap(), Some(&value_3[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 4]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 3, 5]).unwrap(), None);
    });
}

#[test]
fn get_to_branch_node_parent() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];
        let value_3 = [6, 7];

        // Act
        trie.set(&[1, 2, 3, 4], &value_2).unwrap();
        trie.set(&[1, 2, 3, 6, 7], &value_3).unwrap();
        trie.set(&[1, 2, 3], &value_1).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 2, 3, 4]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[1, 2, 3, 6, 7]).unwrap(), Some(&value_3[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 4]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 3, 5]).unwrap(), None);
    });
}

#[test]
fn get_branch_node() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];
        let value_3 = [6, 7];

        // Act
        trie.set(&[1, 2, 3, 254], &value_2).unwrap();
        trie.set(&[1, 2, 3, 6, 7], &value_3).unwrap();
        trie.set(&[1, 2, 3], &value_1).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 2, 3, 254]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[1, 2, 3, 6, 7]).unwrap(), Some(&value_3[..]));
        assert_eq!(trie.get(&[]).unwrap(), None);
        assert_eq!(trie.get(&[1]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 4]).unwrap(), None);
        assert_eq!(trie.get(&[1, 2, 3, 5]).unwrap(), None);
    });
}

#[test]
fn get_extension_node_parent() {
    with_trie(|trie| {
        // Arrange
        let value_1 = [2, 3];
        let value_2 = [3, 4, 5];
        let value_3 = [6, 7];

        // Act
        trie.set(&[1, 2, 6, 7, 8], &value_1).unwrap();
        trie.set(&[1, 2, 3], &value_2).unwrap();
        trie.set(&[1, 2, 6, 7], &value_3).unwrap();

        // Assert
        assert_eq!(trie.get(&[1, 2, 6, 7, 8]).unwrap(), Some(&value_1[..]));
        assert_eq!(trie.get(&[1, 2, 3]).unwrap(), Some(&value_2[..]));
        assert_eq!(trie.get(&[1, 2, 6, 7]).unwrap(), Some(&value_3[..]));
    });
}

/// Check all the actions sequence to improve the test coverage
fn trie_test_with_all_actions_sequence(trie: &mut dyn MutableTrie, actions: Vec<TrieAction>) {
    for_all_combinations(actions.len(), |index_mapping| {
        let actions = index_mapping.iter().map(|i| actions[*i].clone()).collect();
        trie_test_with_actions(trie, actions, None);
    })
}

#[test]
fn insert_single_node() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![TrieAction::Set(vec![0x01], vec![2, 3])];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn insert_two_siblings() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
            TrieAction::Set(vec![0x01, 0x56], vec![4, 5]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn insert_to_branch_node() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
            TrieAction::Set(vec![0x01, 0x56], vec![4, 5]),
            TrieAction::Set(vec![0x01], vec![6, 7]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn insert_to_extension_node() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
            TrieAction::Set(vec![0x01, 0x56], vec![4, 5]),
            TrieAction::Set(vec![0x02], vec![6, 7]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn insert_new_child_to_branch() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
            TrieAction::Set(vec![0x01, 0x56], vec![4, 5]),
            TrieAction::Set(vec![0x01, 0x78], vec![6, 7]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn insert_update_leaf() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
            TrieAction::Set(vec![0x01, 0x56], vec![4, 5]),
            TrieAction::Set(vec![0x01, 0x56], vec![6, 7]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn insert_update_branch() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
            TrieAction::Set(vec![0x01, 0x56], vec![4, 5]),
            TrieAction::Set(vec![0x01], vec![6, 7]),
            TrieAction::Set(vec![0x01], vec![7, 8]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

fn fill_trie_actions() -> Vec<TrieAction> {
    vec![
        TrieAction::Set(vec![0x01, 0x34], vec![2, 3]),
        TrieAction::Set(vec![0x01, 0x34, 0x56], vec![3, 4]),
        TrieAction::Set(vec![0x01, 0x34, 0x67], vec![4, 5]),
        TrieAction::Set(vec![0x01, 0x56], vec![5, 6]),
        TrieAction::Set(vec![0x01], vec![6, 7]),
        TrieAction::Set(vec![0x02], vec![7, 8]),
    ]
}

#[test]
fn remove_from_empty_trie() {
    with_trie(|trie| {
        // Arrange
        let actions = vec![
            TrieAction::Delete(vec![]),
            TrieAction::Delete(vec![0x01]),
            TrieAction::Delete(vec![0x01, 0x02]),
        ];

        // Act
        trie_test_with_all_actions_sequence(trie, actions);
    });
}

#[test]
fn remove_non_existing_node() {
    with_trie(|trie| {
        for remove_addr in [vec![], vec![0x01], vec![0x01, 0x02]] {
            // Arrange
            let mut actions = fill_trie_actions();
            actions.push(TrieAction::Delete(remove_addr));

            // Act
            trie_test_with_all_actions_sequence(trie, actions);
        }
    });
}

#[test]
fn remove_leave_node() {
    with_trie(|trie| {
        for remove_addr in [vec![0x01, 0x34, 0x56], vec![0x01, 0x56], vec![0x02]] {
            // Arrange
            let mut actions = fill_trie_actions();
            actions.push(TrieAction::Delete(remove_addr));

            // Act
            trie_test_with_all_actions_sequence(trie, actions);
        }
    });
}

#[test]
fn remove_branch_node() {
    with_trie(|trie| {
        for remove_addr in [vec![0x01], vec![0x01, 0x34]] {
            // Arrange
            let mut actions = fill_trie_actions();
            actions.push(TrieAction::Delete(remove_addr));

            // Act
            trie_test_with_all_actions_sequence(trie, actions);
        }
    });
}

#[test]
fn remove_children_and_branch() {
    with_trie(|trie| {
        // Arrange
        let mut actions = fill_trie_actions();
        actions.extend([
            TrieAction::Delete(vec![0x01, 0x34, 0x56]),
            TrieAction::Delete(vec![0x01, 0x34, 0x67]),
            TrieAction::Delete(vec![0x01, 0x34]),
        ]);

        // Act
        trie_test_with_actions(trie, actions, None);
    });
}

#[test]
fn clear_trie_empty() {
    with_trie(|trie| {
        // Arrange

        // Act
        trie.clear().unwrap();

        // Assert
        assert_eq!(trie.root(), &KECCAK_NULL_RLP);
    });
}

#[test]
fn clear_trie_non_empty() {
    with_trie(|trie| {
        // Arrange
        trie.set(&[1, 2, 3], &[1, 2]).unwrap();
        trie.set(&[1, 2], &[2, 3]).unwrap();

        // Act
        trie.clear().unwrap();

        // Assert
        assert_eq!(trie.root(), &KECCAK_NULL_RLP);
    });
}

#[test]
fn test_storage_trie() {
    use trie::storage_trie::Trie;


        for i in 1..=3 {

            let mut persistent_storage = MockPersistentStorage::default();
            let transactional_storage = CommittableHashStorage::new(&mut persistent_storage);
            let mut trie = PatriciaMerkleTrie::new(&transactional_storage, KECCAK_NULL_RLP).unwrap();

            let entries = 1_000_000;
            let (keys, values) = random_data(entries);
            
            println!("-------------------------");
            println!("Attempt {i}");
            println!("-------------------------");
            println!("Evmc Trie");
                let start = Instant::now();
                for i in 0..keys.len() {
                    trie.set(&keys[i], &values[i]).unwrap();
                    trie.set(&keys[i], &values[i]).unwrap();
                }
                let duration = start.elapsed();
                println!("Time to insert {} entries is:   {:?}", entries, duration);

                let our_hash_root = trie.root().clone();
                drop(trie);
                transactional_storage.commit();
                println!("persistent_storage.map.len(): {}", persistent_storage.map.len());

                let transactional_storage = CommittableHashStorage::new(&mut persistent_storage);
                let mut trie = PatriciaMerkleTrie::new(&transactional_storage, our_hash_root.clone()).unwrap();
                
                let start = Instant::now();
                for i in 0..keys.len() {
                    trie.set(&keys[i], &values[i]).unwrap();
                    trie.set(&keys[i], &values[i]).unwrap();
                }
                let duration = start.elapsed();
                println!("Time to insert {} entries is:   {:?}", entries, duration);

                let our_hash_root = trie.root().clone();
                drop(trie);
                transactional_storage.commit();
                println!("persistent_storage.map.len(): {}", persistent_storage.map.len());

                let transactional_storage = CommittableHashStorage::new(&mut persistent_storage);
                let mut trie = PatriciaMerkleTrie::new(&transactional_storage, our_hash_root.clone()).unwrap();
                

                let start = Instant::now();
                for i in 0..keys.len() {
                    assert!(trie.get(&keys[i]).unwrap().is_some());
                }
                let duration = start.elapsed();
                println!("Time to read {} entries is:     {:?}", entries, duration);
            
                let start = Instant::now();
                for i in 0..keys.len() {
                    trie.delete(&keys[i]).unwrap();
                }
                let duration = start.elapsed();
                println!("Time to delete {} entries is:   {:?}", entries, duration);
                drop(trie);
                transactional_storage.commit();
                println!("persistent_storage.map.len(): {}", persistent_storage.map.len());

            

            //trie.clear().unwrap();







            println!("-------------------------");
            println!("EthTrie");
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = EthTrie::new(memdb.clone());
            
                let start = Instant::now();
                for i in 0..keys.len() {
                    trie.insert(&keys[i], &values[i]).unwrap()
                }
                let duration = start.elapsed();
                println!("Time to insert {} entries is:   {:?}", entries, duration);

                
                let start = Instant::now();
                for i in 0..keys.len() {
                    assert!(trie.get(&keys[i]).unwrap().is_some());
                }
                let duration = start.elapsed();
                println!("Time to read {} entries is:     {:?}", entries, duration);
                
                let their_hash_root = trie.root_hash().unwrap().clone();
                let start = Instant::now();
                for i in 0..keys.len() {
                    trie.remove(&keys[i]).unwrap();
                }
                let duration = start.elapsed();
                println!("Time to delete {} entries is:   {:?}", entries, duration);


                assert_eq!(our_hash_root.0, their_hash_root);

        }


}

fn random_data(n: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys = Vec::with_capacity(n);
    let mut values = Vec::with_capacity(n);
    for _ in 0..n {
        let key = Uuid::new_v4().as_bytes().to_vec();
        let value = Uuid::new_v4().as_bytes().to_vec();
        keys.push(key);
        values.push(value);
    }

    (keys, values)
}
