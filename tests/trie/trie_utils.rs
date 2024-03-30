use std::collections::BTreeMap;

use eth_trie::*;
use keccak_hash::H256;

#[derive(Clone)]
pub enum TrieAction {
    Set(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

// Check if trie content corresponds to the map
pub fn check_trie(trie: &EthTrie<&mut MemoryDB>, expected_data: &BTreeMap<Vec<u8>, Vec<u8>>) {
    // Check that all values in map are accessible
    for (key, value) in expected_data {
        assert_eq!(trie.get(key).unwrap(), Some(value.to_owned()));
    }

    // Check that tree data corresponds to the map
    let trie_data = trie
        .iter()
        .map(|(k, v)| (k, v.to_vec()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(&trie_data, expected_data);
}

pub fn trie_test_with_actions(
    actions: Vec<TrieAction>,
    expected_root: Option<H256>,
) {
    // Arrange
    let mut db = MemoryDB::new(true);
    let mut trie = EthTrie::new(&mut db);
    let mut roots = Vec::new();
    let mut storage = BTreeMap::<Vec<u8>, Vec<u8>>::new();

    // Do the actions
    for action in actions {
        roots.push(trie.commit().unwrap());

        match action {
            TrieAction::Set(key, val) => {
                trie.insert(key.as_ref(), val.as_ref()).unwrap();

                storage.insert(key.clone(), val.clone());
            }
            TrieAction::Delete(key) => {
                storage.remove(&key);
                trie.remove(key.as_ref()).unwrap();
            }
        }

        check_trie(&trie, &storage);
    }

    if let Some(expected) = &expected_root {
        assert_eq!(trie.commit().unwrap(), *expected);
    }

}

pub fn for_all_combinations(len: usize, mut f: impl FnMut(&[usize])) {
    let mut indices_used = vec![false; len];
    let mut current_slice = vec![0; len];

    fn for_all_combinations_from_n(
        index: usize,
        indices_used: &mut [bool],
        current_slice: &mut [usize],
        f: &mut impl FnMut(&[usize]),
    ) {
        if index == current_slice.len() {
            return f(current_slice);
        }

        for current_index in 0..indices_used.len() {
            if !indices_used[current_index] {
                indices_used[current_index] = true;
                current_slice[index] = current_index;
                for_all_combinations_from_n(index + 1, indices_used, current_slice, f);
                indices_used[current_index] = false;
            }
        }
    }

    for_all_combinations_from_n(0, &mut indices_used, &mut current_slice, &mut f);
}
