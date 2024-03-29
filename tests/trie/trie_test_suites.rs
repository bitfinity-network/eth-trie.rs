use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

use keccak_hash::keccak;
use serde::{Deserialize, Serialize};

use super::trie_utils::{for_all_combinations, trie_test_with_actions, TrieAction};

#[derive(Deserialize)]
struct SequentialTestData {
    r#in: Vec<(String, Option<String>)>,
    root: String,
}

#[derive(Deserialize)]
struct TestsData<Test>(BTreeMap<String, Test>);

fn get_bytes(hex_str: &str) -> Cow<[u8]> {
    if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        hex::decode(&hex_str[2..]).unwrap().into()
    } else {
        hex_str.as_bytes().into()
    }
}

fn trie_sequential_test(test_data: &SequentialTestData, secured: bool) {
    let get_key = |key| -> Cow<[u8]> {
        let bytes = get_bytes(key);
        if secured {
            Cow::Owned(keccak(bytes.as_ref()).0.into())
        } else {
            bytes
        }
    };
    let actions = test_data
        .r#in
        .iter()
        .map(|(key, data)| match data {
            Some(value) => {
                TrieAction::Set(get_key(key).into_owned(), get_bytes(value).into_owned())
            }
            None => TrieAction::Delete(get_key(key).into_owned()),
        })
        .collect();

    // Act
        trie_test_with_actions(
            actions,
            Some((ethereum_types::H256::from_str(&test_data.root).unwrap()).into()),
        );

}

#[derive(Serialize, Deserialize)]
struct AnyOrderTestData {
    r#in: BTreeMap<String, String>,
    root: String,
}

fn trie_anyorder_test(test_data: &AnyOrderTestData, secured: bool) {
    let actions = test_data.r#in.iter().collect::<Vec<_>>();
    for_all_combinations(actions.len(), |combination| {
        let actions = combination
            .iter()
            .map(|index| {
                let action = actions[*index];
                (action.0.clone(), Some(action.1.clone()))
            })
            .collect::<Vec<_>>();
        let test_data = SequentialTestData {
            r#in: actions,
            root: test_data.root.clone(),
        };

        trie_sequential_test(&test_data, secured);
    });
}

fn load_test_suite<Test>(name: &str) -> TestsData<Test>
where
    for<'a> Test: Deserialize<'a>,
{
    let mut tests_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tests_dir.push("tests/trie/resources");

    let mut path = tests_dir.clone();
    path.push(format!("{name}.json"));

    let file = File::open(path).unwrap();
    let tests: TestsData<Test> = serde_json::from_reader(file).unwrap();

    tests
}

fn run_sequential_trie_test_suite(name: &str, secured: bool) {
    let tests = load_test_suite::<SequentialTestData>(name);
    for (_test_name, test_input) in tests.0 {
        trie_sequential_test(&test_input, secured);
    }
}

fn run_anyorder_test_suite(name: &str, secured: bool) {
    let tests = load_test_suite::<AnyOrderTestData>(name);
    for (_test_name, test_input) in tests.0 {
        trie_anyorder_test(&test_input, secured);
    }
}

// Trie test suites from https://github.com/ethereum/tests/blob/develop/TrieTests/trietestnextprev.json
// Each test suite contain a sequence of the trie operation and the expected root value
#[test]
fn test_sequential_actions() {
    run_sequential_trie_test_suite("trietest", false);
    run_sequential_trie_test_suite("trietest_secureTrie", true);
}

// Trie test suites from https://github.com/ethereum/tests/blob/develop/TrieTests/trietestnextprev.json
// Each test suite contain a set of the operations and the expected root value.
// Operations are supposed to be performed in all possible combinations.
#[test]
fn test_anyorder_actions() {
    run_anyorder_test_suite("trieanyorder", false);
    run_anyorder_test_suite("trieanyorder_secureTrie", true);
    run_anyorder_test_suite("hex_encoded_securetrie_test", true);
}
