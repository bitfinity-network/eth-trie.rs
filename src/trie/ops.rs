use std::sync::Arc;

use ethereum_types::H256;
use hashbrown::{HashMap, HashSet};
use keccak_hash::keccak;
use parking_lot::RwLock;
use rlp::{Prototype, Rlp, RlpStream};

use crate::db::{MemoryDB, DB};
use crate::errors::TrieError;
use crate::nibbles::Nibbles;
use crate::node::{empty_children, BranchNode, Node};
use crate::{EthTrie, Trie};

use super::{EncodedNode, TrieResult, HASHED_LENGTH};

pub struct TrieOps;

impl TrieOps {
    
    pub fn get<D: DB>(key: &[u8], root_hash: &H256,
        db: &D,
        root: &Node,) -> TrieResult<Option<Vec<u8>>> {
        
        let path = &Nibbles::from_raw(key, true);
        let result = Self::get_at(root_hash, db,  root, path, 0);
        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            result
        }
    }

    pub fn contains<D: DB>(key: &[u8], root_hash: &H256,
        db: &D,
        root: &Node,) -> TrieResult<bool> {
        let path = &Nibbles::from_raw(key, true);
        Ok(Self::get_at(root_hash, db,  root, path, 0)?.map_or(false, |_| true))
    }

    pub fn insert<D: DB>(key: &[u8], value: &[u8], root_hash: &H256,
        db: &D,
        root: &Node,
        passing_keys: &mut HashSet<H256>
    ) -> TrieResult<Node> {
        if value.is_empty() {
            let (node, _) = Self::remove(key, root_hash, db, root, passing_keys)?;
            return Ok(node);
        }
        let path = &Nibbles::from_raw(key, true);
        let result = Self::insert_at(root_hash, root, db, path, 0, value.to_vec(), passing_keys);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            Ok(result?)
        }
    }

    pub fn remove<D: DB>(key: &[u8], root_hash: &H256,
        db: &D,
        root: &Node,
        passing_keys: &mut HashSet<H256>,
    ) -> TrieResult<(Node, bool)> {
        let path = &Nibbles::from_raw(key, true);
        let result = Self::delete_at(root_hash, root, db, path, 0, passing_keys);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            let (n, removed) = result?;
            Ok((n, removed))
        }
    }

    pub fn get_proof<D: DB>(key: &[u8], root_hash: &H256,
        db: &D,
        root: &Node, gen_keys: &mut HashSet<H256>, cache: &mut HashMap<H256, Vec<u8>>) -> TrieResult<Vec<Vec<u8>>> {
        let key_path = &Nibbles::from_raw(key, true);
        let result = Self::get_path_at(root_hash, root, db, key_path, 0);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            let mut path = result?;
            match root {
                Node::Empty => {}
                _ => path.push(root.clone()),
            }
            Ok(path
                .into_iter()
                .rev()
                .map(|n| Self::encode_raw(&n, gen_keys, cache))
                .collect())
        }
    }

    pub fn verify_proof(
        root_hash: H256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        let mut proof_db = MemoryDB::new(true);
        for node_encoded in proof.into_iter() {
            let hash: H256 = keccak(&node_encoded).as_fixed_bytes().into();

            if root_hash.eq(&hash) || node_encoded.len() >= HASHED_LENGTH {
                proof_db.insert(hash, node_encoded.into()).unwrap();
            }
        }
        let trie = EthTrie::with_root(&mut proof_db, root_hash);
        trie.get(key).or(Err(TrieError::InvalidProof))
    }

    fn get_at<D: DB>(
        root_hash: &H256,
        db: &D,
        source_node: &Node,
        path: &Nibbles,
        path_index: usize,
    ) -> TrieResult<Option<Vec<u8>>> {
        let partial = &path.offset(path_index);
        match source_node {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                if &leaf.key == partial {
                    Ok(Some(leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.read();

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(borrow_branch.value.clone())
                } else {
                    let index = partial.at(0);
                    Self::get_at(root_hash, db, &borrow_branch.children[index], path, path_index + 1)
                }
            }
            Node::Extension(extension) => {
                let extension = extension.read();

                let prefix = &extension.prefix;
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    Self::get_at(root_hash, db, &extension.node, path, path_index + match_len)
                } else {
                    Ok(None)
                }
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                let node =
                    Self::recover_from_db(db, &node_hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(*root_hash),
                            err_key: None,
                        })?;
                Self::get_at(root_hash, db, &node, path, path_index)
            }
        }
    }

    fn insert_at<D: DB>(
        root_hash: &H256,
        n: &Node,
        db: &D,
        path: &Nibbles,
        path_index: usize,
        value: Vec<u8>,
        passing_keys: &mut HashSet<H256>,
    ) -> TrieResult<Node> {
        let partial = path.offset(path_index);
        match n {
            Node::Empty => Ok(Node::from_leaf(partial, value)),
            Node::Leaf(leaf) => {
                let old_partial = &leaf.key;
                let match_index = partial.common_prefix(old_partial);
                if match_index == old_partial.len() {
                    return Ok(Node::from_leaf(leaf.key.clone(), value));
                }

                let mut branch = BranchNode {
                    children: empty_children(),
                    value: None,
                };

                let n = Node::from_leaf(old_partial.offset(match_index + 1), leaf.value.clone());
                branch.insert(old_partial.at(match_index), n);

                let n = Node::from_leaf(partial.offset(match_index + 1), value);
                branch.insert(partial.at(match_index), n);

                if match_index == 0 {
                    return Ok(Node::Branch(Arc::new(RwLock::new(branch))));
                }

                // if include a common prefix
                Ok(Node::from_extension(
                    partial.slice(0, match_index),
                    Node::Branch(Arc::new(RwLock::new(branch))),
                ))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.write();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = Some(value);
                    return Ok(Node::Branch(branch.clone()));
                }

                let child = borrow_branch.children[partial.at(0)].clone();
                let new_child = Self::insert_at(root_hash, &child, db, path, path_index + 1, value, passing_keys)?;
                borrow_branch.children[partial.at(0)] = new_child;
                Ok(Node::Branch(branch.clone()))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.write();

                let prefix = &borrow_ext.prefix;
                let sub_node = borrow_ext.node.clone();
                let match_index = partial.common_prefix(prefix);

                if match_index == 0 {
                    let mut branch = BranchNode {
                        children: empty_children(),
                        value: None,
                    };
                    branch.insert(
                        prefix.at(0),
                        if prefix.len() == 1 {
                            sub_node
                        } else {
                            Node::from_extension(prefix.offset(1), sub_node)
                        },
                    );
                    let node = Node::Branch(Arc::new(RwLock::new(branch)));

                    return Self::insert_at(root_hash, &node, db, path, path_index, value, passing_keys);
                }

                if match_index == prefix.len() {
                    let new_node =
                        Self::insert_at(root_hash, &sub_node, db, path, path_index + match_index, value, passing_keys)?;
                    return Ok(Node::from_extension(prefix.clone(), new_node));
                }

                let new_ext = Node::from_extension(prefix.offset(match_index), sub_node);
                let new_node = Self::insert_at(root_hash, &new_ext, db,  path, path_index + match_index, value, passing_keys)?;
                borrow_ext.prefix = prefix.slice(0, match_index);
                borrow_ext.node = new_node;
                Ok(Node::Extension(ext.clone()))
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                passing_keys.insert(node_hash);
                let node =
                    Self::recover_from_db(db, &node_hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(*root_hash),
                            err_key: None,
                        })?;
                Self::insert_at(root_hash, &node, db, path, path_index, value, passing_keys)
            }
        }
    }

    fn delete_at<D: DB>(
        root_hash: &H256,
        old_node: &Node,
        db: &D,
        path: &Nibbles,
        path_index: usize,
        passing_keys: &mut HashSet<H256>,
    ) -> TrieResult<(Node, bool)> {
        let partial = &path.offset(path_index);
        let (new_node, deleted) = match old_node {
            Node::Empty => Ok((Node::Empty, false)),
            Node::Leaf(leaf) => {
                if &leaf.key == partial {
                    return Ok((Node::Empty, true));
                }
                Ok((Node::Leaf(leaf.clone()), false))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.write();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = None;
                    return Ok((Node::Branch(branch.clone()), true));
                }

                let index = partial.at(0);
                let child = &borrow_branch.children[index];

                let (new_child, deleted) = Self::delete_at(root_hash, child, db, path, path_index + 1, passing_keys)?;
                if deleted {
                    borrow_branch.children[index] = new_child;
                }

                Ok((Node::Branch(branch.clone()), deleted))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.write();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    let (new_node, deleted) =
                        Self::delete_at(root_hash, &borrow_ext.node, db, path, path_index + match_len, passing_keys)?;

                    if deleted {
                        borrow_ext.node = new_node;
                    }

                    Ok((Node::Extension(ext.clone()), deleted))
                } else {
                    Ok((Node::Extension(ext.clone()), false))
                }
            }
            Node::Hash(hash_node) => {
                let hash = hash_node.hash;
                passing_keys.insert(hash);

                let node =
                    Self::recover_from_db(db, &hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash: hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(*root_hash),
                            err_key: None,
                        })?;
                Self::delete_at(root_hash, &node, db, path, path_index, passing_keys)
            }
        }?;

        if deleted {
            Ok((Self::degenerate(root_hash, new_node, db, passing_keys)?, deleted))
        } else {
            Ok((new_node, deleted))
        }
    }

    // This refactors the trie after a node deletion, as necessary.
    // For example, if a deletion removes a child of a branch node, leaving only one child left, it
    // needs to be modified into an extension and maybe combined with its parent and/or child node.
    fn degenerate<D: DB>(root_hash: &H256, n: Node, db: &D, passing_keys: &mut HashSet<H256>) -> TrieResult<Node> {
        match n {
            Node::Branch(branch) => {
                let borrow_branch = branch.read();

                let mut used_indexs = vec![];
                for (index, node) in borrow_branch.children.iter().enumerate() {
                    match node {
                        Node::Empty => continue,
                        _ => used_indexs.push(index),
                    }
                }

                // if only a value node, transmute to leaf.
                if used_indexs.is_empty() && borrow_branch.value.is_some() {
                    let key = Nibbles::from_raw(&[], true);
                    let value = borrow_branch.value.clone().unwrap();
                    Ok(Node::from_leaf(key, value))
                // if only one node. make an extension.
                } else if used_indexs.len() == 1 && borrow_branch.value.is_none() {
                    let used_index = used_indexs[0];
                    let n = borrow_branch.children[used_index].clone();

                    let new_node = Node::from_extension(Nibbles::from_hex(&[used_index as u8]), n);
                    Self::degenerate(root_hash, new_node, db, passing_keys)
                } else {
                    Ok(Node::Branch(branch.clone()))
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.read();

                let prefix = &borrow_ext.prefix;
                match borrow_ext.node.clone() {
                    Node::Extension(sub_ext) => {
                        let borrow_sub_ext = sub_ext.read();

                        let new_prefix = prefix.join(&borrow_sub_ext.prefix);
                        let new_n = Node::from_extension(new_prefix, borrow_sub_ext.node.clone());
                        Self::degenerate(root_hash, new_n, db, passing_keys)
                    }
                    Node::Leaf(leaf) => {
                        let new_prefix = prefix.join(&leaf.key);
                        Ok(Node::from_leaf(new_prefix, leaf.value.clone()))
                    }
                    // try again after recovering node from the db.
                    Node::Hash(hash_node) => {
                        let node_hash = hash_node.hash;
                        passing_keys.insert(node_hash);

                        let new_node =
                            Self::recover_from_db(db, &node_hash)?
                                .ok_or(TrieError::MissingTrieNode {
                                    node_hash,
                                    traversed: None,
                                    root_hash: Some(*root_hash),
                                    err_key: None,
                                })?;

                        let n = Node::from_extension(borrow_ext.prefix.clone(), new_node);
                        Self::degenerate(root_hash, n, db, passing_keys)
                    }
                    _ => Ok(Node::Extension(ext.clone())),
                }
            }
            _ => Ok(n),
        }
    }

    // Get nodes path along the key, only the nodes whose encode length is greater than
    // hash length are added.
    // For embedded nodes whose data are already contained in their parent node, we don't need to
    // add them in the path.
    // In the code below, we only add the nodes get by `get_node_from_hash`, because they contains
    // all data stored in db, including nodes whose encoded data is less than hash length.
    fn get_path_at<D: DB>(
        root_hash: &H256,
        source_node: &Node,
        db: &D,
        path: &Nibbles,
        path_index: usize,
    ) -> TrieResult<Vec<Node>> {
        let partial = &path.offset(path_index);
        match source_node {
            Node::Empty | Node::Leaf(_) => Ok(vec![]),
            Node::Branch(branch) => {
                let borrow_branch = branch.read();

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(vec![])
                } else {
                    let node = &borrow_branch.children[partial.at(0)];
                    Self::get_path_at(root_hash, node, db, path, path_index + 1)
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.read();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    Self::get_path_at(root_hash, &borrow_ext.node, db, path, path_index + match_len)
                } else {
                    Ok(vec![])
                }
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                let n = Self::recover_from_db(db, &node_hash)?
                    .ok_or(TrieError::MissingTrieNode {
                        node_hash,
                        traversed: None,
                        root_hash: Some(*root_hash),
                        err_key: None,
                    })?;
                let mut rest = Self::get_path_at(root_hash, &n, db, path, path_index)?;
                rest.push(n);
                Ok(rest)
            }
        }
    }

    pub fn commit<D: DB>(
        root: &Node,
        db: &mut D,
        gen_keys: &mut HashSet<H256>, 
        cache: &mut HashMap<H256, Vec<u8>>,
        passing_keys: &mut HashSet<H256>,
    ) -> TrieResult<(H256, Node)> {
        let root_hash = match Self::write_node(root, gen_keys, cache) {
            EncodedNode::Hash(hash) => hash,
            EncodedNode::Inline(encoded) => {
                let hash: H256 = keccak(&encoded).as_fixed_bytes().into();
                cache.insert(hash, encoded);
                hash
            }
        };

        for (key, value) in cache.drain() {
            db.insert(key, value.into()).map_err(|e| TrieError::DB(e.to_string()))?;
        }

        for key in passing_keys.drain() {
            if !gen_keys.contains(&key) {
                db.remove(&key).map_err(|e| TrieError::DB(e.to_string()))?;
            }
        }

        gen_keys.clear();

        let new_root = Self::recover_from_db(db, &root_hash)?
            .expect("The root that was just created is missing");
        Ok((root_hash, new_root))
    }


    fn write_node(to_encode: &Node, gen_keys: &mut HashSet<H256>, cache: &mut HashMap<H256, Vec<u8>>) -> EncodedNode {
        // Returns the hash value directly to avoid double counting.
        if let Node::Hash(hash_node) = to_encode {
            return EncodedNode::Hash(hash_node.hash);
        }

        let data = Self::encode_raw(to_encode, gen_keys, cache);
        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < HASHED_LENGTH {
            EncodedNode::Inline(data)
        } else {
            let hash: H256 = keccak(&data).as_fixed_bytes().into();
            cache.insert(hash, data);

            gen_keys.insert(hash);
            EncodedNode::Hash(hash)
        }
    }

    fn encode_raw(node: &Node, gen_keys: &mut HashSet<H256>, cache: &mut HashMap<H256, Vec<u8>>) -> Vec<u8> {
        match node {
            Node::Empty => rlp::NULL_RLP.to_vec(),
            Node::Leaf(leaf) => {
                let mut stream = RlpStream::new_list(2);
                stream.append(&leaf.key.encode_compact());
                stream.append(&leaf.value);
                stream.out().to_vec()
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.read();

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = &borrow_branch.children[i];
                    match Self::write_node(n, gen_keys, cache) {
                        EncodedNode::Hash(hash) => stream.append(&hash.as_bytes()),
                        EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                    };
                }

                match &borrow_branch.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out().to_vec()
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.read();

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_ext.prefix.encode_compact());
                match Self::write_node(&borrow_ext.node, gen_keys, cache) {
                    EncodedNode::Hash(hash) => stream.append(&hash.as_bytes()),
                    EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                };
                stream.out().to_vec()
            }
            Node::Hash(_hash) => unreachable!(),
        }
    }

    fn decode_node(data: &[u8]) -> TrieResult<Node> {
        let r = Rlp::new(data);

        match r.prototype()? {
            Prototype::Data(0) => Ok(Node::Empty),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let key = Nibbles::from_compact(key);

                if key.is_leaf() {
                    Ok(Node::from_leaf(key, r.at(1)?.data()?.to_vec()))
                } else {
                    let n = Self::decode_node(r.at(1)?.as_raw())?;

                    Ok(Node::from_extension(key, n))
                }
            }
            Prototype::List(17) => {
                let mut nodes = empty_children();
                #[allow(clippy::needless_range_loop)]
                for i in 0..nodes.len() {
                    let rlp_data = r.at(i)?;
                    let n = Self::decode_node(rlp_data.as_raw())?;
                    nodes[i] = n;
                }

                // The last element is a value node.
                let value_rlp = r.at(16)?;
                let value = if value_rlp.is_empty() {
                    None
                } else {
                    Some(value_rlp.data()?.to_vec())
                };

                Ok(Node::from_branch(nodes, value))
            }
            _ => {
                if r.is_data() && r.size() == HASHED_LENGTH {
                    let hash = H256::from_slice(r.data()?);
                    Ok(Node::from_hash(hash))
                } else {
                    Err(TrieError::InvalidData)
                }
            }
        }
    }

    pub fn recover_from_db<D: DB>(db: &D, key: &H256) -> TrieResult<Option<Node>> {
        let node = match db
            .get(key)
            .map_err(|e| TrieError::DB(e.to_string()))?
        {
            Some(value) => Some(Self::decode_node(&value)?),
            None => None,
        };
        Ok(node)
    }
}