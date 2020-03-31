#![no_std]
#![feature(proc_macro_hygiene)]
extern crate ontio_std as ostd;
use ostd::abi::{Encoder, EventBuilder, Sink, Source};
use ostd::macros::base58;
use ostd::prelude::*;
use ostd::{database, runtime};

use staticvec::StaticVec;

type Hashes = StaticVec<H256, 36>;

struct CompactMerkleTree {
    tree_size: u32,
    hashes: Hashes,
}

fn load_merkletree() -> Option<CompactMerkleTree> {
    if let Some(value) = runtime::storage_read(MERKLETREE_KEY) {
        let mut source = Source::new(&value);
        let tree_size = source.read_u32().ok()?;
        let len = source.read_u32().ok()?;
        let mut hashes: Hashes = Hashes::new();
        for _i in 0..len {
            let hash = source.read_h256().ok()?;
            hashes.push(hash.clone());
        }

        return Some(CompactMerkleTree { tree_size, hashes });
    }
    return Some(CompactMerkleTree {
        tree_size: 0u32,
        hashes: Hashes::new(),
    });
}

fn store_merkletree(tree: &CompactMerkleTree) {
    let mut sink = Sink::new(4 + 4 + tree.hashes.len() * 32);
    sink.write(tree.tree_size);
    sink.write(tree.hashes.len() as u32);
    for hash in tree.hashes.iter() {
        sink.write(hash);
    }

    runtime::storage_write(MERKLETREE_KEY, sink.bytes());
}

impl CompactMerkleTree {
    #[inline(never)]
    fn append_hashes(&mut self, hash_list: &[&H256]) {
        assert!(self.tree_size < u32::max_value() - hash_list.len() as u32);
        for h in hash_list {
            self.append_hash(h);
        }
    }

    fn append_hash(&mut self, leaf: &H256) {
        let mut size = self.hashes.len();
        let mut s = self.tree_size;
        let mut data = [1; 65];
        data[33..65].clone_from_slice(leaf.as_ref());
        loop {
            if s % 2 != 1 {
                break;
            }
            s = s / 2;

            data[1..33].clone_from_slice(self.hashes[size - 1].as_ref());
            sha256(&mut data);
            size -= 1;
        }
        let leaf = H256::from_slice(&data[33..65]);
        self.tree_size += 1;
        self.hashes.truncate(size);
        self.hashes.push(leaf);
    }
}

mod env {
    extern "C" {
        pub fn ontio_sha256(data: *const u8, len: u32, val: *mut u8);
    }
}

fn sha256(data: &mut [u8]) {
    unsafe {
        env::ontio_sha256(data.as_ptr(), data.len() as u32, data[33..65].as_mut_ptr());
    }
}

#[derive(Encoder)]
struct RootSize {
    root: H256,
    tree_size: u32,
}

const OWNER_KEY: &[u8] = b"o";
const MERKLETREE_KEY: &[u8] = b"m";
const ADMIN: Address = base58!("APHNPLz2u1JUXyD8rhryLaoQrW46J3P6y2");

fn get_root_inner(ogq_tree: &CompactMerkleTree) -> H256 {
    if ogq_tree.hashes.len() != 0 {
        let l = ogq_tree.hashes.len() as i32;
        let mut data = [1; 65];
        data[33..65].clone_from_slice(ogq_tree.hashes[(l - 1) as usize].as_ref());
        let mut i = l - 2;
        loop {
            if i < 0 {
                break;
            }
            data[1..33].clone_from_slice(ogq_tree.hashes[i as usize].as_ref());
            sha256(&mut data);
            i -= 1;
        }
        return H256::from_slice(&data[33..65]);
    } else {
        return runtime::sha256(b"");
    }
}

fn set_owner(addr: &Address) -> bool {
    assert!(runtime::check_witness(&ADMIN));
    database::put(OWNER_KEY, addr);
    EventBuilder::new().address(addr).notify();
    true
}

fn batch_add(hash_list: &[&H256]) -> bool {
    let owner: Address = database::get(OWNER_KEY).expect("get owner address error");
    assert!(runtime::check_witness(&owner));
    if hash_list.len() == 0 {
        return false;
    }
    let mut ogq_tree: CompactMerkleTree = load_merkletree().expect("load merkletree error");
    ogq_tree.append_hashes(hash_list);
    store_merkletree(&ogq_tree);
    let root = get_root_inner(&ogq_tree);
    EventBuilder::new()
        .h256(root)
        .number(ogq_tree.tree_size as u128)
        .notify();
    return true;
}

fn get_root() -> RootSize {
    let mut ogq_tree: CompactMerkleTree = load_merkletree().expect("load merkletree error");
    let root = get_root_inner(&mut ogq_tree);
    let root_size = RootSize {
        root,
        tree_size: ogq_tree.tree_size,
    };
    EventBuilder::new()
        .h256(root)
        .number(ogq_tree.tree_size as u128)
        .notify();
    return root_size;
}

fn contract_migrate(code: &[u8]) -> bool {
    assert!(runtime::check_witness(&ADMIN));
    let addr: Address =
        runtime::contract_migrate(code, 3, "name", "version", "author", "email", "desc");
    EventBuilder::new().address(&addr).notify();
    true
}

fn contract_destroy() -> bool {
    assert!(runtime::check_witness(&ADMIN));
    runtime::contract_delete();
}

#[no_mangle]
pub fn invoke() {
    let input = runtime::input();
    let mut source = Source::new(&input);
    let action: &[u8] = source.read_bytes().unwrap();
    let mut sink = Sink::new(12);
    match action {
        b"set_owner" => {
            let owner: Address = source.read().unwrap();
            sink.write(set_owner(&owner));
        }
        b"batch_add" => {
            let hash_list: Vec<&H256> = source.read().unwrap();
            sink.write(batch_add(hash_list.as_slice()));
        }
        b"get_root" => {
            sink.write(get_root());
        }
        b"contract_migrate" => {
            let code = source.read().unwrap();
            sink.write(contract_migrate(code));
        }
        b"contract_destroy" => sink.write(contract_destroy()),
        _ => panic!("unsupported action!"),
    }
    runtime::ret(sink.bytes())
}
