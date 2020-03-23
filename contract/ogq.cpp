#include<ontiolib/ontio.hpp>

using namespace ontio;

class ogq: public contract {
	class CompactMerkleTree {
		public:
		CompactMerkleTree() {
			tree_size = 0;
			hashes.resize(0);
		}
		uint32_t tree_size;
		vector<H256> hashes;
        ONTLIB_SERIALIZE(CompactMerkleTree, (tree_size)(hashes))
		
		void append_hash(H256 leaf) {
			uint32_t size = hashes.size();
			check(tree_size != std::numeric_limits<uint32_t>::max(), "tree_size get max uint32" );

			for (auto s = tree_size; s%2 == 1; s = s>>1) {
				hash_children(hashes[size-1], leaf, leaf);
				size -= 1;
			}

			tree_size += 1;

			hashes.resize(size + 1);
			hashes[size] = leaf;
		}

		void hash_children(const H256 &left, const H256 &right, H256 &res) {
			vector<char> data;
			data.resize(65);
			data[0] = uint8_t(1);
			std::copy(left.begin(), left.end(), data.begin()+1);
			std::copy(right.begin(), right.end(), data.begin() + 33);
			sha256(data, res);
		}
	};

    key owner_key = make_key("owner_key");
	key merkletree_key = make_key("merkletree_key");
	address admin = base58toaddress("APHNPLz2u1JUXyD8rhryLaoQrW46J3P6y2");

	struct root_size {
		H256 root;
		uint32_t tree_size;
        ONTLIB_SERIALIZE(root_size, (root)(tree_size))
	};

	void notify_if_failed(bool cond, const char *msg) {
		if (not cond) {
			notify_event<string>(msg);
			check(false, msg);
		}
	}

	H256 get_root_inner(CompactMerkleTree &ogq_tree) {
		if (ogq_tree.hashes.size() != 0) {
			int l = ogq_tree.hashes.size();
			H256 accum = ogq_tree.hashes[l - 1];
			for (auto i = l - 2; i >= 0; i --) {
				ogq_tree.hash_children(ogq_tree.hashes[i], accum, accum);
			}
			return accum;
		} else {
			H256 res;
			vector<char> data = {};
			sha256(data, res);
			return res;
		}
	}

    public:
    using contract::contract;

    bool set_owner(address &addr) {
        notify_if_failed(check_witness(admin),"checkwitness admin failed");
        storage_put(owner_key ,addr);
		CompactMerkleTree t;
		storage_put(merkletree_key, t);
		notify_event(addr);
        return true;
    }

	void batch_add2(vector<vector<char>> hash_list) {
		address owner;
        notify_if_failed(storage_get(owner_key ,owner), "owner not set");
        notify_if_failed(check_witness(owner),"checkwitness owner failed");
		if (hash_list.size() == 0) {
			return;
		}

		CompactMerkleTree ogq_tree;
		notify_if_failed(storage_get(merkletree_key, ogq_tree), "get merkletree_key failed");
		
		for (auto h: hash_list) {
			H256 t;
			notify_if_failed(h.size() == t.size(), "hash argument error");
			std::copy(h.begin(), h.end(), t.begin());
			ogq_tree.append_hash(t);
		}

		storage_put(merkletree_key, ogq_tree);
		auto root = get_root_inner(ogq_tree);
		notify_event(root, ogq_tree.tree_size);
	}

	void batch_add(vector<H256> hash_list) {
		address owner;
        notify_if_failed(storage_get(owner_key ,owner), "owner not set");
        notify_if_failed(check_witness(owner),"checkwitness owner failed");
		if (hash_list.size() == 0) {
			return;
		}

		CompactMerkleTree ogq_tree;
		notify_if_failed(storage_get(merkletree_key, ogq_tree), "get merkletree_key failed");
		
		for (auto h: hash_list) {
			ogq_tree.append_hash(h);
		}

		storage_put(merkletree_key, ogq_tree);
		auto root = get_root_inner(ogq_tree);
		notify_event(root, ogq_tree.tree_size);
	}


	root_size get_root(void) {
		CompactMerkleTree ogq_tree;
		notify_if_failed(storage_get(merkletree_key, ogq_tree), "get merkletree_key failed");
		auto root = get_root_inner(ogq_tree);
		root_size t;
		t.root = root;
		t.tree_size = ogq_tree.tree_size;
		notify_event(root, ogq_tree.tree_size);
		return t;
	}

	void contract_migrate(vector<char> code) {
        notify_if_failed(check_witness(admin),"checkwitness admin failed");
		address t = ontio::contract_migrate(code, 3, "name", "version", "author", "email", "desc");
		notify_event(t);
	}

	void contract_destroy() {
        notify_if_failed(check_witness(admin),"checkwitness admin failed");
		ontio::contract_destroy();
	}
};

ONTIO_DISPATCH(ogq, (set_owner)(batch_add)(batch_add2)(get_root)(contract_migrate)(contract_destroy))
