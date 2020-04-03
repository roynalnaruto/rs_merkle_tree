extern crate crypto;

use crypto::digest::Digest;

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl AsBytes for str {
    fn as_bytes(&self) -> &[u8] {
        str::as_bytes(self)
    }
}

impl AsBytes for String {
    fn as_bytes(&self) -> &[u8] {
        String::as_bytes(self)
    }
}

#[derive(Debug)]
pub struct Node<T>
    where T: AsBytes + Clone,
{
    value: Option<T>,
    hash: String,
}

pub struct MerkleTree<H, T>
    where H: Digest,
          T: AsBytes + Clone,
{
    hasher: H,
    nodes: Vec<Node<T>>,
}

impl<H, T> MerkleTree<H, T>
    where H: Digest,
          T: AsBytes + Clone,
{
    fn root(&self) -> Result<&Node<T>, &'static str> {
        match self.nodes.as_slice().last() {
            Some(root) => Ok(root),
            None => Err("Error constructing merkle tree")
        }
    }

    fn from_leaves(values: &mut Vec<T>, mut hasher: H) -> Result<Self, &'static str> {
        if values.len() == 0 {
            return Err("Leaves cannot be empty");
        }

        let n = values.len().next_power_of_two();
        if values.len() < n {
            let pad_by = values.len().next_power_of_two() - values.len();
            if let Some(last) = values.last().map(|v| (*v).clone()) {
                let extend_by = vec![last; pad_by];
                values.extend(extend_by);
            }
        }

        let mut nodes: Vec<Node<T>> = vec![];
        for v in values {
            let leaf_node: Node<T> = Self::as_leaf(v, &mut hasher);
            nodes.push(leaf_node);
        }

        let parent_nodes: Vec<Node<T>> = Self::build_parent_nodes(&nodes, &mut hasher);

        nodes.extend(parent_nodes);

        Ok(MerkleTree {
            hasher: hasher,
            nodes: nodes,
        })
    }

    fn build_parent_nodes(children: &Vec<Node<T>>, mut hasher: &mut H) -> Vec<Node<T>> {
        let mut parent_nodes = vec![];

        for pairs in children.iter().collect::<Vec<_>>().chunks(2) {
            let left_child = pairs[0];
            let right_child = pairs[1];

            parent_nodes.push(Self::as_internal(&left_child, &right_child, &mut hasher));
        }

        if parent_nodes.len() > 1 {
            let new_parents: Vec<Node<T>> = Self::build_parent_nodes(&parent_nodes, &mut hasher);
            parent_nodes.extend(new_parents);
            return parent_nodes;
        } else {
            return parent_nodes;
        }
    }

    fn as_leaf(v: &T, hasher: &mut H) -> Node<T> {
        hasher.reset();
        hasher.input(v.as_bytes());
        let hash = hasher.result_str();

        let value = v.clone();

        Node {
            value: Some(value),
            hash: hash,
        }
    }

    fn as_internal(left: &Node<T>, right: &Node<T>, hasher: &mut H) -> Node<T> {
        hasher.reset();
        hasher.input(left.hash.as_bytes());
        hasher.input(right.hash.as_bytes());
        let hash = hasher.result_str();

        Node {
            value: None,
            hash: hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::sha2::Sha256;
    use super::*;

    #[test]
    fn test_as_leaf() {
        let mut hasher = Sha256::new();
        let leaf_node: Node<String> = MerkleTree::as_leaf(&String::from("tea"), &mut hasher);

        assert_eq!(leaf_node.value, Some(String::from("tea")));
        assert_eq!(leaf_node.hash, "a9f74d1ec36ebdeb2da3f6e5868090cd2a2d20b3dcca7b62f60304b1d3d9ef42");
    }

    #[test]
    fn test_as_internal() {
        let mut hasher = Sha256::new();
        let leaf_node_left: Node<String> = MerkleTree::as_leaf(&String::from("tea"), &mut hasher);
        let leaf_node_right: Node<String> = MerkleTree::as_leaf(&String::from("coffee"), &mut hasher);
        let parent_node: Node<String> = MerkleTree::as_internal(&leaf_node_left, &leaf_node_right, &mut hasher);

        assert_eq!(parent_node.value, None);
        assert_eq!(parent_node.hash, "d050213312c90773722bdb448110143b042d5f13de000e93b68a8769453ba38d");
    }

    #[test]
    fn test_from_leaves_2n() {
        let mut leaf_values: Vec<String> = vec![
            String::from("tea"),
            String::from("coffee"),
            String::from("lemonade"),
            String::from("wine")
        ];
        if let Some(mt) = MerkleTree::from_leaves(&mut leaf_values, Sha256::new()).ok() {
            assert_eq!(mt.nodes.len(), 7 as usize);
            assert_eq!(mt.nodes[0].value, Some(String::from("tea")));
            assert_eq!(mt.nodes[1].value, Some(String::from("coffee")));
            assert_eq!(mt.nodes[2].value, Some(String::from("lemonade")));
            assert_eq!(mt.nodes[3].value, Some(String::from("wine")));

            assert_eq!(mt.nodes[4].value, None);
            assert_eq!(mt.nodes[4].hash, "d050213312c90773722bdb448110143b042d5f13de000e93b68a8769453ba38d");

            assert_eq!(mt.nodes[5].value, None);
            assert_eq!(mt.nodes[5].hash, "f6c1118a17527ef7c6addbe574fa8c2256f98764cab46568c6bc7ab70e1ee808");

            assert_eq!(mt.nodes[6].value, None);
            assert_eq!(mt.nodes[6].hash, "0e3bc6149e1f99b5192e73c92328a7e4bb95df94ad9b96253698418a2e746766");
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_from_leaves_not_2n() {
        let mut leaf_values: Vec<String> = vec![
            String::from("tea"),
            String::from("coffee"),
            String::from("lemonade"),
            String::from("wine"),
            String::from("pepsi"),
            String::from("cola")
        ];
        if let Some(mt) = MerkleTree::from_leaves(&mut leaf_values, Sha256::new()).ok() {
            assert_eq!(mt.nodes.len(), 15 as usize);
            assert_eq!(mt.nodes[0].value, Some(String::from("tea")));
            assert_eq!(mt.nodes[1].value, Some(String::from("coffee")));
            assert_eq!(mt.nodes[2].value, Some(String::from("lemonade")));
            assert_eq!(mt.nodes[3].value, Some(String::from("wine")));
            assert_eq!(mt.nodes[4].value, Some(String::from("pepsi")));
            assert_eq!(mt.nodes[5].value, Some(String::from("cola")));
            assert_eq!(mt.nodes[6].value, Some(String::from("cola")));
            assert_eq!(mt.nodes[7].value, Some(String::from("cola")));

            assert_eq!(mt.nodes[8].value, None);
            assert_eq!(mt.nodes[8].hash, "d050213312c90773722bdb448110143b042d5f13de000e93b68a8769453ba38d");

            assert_eq!(mt.nodes[9].value, None);
            assert_eq!(mt.nodes[9].hash, "f6c1118a17527ef7c6addbe574fa8c2256f98764cab46568c6bc7ab70e1ee808");

            assert_eq!(mt.nodes[10].value, None);
            assert_eq!(mt.nodes[10].hash, "0f932c1de87f02001cca7bb3e7e9982db2cf0022a601461ed51da468c7caa423");

            assert_eq!(mt.nodes[11].value, None);
            assert_eq!(mt.nodes[11].hash, "97c9f489762d8909272edbd6aeec2a6e75916604dc8e087d82dcae43b082a8dc");

            assert_eq!(mt.nodes[12].value, None);
            assert_eq!(mt.nodes[12].hash, "0e3bc6149e1f99b5192e73c92328a7e4bb95df94ad9b96253698418a2e746766");

            assert_eq!(mt.nodes[13].value, None);
            assert_eq!(mt.nodes[13].hash, "7c5bf950be2daf8381ab6fb02ad6d66727fc02b2a793d01e60fab5a795736179");

            assert_eq!(mt.nodes[14].value, None);
            assert_eq!(mt.nodes[14].hash, "93993d7a938d03233784c7b480e32665b483542bd2d22e09bdd6dd590874d5c6");

            let root = mt.root().ok().unwrap();
            assert_eq!(root.value, None);
            assert_eq!(root.hash, "93993d7a938d03233784c7b480e32665b483542bd2d22e09bdd6dd590874d5c6");
        } else {
            assert!(false);
        }
    }
}
