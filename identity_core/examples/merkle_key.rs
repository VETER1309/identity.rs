//! cargo run --example merkle_key

use did_doc::DocumentBuilder;
use did_doc::Method;
use did_doc::MethodBuilder;
use did_doc::MethodData;
use did_doc::MethodScope;
use did_doc::MethodType;
use did_doc::SignatureOptions;
use did_doc::VerifiableDocument;
use did_url::DID;
use digest::Digest;
use identity_core::crypto::merkle_tree::DigestExt;
use identity_core::crypto::merkle_tree::Hash;
use identity_core::crypto::merkle_tree::MTree;
use identity_core::crypto::KeyPair;
use identity_core::crypto::PublicKey;
use identity_core::crypto::SecretKey;
use identity_core::proof::JcsEd25519Signature2020;
use identity_core::proof::MerkleSign;
use identity_core::proof::MerkleVerify;
use identity_core::utils::encode_b58;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Sha256;

type Signer<'a> = MerkleSign<'a, Sha256, JcsEd25519Signature2020>;
type Verifier<'a> = MerkleVerify<'a, Sha256, JcsEd25519Signature2020>;

const LEAVES: usize = 1 << 8;

fn generate_leaves(count: usize) -> Vec<KeyPair> {
    (0..count).map(|_| JcsEd25519Signature2020::new_keypair()).collect()
}

fn generate_hashes<'a, D, T, I>(digest: &mut D, leaves: I) -> Vec<Hash<D>>
where
    D: DigestExt,
    T: AsRef<[u8]> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    leaves
        .into_iter()
        .map(AsRef::as_ref)
        .map(|leaf| digest.hash_data(leaf))
        .collect()
}

fn main() {
    let mut digest: Sha256 = Sha256::new();

    let index: usize = OsRng.gen_range(0, LEAVES);

    let kpairs: Vec<KeyPair> = generate_leaves(LEAVES);
    let leaves: _ = kpairs.iter().map(KeyPair::public);
    let hashes: Vec<Hash<Sha256>> = generate_hashes(&mut digest, leaves);

    let tree: MTree<Sha256> = MTree::from_leaves(&hashes).unwrap();
    let controller: DID = "did:iota:1234".parse().unwrap();

    let method: Method = MethodBuilder::default()
        .id(controller.join("#merkle").unwrap())
        .controller(controller.clone())
        .key_type(MethodType::Ed25519MerkleVerificationKey2021)
        .key_data(MethodData::PublicKeyBase58(encode_b58(tree.root())))
        .build()
        .unwrap();

    let mut document: VerifiableDocument = DocumentBuilder::default()
        .id(controller)
        .authentication(method.id().clone())
        .verification_method(method)
        .build()
        .map(VerifiableDocument::new)
        .unwrap();

    let public: &PublicKey = kpairs[index].public();
    let secret: &SecretKey = kpairs[index].secret();

    let suite: Signer<'_> = Signer::new(&tree, index, JcsEd25519Signature2020);
    let options: SignatureOptions = document.resolve_options((0, MethodScope::Authentication)).unwrap();

    suite.sign(&mut document, options, secret).unwrap();

    println!("Document: {:#}", document);

    let suite: Verifier<'_> = Verifier::new(public, JcsEd25519Signature2020);

    println!("Verified: {:?}", suite.verify(&document));
}
