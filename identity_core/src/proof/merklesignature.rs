use core::convert::TryInto;
use core::iter::once;
use core::marker::PhantomData;
use did_doc::Error;
use did_doc::MethodQuery;
use did_doc::MethodType;
use did_doc::MethodWrap;
use did_doc::ResolveMethod;
use did_doc::Result;
use did_doc::SetSignature;
use did_doc::Sign;
use did_doc::Signature;
use did_doc::SignatureData;
use did_doc::SignatureOptions;
use did_doc::SuiteName;
use did_doc::TrySignature;
use did_doc::Verify;
use digest::generic_array::typenum::Unsigned;
use digest::Output;
use serde::Serialize;

use crate::crypto::merkle_tree::DigestExt;
use crate::crypto::merkle_tree::Hash;
use crate::crypto::merkle_tree::MTree;
use crate::crypto::merkle_tree::Node;
use crate::crypto::merkle_tree::Proof;
use crate::crypto::PublicKey;
use crate::utils::decode_b58;
use crate::utils::encode_b58;

const METHODS: &[MethodType] = &[MethodType::Ed25519MerkleVerificationKey2021];

const TAG_L: u8 = 0b11110000;
const TAG_R: u8 = 0b00001111;

fn suite_name<D, S>(suite: &S) -> String
where
    D: MerkleDigest,
    S: SuiteName,
{
    // "MerkleSignature2021"
    format!("Merkle:{}:{}", D::ALG, suite.name())
}

// =============================================================================
// =============================================================================

pub trait MerkleDigest: DigestExt {
    const ALG: &'static str;
}

impl MerkleDigest for ::sha2::Sha256 {
    const ALG: &'static str = "sha256";
}

// =============================================================================
// =============================================================================

#[derive(Clone, Copy, Debug)]
pub struct MerkleSign<'a, D, S>
where
    D: MerkleDigest,
{
    suite: S,
    node: usize,
    tree: &'a MTree<D>,
}

impl<'a, D, S> MerkleSign<'a, D, S>
where
    D: MerkleDigest,
{
    pub fn new(tree: &'a MTree<D>, node: usize, suite: S) -> Self {
        Self { suite, node, tree }
    }
}

impl<'a, D, S> SuiteName for MerkleSign<'a, D, S>
where
    D: MerkleDigest,
    S: SuiteName,
{
    fn name(&self) -> String {
        suite_name::<D, S>(&self.suite)
    }
}

impl<'a, D, S> MerkleSign<'a, D, S>
where
    D: MerkleDigest,
    Output<D>: Copy,
    S: Sign + SuiteName,
{
    pub fn sign<T, K>(&self, message: &mut T, options: SignatureOptions, secret: &K) -> Result<()>
    where
        T: Serialize + SetSignature,
        K: AsRef<[u8]> + ?Sized,
    {
        message.set_signature(Signature::new(self.name(), options));

        let value: SignatureData = self.sign_data(message, secret.as_ref())?;

        message.try_signature_mut()?.set_data(value);

        Ok(())
    }

    pub fn sign_data<T>(&self, data: &T, secret: &[u8]) -> Result<SignatureData>
    where
        T: Serialize,
    {
        let proof: Proof<D> = self
            .tree
            .proof(self.node)
            .ok_or_else(|| Error::message("Merkle Key Invalid Node"))?;

        let encoded: String = encode_b58(&encode_proof(&proof));
        let signature: SignatureData = self.suite.sign(data, secret)?;
        let signature: String = format!("{}.{}", encoded, signature.as_str());
        let signature: SignatureData = SignatureData::Signature(signature);

        Ok(signature)
    }
}

// =============================================================================
// =============================================================================

#[derive(Clone, Copy, Debug)]
pub struct MerkleVerify<'a, D, S>
where
    D: MerkleDigest,
{
    suite: S,
    public: &'a PublicKey,
    marker: PhantomData<D>,
}

impl<'a, D, S> MerkleVerify<'a, D, S>
where
    D: MerkleDigest,
{
    pub fn new(public: &'a PublicKey, suite: S) -> Self {
        Self {
            suite,
            public,
            marker: PhantomData,
        }
    }
}

impl<'a, D, S> SuiteName for MerkleVerify<'a, D, S>
where
    D: MerkleDigest,
    S: SuiteName,
{
    fn name(&self) -> String {
        suite_name::<D, S>(&self.suite)
    }
}

impl<'a, D, S> MerkleVerify<'a, D, S>
where
    D: MerkleDigest,
    S: Verify + SuiteName,
{
    pub fn verify<T, M>(&self, message: &T) -> Result<()>
    where
        T: Serialize + TrySignature + ResolveMethod<M>,
        M: Serialize,
    {
        self.verify_data(message, message)
    }

    pub fn verify_data<T, R, M>(&self, message: &T, resolver: R) -> Result<()>
    where
        T: Serialize + TrySignature,
        R: ResolveMethod<M>,
        M: Serialize,
    {
        let signature: &Signature = message.try_signature()?;

        if signature.type_() != self.name() {
            return Err(Error::message("Invalid Signature Type"));
        }

        let query: MethodQuery<'_> = signature.to_query()?;
        let method: MethodWrap<'_, M> = resolver.try_resolve_method(query)?;

        if !METHODS.contains(&method.key_type()) {
            return Err(Error::message("Invalid Method Type"));
        }

        signature.verify(&self, message, &method.key_data().try_decode()?)?;

        Ok(())
    }

    pub fn verify_signature<T>(&self, message: &T, signature: &SignatureData, public: &[u8]) -> Result<()>
    where
        T: Serialize,
    {
        // The root hash of the Merkle tree is stored in the DID Document
        // Verification Method; we receive the raw bytes as `public`.
        let root: Hash<D> = Hash::from_slice(public).ok_or_else(|| Error::message("Merkle Key Invalid Root Hash"))?;

        // The construct the target hash from the user-provided public key.
        let target: Hash<D> = D::new().hash_data(self.public.as_ref());

        // Extract the encoded merkle tree proof and signature.
        let (proof, signature): (&str, &str) = signature
            .as_str()
            .find('.')
            .ok_or_else(|| Error::message("Merkle Key Invalid Signature"))
            .map(|index| signature.as_str().split_at(index))
            .map(|(this, that)| (this, that.trim_start_matches('.')))?;

        // Decode and reassemble the extracted proof.
        let proof: Proof<D> = decode_b58(proof)
            .ok()
            .as_deref()
            .and_then(decode_proof)
            .ok_or_else(|| Error::message("Merkle Key Invalid Proof"))?;

        // Validate the inclusion of the target hash in the Merkle tree.
        if !proof.verify(&root, target) {
            return Err(Error::message("Merkle Tree Invalid Proof"));
        }

        let signature: SignatureData = SignatureData::Signature(signature.to_string());

        // Verify the attached signature with the now-validated public key.
        self.suite.verify(message, &signature, self.public.as_ref())?;

        Ok(())
    }
}

impl<'a, D, S> Verify for MerkleVerify<'a, D, S>
where
    D: MerkleDigest,
    S: Verify + SuiteName,
{
    const METHODS: &'static [MethodType] = METHODS;

    fn verify<T>(&self, data: &T, signature: &SignatureData, public: &[u8]) -> Result<()>
    where
        T: Serialize,
    {
        self.verify_signature(data, signature, public)
    }
}

// =============================================================================
// =============================================================================

// Encodes a proof in the following form:
//
//   [ U32(PATH-LEN) [ [ U8(NODE-TAG) | HASH(NODE-PATH) ] ... ] ]
fn encode_proof<D>(proof: &Proof<D>) -> Vec<u8>
where
    D: MerkleDigest,
{
    let size: usize = proof.nodes().len();
    let size: [u8; 4] = (size as u32).to_be_bytes();

    let data: _ = proof.nodes().iter().flat_map(|node| match node {
        Node::L(hash) => once(TAG_L).chain(hash.as_ref().iter().copied()),
        Node::R(hash) => once(TAG_R).chain(hash.as_ref().iter().copied()),
    });

    size.iter().copied().chain(data).collect()
}

// Decodes a proof in the following form:
//
//   [ U32(PATH-LEN) [ [ U8(NODE-TAG) | HASH(NODE-PATH) ] ... ] ]
fn decode_proof<D>(data: &[u8]) -> Option<Proof<D>>
where
    D: MerkleDigest,
{
    let size: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    let size: usize = u32::from_be_bytes(size).try_into().ok()?;

    let mut nodes: Vec<Node<D>> = Vec::with_capacity(size);
    let mut slice: &[u8] = data.get(4..)?;

    for _ in 0..size {
        let ntag: u8 = slice.get(0).copied()?;
        let data: &[u8] = slice.get(1..1 + D::OutputSize::USIZE)?;
        let hash: Hash<D> = Hash::from_slice(data)?;

        match ntag {
            self::TAG_L => nodes.push(Node::L(hash)),
            self::TAG_R => nodes.push(Node::R(hash)),
            _ => return None,
        }

        slice = slice.get(1 + D::OutputSize::USIZE..)?;
    }

    Some(Proof::new(nodes.into_boxed_slice()))
}
