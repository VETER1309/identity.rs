use libjose::error::Result;
use libjose::jwk::Jwk;
use libjose::jws::Decoder;
use libjose::jws::Encoder;
use libjose::jws::JwsAlgorithm;
use libjose::jws::JwsFormat;
use libjose::jws::JwsHeader;
use libjose::jws::Token;

static CLAIMS: &[u8] = b"libjose";

fn roundtrip(algorithm: JwsAlgorithm) -> Result<()> {
  let header: JwsHeader = JwsHeader::new(algorithm);
  let secret: Jwk = Jwk::random(algorithm)?;
  let public: Jwk = secret.to_public();

  let mut encoder: Encoder<'_> = Encoder::new().recipient((&secret, &header));
  let mut decoder: Decoder<'_, '_> = Decoder::new(&public);

  let encoded: String = encoder.encode(CLAIMS)?;
  let decoded: Token<'_> = decoder.decode(encoded.as_bytes())?;

  assert_eq!(decoded.protected.unwrap(), header);
  assert_eq!(decoded.claims, CLAIMS);

  encoder = encoder.format(JwsFormat::General);
  decoder = decoder.format(JwsFormat::General);

  let encoded: String = encoder.encode(CLAIMS)?;
  let decoded: Token<'_> = decoder.decode(encoded.as_bytes())?;

  assert_eq!(decoded.protected.unwrap(), header);
  assert_eq!(decoded.claims, CLAIMS);

  encoder = encoder.format(JwsFormat::Flatten);
  decoder = decoder.format(JwsFormat::Flatten);

  let encoded: String = encoder.encode(CLAIMS)?;
  let decoded: Token<'_> = decoder.decode(encoded.as_bytes())?;

  assert_eq!(decoded.protected.unwrap(), header);
  assert_eq!(decoded.claims, CLAIMS);

  Ok(())
}

#[test]
fn test_roundtrip() {
  for alg in JwsAlgorithm::ALL {
    roundtrip(*alg).unwrap();
  }
}
