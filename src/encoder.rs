use crate::Error;
use aes_gcm::aead::{
    generic_array::{ArrayLength, GenericArray},
    Aead, NewAead,
};
use aes_gcm::Aes256Gcm;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

//pub trait SerDe = Serialize + DeserializeOwned;

const NONCE_LEN: usize = 12;

/// Value with expiration timestamp
/// timestamp is expiration time in milliseconds since epoch UTC
#[derive(Debug, Serialize, Deserialize)]
struct TimedVal<T>(T, u64);

/// The T0U8 trait allows the encryption key to be either &[u8] or &[u64],
/// the latter being the data type of secret imported from config.toml.
pub trait ToU8: Copy {
    fn as_u8(self) -> u8;
}
/// Convert array of i64 to u8, treating each value as unsigned
impl ToU8 for i64 {
    #[inline]
    fn as_u8(self) -> u8 {
        self as u8
    }
}
impl ToU8 for u8 {
    #[inline]
    fn as_u8(self) -> u8 {
        self
    }
}

/// Build encryption key from secret (either &[u8] or &[i64] of length 32)
fn key_from_arr<N: ArrayLength<u8>, A: ToU8>(secret: &[A]) -> Result<GenericArray<u8, N>, Error> {
    let key = GenericArray::from_exact_iter(secret.iter().map(|v| (*v).as_u8()))
        .ok_or(Error::ArrayLen)?;
    Ok(key)
}

/// Encrypt value T with expiration timeout to base64 string. Used for session cookie and oauth state.
pub(crate) fn encode<T: Serialize + DeserializeOwned, A: ToU8>(
    value: T,
    secret: &[A],
    timeout_sec: u64,
) -> Result<String, Error> {
    let v = TimedVal(value, current_time_millis() + 1000 * timeout_sec as u64);
    let buf = serde_json::to_vec(&v).map_err(|e| Error::Serde { msg: "encode", e })?;
    encrypt(&buf, secret)
}

/// Encrypt buffer using secret key, returning base64-encoded ciphertext
pub(crate) fn encrypt<A: ToU8>(buf: &[u8], secret: &[A]) -> Result<String, Error> {
    use getrandom::getrandom;

    let key = key_from_arr(secret)?;
    let cipher = Aes256Gcm::new(&key);

    let mut rand_data = [0u8; NONCE_LEN];
    getrandom(&mut rand_data).map_err(|e| Error::Random(e.to_string()))?;
    let nonce = GenericArray::from_slice(&rand_data);
    let mut ciphertext = cipher
        .encrypt(&nonce, buf.as_ref())
        .map_err(|e| Error::Encryption(e.to_string()))?;
    ciphertext.extend_from_slice(&nonce);
    let buf = base64::encode_config(&ciphertext, base64::URL_SAFE_NO_PAD);
    Ok(buf)
}

/// decode+decrypt a string (such as a cookie value) into its original type T
/// T is any type that implements Serialize + Deserialize
pub(crate) fn decode<T: Serialize + DeserializeOwned, A: ToU8>(
    value: &str,
    secret: &[A],
) -> Result<T, Error> {
    let vec = decrypt(value, secret)?;
    let t: TimedVal<T> =
        serde_json::from_slice(&vec).map_err(|e| Error::Serde { msg: "decode", e })?;
    if current_time_millis() > t.1 {
        Err(Error::TimeoutExpired)
    } else {
        Ok(t.0)
    }
}

/// base64-decode, then decrypt string, returning plaintext bytes
pub(crate) fn decrypt<A: ToU8>(value: &str, secret: &[A]) -> Result<Vec<u8>, Error> {
    let data = base64::decode_config(value.as_bytes(), base64::URL_SAFE_NO_PAD)
        .map_err(|_| Error::CookieDecode)?;
    let key = key_from_arr(secret)?;
    let cipher = Aes256Gcm::new(&key);
    let lc = data.len();
    assert!(lc > NONCE_LEN);

    // error if decryption fails
    let plaintext = cipher
        .decrypt(
            &GenericArray::from_slice(&data[(lc - NONCE_LEN)..]),
            &data[..(lc - NONCE_LEN)],
        )
        .map_err(|e| Error::Encryption(e.to_string()))?;
    Ok(plaintext)
}

/// Returns current time in UTC, as integer milliseconds since EPOCH
#[cfg(target_arch = "wasm32")]
// logging api supports floating pt timestamps for fractional millis,
// but we don't need that resolution, and serde float support is bulky
fn current_time_millis() -> u64 {
    js_sys::Date::now() as u64
}

/// Returns current time in UTC, as integer milliseconds since EPOCH
#[cfg(not(target_arch = "wasm32"))]
fn current_time_millis() -> u64 {
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_millis() as u64,
        Err(_) => 0, // panic!("SystemTime before UNIX EPOCH!"),
    }
}

#[cfg(test)]
mod test {
    use super::{decode, decrypt, encode, encrypt, Deserialize, Serialize};

    #[test]
    fn test_encrypt() {
        let plaintext = "A language empowering everyone to build reliable and efficient software"
            .as_bytes()
            .to_vec();
        let key = b"90dd3ef5677e792e5c6f672d53401287";
        let ciphertext = encrypt(&plaintext, key).expect("encrypt");
        let decrypted = decrypt(&ciphertext, key).expect("decrypt");
        assert_eq!(&plaintext, &decrypted, "decrypted should equal plaintext");
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Foo {
        value: String,
        other: i64,
        thing: bool,
    }

    #[test]
    fn test_encode() {
        let key = b"4cf1f76a13e8d7fe18e2d10fb53197d3";
        let foo = Foo {
            value: "Hello".to_string(),
            other: 8080,
            thing: true,
        };
        let original = foo.clone();
        let encoded = encode(foo, key, 100).expect("encode");
        let encoded_and_decoded: Foo = decode(&encoded, key).expect("decode");

        assert_eq!(
            &original, &encoded_and_decoded,
            "decode(encode(foo)) == foo"
        );
    }
}
