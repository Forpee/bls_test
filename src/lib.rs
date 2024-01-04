#[no_mangle]
pub extern "C" fn main() {
    use blst::min_pk::SecretKey;
    let ikm = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
        0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0xcd, 0xef,
    ];

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let msg = b"blst is such a blast";

    let sig = sk.sign(msg, dst, &[]);
    let err = sig.verify(true, msg, dst, &[], &pk, true);

    println!("Verify Success");
    assert_eq!(err, blst::BLST_ERROR::BLST_SUCCESS);
}
