import io::println;

#[inline(always)]
fn rotl(x : u64, b : uint) -> u64 { ((x) << (b)) | ((x) >> (64 - (b))) }

#[inline(always)]
fn load_u64(b : ~[u8]) -> u64 {
    (b[0] as u64 <<  0) | 
    (b[1] as u64 <<  8) | 
    (b[2] as u64 << 16) | 
    (b[3] as u64 << 24) | 
    (b[4] as u64 << 32) | 
    (b[5] as u64 << 40) | 
    (b[6] as u64 << 48) | 
    (b[7] as u64 << 56)
}

#[inline(always)]
fn sipround(&v0 : u64, &v1 : u64, &v2 : u64, &v3 : u64) {
        v0 = v0 + v1; v1=rotl(v1,13); v1 ^= v0; v0=rotl(v0,32);
        v2 = v2 + v3; v3=rotl(v3,16); v3 ^= v2;
        v0 += v3; v3=rotl(v3,21); v3 ^= v0;
        v2 += v1; v1=rotl(v1,17); v1 ^= v2; v2=rotl(v2,32);
}

fn crypto_auth(m : ~[u8], k : ~[u8]) -> u64 {

    let k0 = load_u64(k);
    let k1 = load_u64(vec::slice(k, 8, 16));

    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let mlen = vec::len(m);
    let w = (mlen+1)/8 - 1; // words in main body
    let rem = mlen & 7;

    for uint::range(0u, w) |i| {
        let mi = load_u64(vec::slice(m, i*8, i*8+8));

        v3 ^= mi;

        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);

        v0 ^= mi
    }

    let mut mfinal = (mlen as u64 % 256) << 56;

    let tail = vec::slice(m, w*8, mlen);

    if  7u <= rem { mfinal |= (tail[ 6u] as u64) << 48u }
    if  6u <= rem { mfinal |= (tail[ 5u] as u64) << 40u }
    if  5u <= rem { mfinal |= (tail[ 4u] as u64) << 32u }
    if  4u <= rem { mfinal |= (tail[ 3u] as u64) << 24u }
    if  3u <= rem { mfinal |= (tail[ 2u] as u64) << 16u }
    if  2u <= rem { mfinal |= (tail[ 1u] as u64) <<  8u }
    if  1u <= rem { mfinal |= (tail[ 0u] as u64) <<  0u }

    v3 ^= mfinal;

    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);

    v0 ^= mfinal;

    // finalize

    v2 ^= 0xff;

    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);

    ret v0 ^ v1 ^ v2 ^ v3;

}

// #[test]
fn main() {
    let k = ~[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let m = ~[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
    let h = crypto_auth(m, k);

    assert h == 0xa129ca6149be45e5;

    io::println(~"test passed");
}
