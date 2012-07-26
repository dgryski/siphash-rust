// Rust implementation of the Siphash-2-4 PRF
// For more info on Siphash: http://131002.net/siphash
#[link(name = "siphash", author = "dgryski", vers = "0.1")];

use std;



iface siphash {
    fn input(~[u8]);
    fn input_str(~str);
    fn result() -> u64;
    fn reset();
}

fn siphash(key0 : u64, key1 : u64) -> siphash {
    type sipstate = {
        k0 : u64,
        k1 : u64,
        mut length : uint, // how many bytes we've processed
        mut v0 : u64, // state
        mut v1 : u64,
        mut v2 : u64,
        mut v3 : u64,
        tail : ~[mut u8]/8, // unprocessed bytes
        mut ntail : uint, //  how many bytes in tail are valid
    };

    fn add_input(st : sipstate, msg : ~[u8]) {
        let length = vec::len(msg);
        st.length += length;

        let mut needed = 0u;

        if st.ntail != 0 {
            needed = 8 - st.ntail;

            if length < needed {

                let mut t = 0;
                while t < length {
                    st.tail[st.ntail+t] = msg[t];
                    t += 1;
                }
                st.ntail += length;

                ret;
            }

            let mut t = 0;
            while t < needed {
                st.tail[st.ntail+t] = msg[t];
                t += 1;
            }
            st.ntail += needed;

            let m = (st.tail[0] as u64 <<  0) |
                (st.tail[1] as u64 <<  8) |
                (st.tail[2] as u64 << 16) |
                (st.tail[3] as u64 << 24) |
                (st.tail[4] as u64 << 32) |
                (st.tail[5] as u64 << 40) |
                (st.tail[6] as u64 << 48) |
                (st.tail[7] as u64 << 56);

            st.v3 ^= m;
            sipround(st.v0, st.v1, st.v2, st.v3);
            sipround(st.v0, st.v1, st.v2, st.v3);
            st.v0 ^= m;

            st.ntail = 0;
        }

        let mlen = vec::len(msg) - needed;
        let w = mlen/8; // complete words in main body
        let rem = mlen & 7;

        let mut i = needed;
        while i < w {

            let mi = load_u64(msg, i);

            st.v3 ^= mi;
            sipround(st.v0, st.v1, st.v2, st.v3);
            sipround(st.v0, st.v1, st.v2, st.v3);
            st.v0 ^= mi;

            i += 8;
        }

        let mut t = 0u;
        while t < rem {
            st.tail[t] = msg[i+t];
            t += 1
        }
        st.ntail = rem
    }

    fn mk_result(st : sipstate) -> u64 {

        let mut v0 = st.v0;
        let mut v1 = st.v1;
        let mut v2 = st.v2;
        let mut v3 = st.v3;

        let mut mfinal = (st.length as u64 % 256) << 56;

        if  7u <= st.ntail { mfinal |= (st.tail[ 6u] as u64) << 48u }
        if  6u <= st.ntail { mfinal |= (st.tail[ 5u] as u64) << 40u }
        if  5u <= st.ntail { mfinal |= (st.tail[ 4u] as u64) << 32u }
        if  4u <= st.ntail { mfinal |= (st.tail[ 3u] as u64) << 24u }
        if  3u <= st.ntail { mfinal |= (st.tail[ 2u] as u64) << 16u }
        if  2u <= st.ntail { mfinal |= (st.tail[ 1u] as u64) <<  8u }
        if  1u <= st.ntail { mfinal |= (st.tail[ 0u] as u64) <<  0u }

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

   impl of siphash for sipstate {
        fn reset() {
            self.length = 0;
            self.v0 = self.k0 ^ 0x736f6d6570736575;
            self.v1 = self.k1 ^ 0x646f72616e646f6d;
            self.v2 = self.k0 ^ 0x6c7967656e657261;
            self.v3 = self.k1 ^ 0x7465646279746573;
            self.ntail = 0;
        }
        fn input(msg: ~[u8]) { add_input(self, msg); }
        fn input_str(msg: ~str) { add_input(self, str::bytes(msg)); }
        fn result() -> u64 { ret mk_result(self); }
    }

    let st = {
        k0 : key0,
        k1 : key1,
        mut length : 0u,
        mut v0 : key0 ^ 0x736f6d6570736575,
        mut v1 : key1 ^ 0x646f72616e646f6d,
        mut v2 : key0 ^ 0x6c7967656e657261,
        mut v3 : key1 ^ 0x7465646279746573,
        tail : ~[mut 0u8,0,0,0,0,0,0,0]/8,
        mut ntail : 0u,
    };

    let sh = st as siphash;
    sh.reset();
    ret sh;
}

#[inline(always)]
fn rotl(x : u64, b : uint) -> u64 { ((x) << (b)) | ((x) >> (64 - (b))) }

#[inline(always)]
fn load_u64(b : &[u8], i : uint) -> u64 {
    (b[0+i] as u64 <<  0) |
    (b[1+i] as u64 <<  8) |
    (b[2+i] as u64 << 16) |
    (b[3+i] as u64 << 24) |
    (b[4+i] as u64 << 32) |
    (b[5+i] as u64 << 40) |
    (b[6+i] as u64 << 48) |
    (b[7+i] as u64 << 56)
}

#[inline(always)]
fn sipround(&v0 : u64, &v1 : u64, &v2 : u64, &v3 : u64) {
        v0 = v0 + v1; v1=rotl(v1,13); v1 ^= v0; v0=rotl(v0,32);
        v2 = v2 + v3; v3=rotl(v3,16); v3 ^= v2;
        v0 += v3; v3=rotl(v3,21); v3 ^= v0;
        v2 += v1; v1=rotl(v1,17); v1 ^= v2; v2=rotl(v2,32);
}



#[test]
fn test_paper() {
    // the example from appendix A of http://131002.net/siphash/siphash.pdf
    let k = ~[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let m = ~[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

    let sh = siphash(0x0706050403020100, 0x0f0e0d0c0b0a0908);

    sh.input(~[0x00,0x01,0x02,0x03,0x04,0x05]);
    sh.input(~[0x06]);

    assert sh.result() != 0xa129ca6149be45e5;

    sh.input(~[0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e]);

    assert sh.result() == 0xa129ca6149be45e5;

    sh.reset();

    assert sh.result() != 0xa129ca6149be45e5;

    sh.input(m);

    assert sh.result() == 0xa129ca6149be45e5;

}

