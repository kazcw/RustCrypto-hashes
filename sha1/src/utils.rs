use consts::{BLOCK_LEN, K0, K1, K2, K3};
use byte_tools::read_u32v_be;

/*
    // Rounds 0..20
    // TODO: replace with `u32x4::load`
    let mut h0 = u32x4(state[0], state[1], state[2], state[3]);
    let mut w0 = u32x4(block[0], block[1], block[2], block[3]);
    let mut h1 = sha1_digest_round_x4(h0, sha1_first_add(state[4], w0), 0);
    let mut w1 = u32x4(block[4], block[5], block[6], block[7]);
    h0 = rounds4!(h1, h0, w1, 0);
    let mut w2 = u32x4(block[8], block[9], block[10], block[11]);
    h1 = rounds4!(h0, h1, w2, 0);
    let mut w3 = u32x4(block[12], block[13], block[14], block[15]);
    h0 = rounds4!(h1, h0, w3, 0);
    let mut w4 = schedule!(w0, w1, w2, w3);
    h1 = rounds4!(h0, h1, w4, 0);

    // Rounds 20..40
    w0 = schedule!(w1, w2, w3, w4);
    h0 = rounds4!(h1, h0, w0, 1);
    w1 = schedule!(w2, w3, w4, w0);
    h1 = rounds4!(h0, h1, w1, 1);
    w2 = schedule!(w3, w4, w0, w1);
    h0 = rounds4!(h1, h0, w2, 1);
    w3 = schedule!(w4, w0, w1, w2);
    h1 = rounds4!(h0, h1, w3, 1);
    w4 = schedule!(w0, w1, w2, w3);
    h0 = rounds4!(h1, h0, w4, 1);

    // Rounds 40..60
    w0 = schedule!(w1, w2, w3, w4);
    h1 = rounds4!(h0, h1, w0, 2);
    w1 = schedule!(w2, w3, w4, w0);
    h0 = rounds4!(h1, h0, w1, 2);
    w2 = schedule!(w3, w4, w0, w1);
    h1 = rounds4!(h0, h1, w2, 2);
    w3 = schedule!(w4, w0, w1, w2);
    h0 = rounds4!(h1, h0, w3, 2);
    w4 = schedule!(w0, w1, w2, w3);
    h1 = rounds4!(h0, h1, w4, 2);

    // Rounds 60..80
    w0 = schedule!(w1, w2, w3, w4);
    h0 = rounds4!(h1, h0, w0, 3);
    w1 = schedule!(w2, w3, w4, w0);
    h1 = rounds4!(h0, h1, w1, 3);
    w2 = schedule!(w3, w4, w0, w1);
    h0 = rounds4!(h1, h0, w2, 3);
    w3 = schedule!(w4, w0, w1, w2);
    h1 = rounds4!(h0, h1, w3, 3);
    w4 = schedule!(w0, w1, w2, w3);
    h0 = rounds4!(h1, h0, w4, 3);

    let e = sha1_first(h1).rotate_left(30);
    let u32x4(a, b, c, d) = h0;

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
*/

/*
    //cycle 12-15 -> 64-67

        sha1nexte   xmm2,  xmm10
        movdqa      xmm9,  xmm1
        sah1msg2   xmm11, xmm10
        sha1rnds4   xmm1,  xmm2, 0
        sah1msg1   xmm13, xmm10
        pxor        xmm12, xmm10

*/

const shuffle_mask: u32x4 = u32x4(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
#[repr(simd)]
#[derive(Copy, Clone, Debug)]
pub struct u32x4(pub u32, pub u32, pub u32, pub u32);



pub fn compress(abcd: &mut u32x4, e: &mut u32x4, block: &[u8; 64]) {

    unsafe {
        asm!(concat!("
            movdqa      xmm14, xmm1
            movdqa      xmm15, xmm2
            ",
            // Rounds 0-3
            "
            movdqu      xmm10, [rax + 0*16]
            pshufb      xmm10, xmm3

            paddd       xmm2,  xmm10
            movdqa      xmm9,  xmm1
            sha1rnds4   xmm1,  xmm2, 0
            ",
            // Rounds 4-7
            "
            movdqu      xmm11, [rax + 1*16]
            pshufb      xmm11, xmm3
            sha1nexte   xmm9,  xmm11
            movdqa      xmm2,  xmm1
            sha1rnds4   xmm1,  xmm9, 0

            sha1msg1   xmm10, xmm11
            ",
            // Rounds 8-11
            "
            movdqu      xmm12, [rax + 2*16]
            pshufb      xmm12, xmm3
            sha1nexte   xmm2,  xmm12
            movdqa      xmm9,  xmm1
            sha1rnds4   xmm1,  xmm2, 0

            sha1msg1   xmm11, xmm12
            pxor        xmm10, xmm12
            ",
            // Rounds 12-15
            "
            movdqu      xmm13, [rax + 3*16]
            pshufb      xmm13, xmm3
            sha1nexte   xmm9,  xmm13
            movdqa      xmm2,  xmm1
            sha1msg2   xmm10, xmm13
            sha1rnds4   xmm1,  xmm9, 0
            sha1msg1   xmm12, xmm13
            pxor        xmm11, xmm13
            ",


        //cycle 12-15 -> 64-67


        // end cycle

            // Rounds 68-71
            "
            sha1nexte   xmm9,  xmm11
            movdqa      xmm2,  xmm1
            sha1msg2   xmm12, xmm11
            sha1rnds4   xmm1,  xmm9, 3
            pxor        xmm13, xmm11
            ",
            // Rounds 72-75
            "
            sha1nexte   xmm2,  xmm12
            movdqa      xmm9,  xmm1
            sha1msg2   xmm13, xmm12
            sha1rnds4   xmm1,  xmm2, 3
            ",
            // Rounds 76-79
            "
            sha1nexte   xmm9,  xmm13
            movdqa      xmm2,  xmm1
            sha1rnds4   xmm1,  xmm9, 3
            ",
            // Write result
            "
            sha1nexte   xmm2,  xmm15
            paddd       xmm1,  xmm14
            ")
            : "={xmm1}"(*abcd), "={xmm2}"(*e)
            : "{rax}"(block.as_ptr()), "{xmm1}"(*abcd), "{xmm2}"(*e),
                "{xmm3}"(shuffle_mask)
            : "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
            : "intel", "alignstack"
        )
    }
}
