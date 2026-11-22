package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class LogRedactorTest {

    @Test
    public void masksEmail() {
        assertEquals("user *** logged in", LogRedactor.redact("user someone@example.com logged in"));
    }

    @Test
    public void masksIpv4AndMac() {
        String in = "peer 192.168.31.77 mac aa:bb:cc:dd:ee:ff up";
        String out = LogRedactor.redact(in);
        assertTrue(out, out.contains("peer *** mac *** up"));
    }

    @Test
    public void masksCnMobile() {
        assertEquals("call *** now", LogRedactor.redact("call 13812345678 now"));
    }

    @Test
    public void masksExplicitKeyValues() {
        String out = LogRedactor.redact("serial=ABC123DEF456 imei: 860000000000001 token=deadbeef");
        assertEquals("serial=*** imei=*** token=***", out);
    }

    /** 排障必须保留的字段不能被误伤。 */
    @Test
    public void keepsKernelVersionPathsAndHex() {
        String in = "kernel=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k "
                + "slide=0x1f000000 path=/data/local/tmp/uaf_replay.log";
        String out = LogRedactor.redact(in);
        assertEquals(in, out);
    }

    @Test
    public void keepsOrdinaryNumbers() {
        String in = "attempt 3/8 elapsed 41s uid=0 cap=0x3fffffffff";
        assertEquals(in, LogRedactor.redact(in));
    }

    @Test
    public void handlesNullAndEmpty() {
        assertNull(LogRedactor.redact(null));
        assertEquals("", LogRedactor.redact(""));
    }
}
