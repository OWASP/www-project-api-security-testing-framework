package org.owasp.astf.core.result;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class EvidenceMaskingTest {

    @Test
    void setCookieKeepsNameAndAttributes() {
        assertEquals("session=[REDACTED]; Path=/; HttpOnly",
                EvidenceMasking.maskSetCookie("session=abc123; Path=/; HttpOnly"));
        assertEquals("a=[REDACTED]", EvidenceMasking.maskSetCookie("a=b=c"));
        assertEquals("novalue", EvidenceMasking.maskSetCookie("novalue"));
        assertNull(EvidenceMasking.maskSetCookie(null));
    }

    @Test
    void cookieHeaderMasksEveryValue() {
        assertEquals("a=[REDACTED]; b=[REDACTED]", EvidenceMasking.maskCookie("a=1; b=2"));
    }

    @Test
    void locationMasksOnlyTokenLikeParams() {
        assertEquals("https://h/p?access_token=[REDACTED]&next=/x",
                EvidenceMasking.maskLocation("https://h/p?access_token=abc&next=/x"));
        assertEquals("https://h/p?a=1&code=[REDACTED]#f",
                EvidenceMasking.maskLocation("https://h/p?a=1&code=zz#f"));
        assertEquals("https://h/p?next=/x", EvidenceMasking.maskLocation("https://h/p?next=/x"));
        assertNull(EvidenceMasking.maskLocation(null));
    }
}
