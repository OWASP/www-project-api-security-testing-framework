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
    void locationMasksTokenInFragment() {
        assertEquals("https://h/cb#access_token=[REDACTED]&state=x",
                EvidenceMasking.maskLocation("https://h/cb#access_token=abc&state=x"));
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

    @Test
    void locationMasksMoreCredentialNamesAndUserInfo() {
        assertEquals("https://h/cb?pwd=[REDACTED]&ticket=[REDACTED]",
                EvidenceMasking.maskLocation("https://h/cb?pwd=x&ticket=ST-123"));
        assertEquals("https://[REDACTED]@h/p?next=/x",
                EvidenceMasking.maskLocation("https://user:secret@h/p?next=/x"));
    }
}
