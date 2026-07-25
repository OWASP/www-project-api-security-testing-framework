package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Tests mutual TLS (mTLS) client-certificate validation.
 *
 * <p>Some APIs (particularly internal/service-to-service and gRPC APIs) authenticate clients via
 * TLS client certificates rather than — or in addition to — application-layer tokens. Two common
 * misconfigurations in that setup are:</p>
 * <ul>
 *   <li><b>Arbitrary certificate acceptance</b> — the server performs the TLS handshake but never
 *       actually validates the client certificate against a trusted CA, so any self-signed or
 *       otherwise untrusted certificate is accepted.</li>
 *   <li><b>Missing subject/CN validation</b> — the server validates that the certificate chains
 *       to a trusted CA, but never checks that the certificate's subject matches the identity it
 *       claims, allowing certificate substitution between different valid identities.</li>
 * </ul>
 *
 * <p>This test case only runs when the operator has supplied client certificate material via
 * {@code --client-cert} (a valid identity for the target) and, for the arbitrary-acceptance
 * check, {@code --invalid-client-cert} (a deliberately wrong/untrusted certificate). Generating a
 * throwaway invalid certificate automatically isn't attempted — doing so correctly requires a
 * certificate-authority library ASTF doesn't currently depend on, and a pentester testing mTLS
 * specifically will typically already have appropriate test certificates on hand.</p>
 */
public class MutualTlsValidationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(MutualTlsValidationTestCase.class);

    @Override
    public String getId() {
        return "ASTF-MTLS-2023";
    }

    @Override
    public String getName() {
        return "Mutual TLS Validation";
    }

    @Override
    public String getDescription() {
        return "Tests whether the server actually validates client certificates during mutual " +
               "TLS, rather than accepting any presented certificate regardless of trust chain " +
               "or subject.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getFullUrl().startsWith("https://")) {
            return findings;
        }
        if (!httpClient.hasClientCert()) {
            logger.debug("Skipping mTLS validation test — no --client-cert configured");
            return findings;
        }

        logger.info("Executing {} test on {}", getId(), endpoint);
        findings.addAll(testArbitraryCertificateAccepted(endpoint, httpClient));

        return findings;
    }

    /**
     * Confirms the valid certificate is accepted, then presents the deliberately invalid/untrusted
     * certificate to the same endpoint. If the server accepts both identically, it isn't actually
     * validating client certificates at all — the "Arbitrary mTLS" class of vulnerability.
     */
    private List<Finding> testArbitraryCertificateAccepted(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!httpClient.hasInvalidClientCert()) {
            logger.debug("Skipping arbitrary-certificate check — no --invalid-client-cert configured");
            return findings;
        }

        String url = endpoint.getFullUrl();
        try {
            HttpResponse validCertResponse = httpClient.getWithClientCert(
                    url, Map.of(), httpClient.getClientCertPath(), httpClient.getClientCertPassword());

            if (validCertResponse == null || !validCertResponse.isSuccess()) {
                // Can't establish a baseline of "the valid cert works" — nothing to compare against.
                logger.debug("Valid client certificate was not accepted at {}; skipping comparison", endpoint);
                return findings;
            }

            HttpResponse invalidCertResponse;
            try {
                invalidCertResponse = httpClient.getWithClientCert(
                        url, Map.of(), httpClient.getInvalidClientCertPath(), httpClient.getInvalidClientCertPassword());
            } catch (IOException tlsRejected) {
                // The TLS handshake itself failing for the invalid cert is the correct, secure
                // behavior — nothing to report.
                logger.debug("Invalid client certificate correctly rejected at TLS handshake for {}: {}",
                        endpoint, tlsRejected.getMessage());
                return findings;
            }

            if (invalidCertResponse != null && invalidCertResponse.isSuccess()) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Arbitrary Client Certificate Accepted (mTLS)",
                        "The server accepted a deliberately invalid/untrusted client certificate and " +
                        "responded identically to how it responded with a valid certificate. This " +
                        "indicates the server is not actually validating client certificates against " +
                        "a trusted certificate authority, defeating the purpose of mutual TLS.",
                        Severity.CRITICAL,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Configure the TLS server to require and verify that the client certificate " +
                        "chains to a trusted CA (mTLS with client certificate verification enabled), " +
                        "and reject connections presenting untrusted or self-signed certificates."
                );
                finding.setEvidence("Valid cert: HTTP " + validCertResponse.getStatusCode() +
                        "; Invalid/untrusted cert: HTTP " + invalidCertResponse.getStatusCode());
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing mTLS arbitrary-certificate acceptance on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }
}
