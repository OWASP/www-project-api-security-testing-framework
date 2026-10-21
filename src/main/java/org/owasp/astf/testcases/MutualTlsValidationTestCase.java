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
     * validating client certificates at all: the "Arbitrary mTLS" class of vulnerability.
     *
     * <p>The first pair carries the certificate as its only credential. When the valid certificate
     * alone is not accepted and the scan has credentials (an API that needs a certificate AND a
     * token), the pair is sent again with the same configured credentials on both requests, so the
     * only difference between them is still the certificate. A result from that pair says so in
     * its title and evidence.</p>
     */
    private List<Finding> testArbitraryCertificateAccepted(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!httpClient.hasInvalidClientCert()) {
            logger.debug("Skipping arbitrary-certificate check: no --invalid-client-cert configured");
            return findings;
        }

        String url = endpoint.getFullUrl();
        HttpResponse certOnlyValid = null;
        try {
            certOnlyValid = httpClient.getWithClientCert(
                    url, Map.of(), httpClient.getClientCertPath(), httpClient.getClientCertPassword());
        } catch (Exception e) {
            logger.debug("Valid client certificate request failed at {}: {}", endpoint, e.getMessage());
        }

        if (certOnlyValid != null && certOnlyValid.isSuccess()) {
            compare(endpoint, httpClient, certOnlyValid, false, null).ifPresent(findings::add);
            return findings;
        }

        if (!httpClient.hasConfiguredCredentials()) {
            // Can't establish a baseline of "the valid cert works", and there are no credentials
            // that could make it work: nothing to compare against.
            logger.debug("Valid client certificate was not accepted at {}; no credentials configured, " +
                    "so no comparison", endpoint);
            return findings;
        }

        try {
            HttpResponse credentialedValid = httpClient.getWithClientCertAndCredentials(
                    url, Map.of(), httpClient.getClientCertPath(), httpClient.getClientCertPassword());
            if (credentialedValid == null || !credentialedValid.isSuccess()) {
                logger.debug("Valid client certificate was not accepted at {} even with the configured " +
                        "credentials; no comparison", endpoint);
                return findings;
            }
            compare(endpoint, httpClient, credentialedValid, true, certOnlyValid).ifPresent(findings::add);
        } catch (javax.net.ssl.SSLException e) {
            // The credentialed comparison validates the server certificate, because it sends a token or
            // API key. A self-signed server certificate therefore stops it, and it must not be silent.
            Finding notMade = new Finding(
                    UUID.randomUUID().toString(),
                    "mTLS Certificate Comparison With Credentials Not Made (server certificate not trusted)",
                    "The client certificate alone was not accepted, so the comparison of a valid and an invalid " +
                    "client certificate needs the scan's credentials as well. Those are only sent over a " +
                    "connection whose server certificate validates, and this server's certificate is not trusted " +
                    "by this JVM, so the comparison was not made and no credential was sent.",
                    Severity.INFO,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Add the server's certificate authority to the Java trust store (or test a deployment with a " +
                    "certificate from a trusted authority) to run this comparison."
            );
            notMade.setEvidence("TLS error: " + e.getMessage());
            findings.add(notMade);
        } catch (Exception e) {
            logger.debug("Error testing mTLS arbitrary-certificate acceptance with credentials on {}: {}",
                    endpoint, e.getMessage());
        }

        return findings;
    }

    /**
     * Sends the invalid certificate the same way the accepted valid-certificate request was sent
     * (certificate only, or with the configured credentials) and reports if it is accepted too.
     */
    private java.util.Optional<Finding> compare(EndpointInfo endpoint, HttpClient httpClient,
                                                HttpResponse validResponse, boolean withCredentials,
                                                HttpResponse certOnlyValid) {
        String url = endpoint.getFullUrl();
        HttpResponse invalidResponse;
        try {
            invalidResponse = withCredentials
                    ? httpClient.getWithClientCertAndCredentials(url, Map.of(),
                            httpClient.getInvalidClientCertPath(), httpClient.getInvalidClientCertPassword())
                    : httpClient.getWithClientCert(url, Map.of(),
                            httpClient.getInvalidClientCertPath(), httpClient.getInvalidClientCertPassword());
        } catch (IOException tlsRejected) {
            // The TLS handshake itself failing for the invalid cert is the correct, secure
            // behavior: nothing to report.
            logger.debug("Invalid client certificate correctly rejected at TLS handshake for {}: {}",
                    endpoint, tlsRejected.getMessage());
            return java.util.Optional.empty();
        } catch (Exception e) {
            logger.debug("Error testing mTLS arbitrary-certificate acceptance on {}: {}", endpoint, e.getMessage());
            return java.util.Optional.empty();
        }

        if (invalidResponse == null || !invalidResponse.isSuccess()) {
            return java.util.Optional.empty();
        }

        String title = "Arbitrary Client Certificate Accepted (mTLS)";
        String description = "The server accepted a deliberately invalid/untrusted client certificate and " +
                "responded identically to how it responded with a valid certificate. This " +
                "indicates the server is not actually validating client certificates against " +
                "a trusted certificate authority, defeating the purpose of mutual TLS.";
        Severity severity = Severity.CRITICAL;
        String evidence = "Valid cert: HTTP " + validResponse.getStatusCode() +
                "; Invalid/untrusted cert: HTTP " + invalidResponse.getStatusCode();
        if (withCredentials) {
            title = "Arbitrary Client Certificate Accepted (mTLS, with the configured credentials)";
            description = "With the scan's configured credentials on both requests, the server accepted a " +
                    "deliberately invalid/untrusted client certificate just as it accepted the valid one. " +
                    "The credentials are still needed, but the client certificate is not being validated " +
                    "against a trusted certificate authority, so it adds no assurance of the caller's identity.";
            severity = Severity.HIGH;
            String certOnly = certOnlyValid != null
                    ? "HTTP " + certOnlyValid.getStatusCode()
                    : "request failed";
            evidence = "Valid cert alone (no other credentials): " + certOnly +
                    ". Comparison made with the configured credentials on both requests: " + evidence;
        }

        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                title,
                description,
                severity,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Configure the TLS server to require and verify that the client certificate " +
                "chains to a trusted CA (mTLS with client certificate verification enabled), " +
                "and reject connections presenting untrusted or self-signed certificates."
        );
        finding.setEvidence(evidence);
        return java.util.Optional.of(finding);
    }
}
