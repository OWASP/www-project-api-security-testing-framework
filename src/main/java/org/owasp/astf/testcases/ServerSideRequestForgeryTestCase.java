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
 * Tests for API7:2023 Server Side Request Forgery (SSRF).
 *
 * SSRF vulnerabilities occur when an API fetches a remote resource using a user-supplied URL
 * without validating it. Attackers can trick the server into fetching internal resources,
 * cloud metadata endpoints, or other internal services.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/">OWASP API7:2023</a>
 */
public class ServerSideRequestForgeryTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(ServerSideRequestForgeryTestCase.class);

    // URL parameters commonly used to pass URLs to the server
    private static final List<String> URL_PARAMETERS = List.of(
            "url", "uri", "link", "src", "source", "target", "dest", "destination",
            "redirect", "return", "returnUrl", "return_url", "callback", "callbackUrl",
            "webhook", "webhookUrl", "webhook_url", "fetch", "load", "path",
            "imageUrl", "image_url", "avatar", "icon", "file", "document"
    );

    // SSRF test payloads targeting cloud metadata and internal services
    private static final List<String> SSRF_PAYLOADS = List.of(
            "http://169.254.169.254/latest/meta-data/",          // AWS metadata
            "http://metadata.google.internal/computeMetadata/",   // GCP metadata
            "http://169.254.169.254/metadata/instance",           // Azure metadata
            "http://localhost/",                                   // localhost
            "http://127.0.0.1/",                                  // loopback
            "http://[::1]/",                                       // IPv6 loopback
            "http://0.0.0.0/"                                      // any interface
    );

    // Content patterns that indicate successful SSRF (returned from metadata endpoints)
    private static final List<String> SSRF_INDICATORS = List.of(
            "ami-id", "instance-id", "instance-type",             // AWS metadata keys
            "computeMetadata", "serviceAccounts",                   // GCP metadata keys
            "subscriptionId", "resourceGroupName",                  // Azure metadata keys
            "root:x:", "www-data",                                  // /etc/passwd content
            "docker", "kubernetes", "k8s"                          // container environment
    );

    @Override
    public String getId() {
        return "ASTF-API7-2023";
    }

    @Override
    public String getName() {
        return "Server Side Request Forgery";
    }

    @Override
    public String getDescription() {
        return "Tests for SSRF vulnerabilities by injecting internal or cloud metadata URLs into " +
               "parameters that the API may use to fetch remote resources.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testQueryParameterSsrf(endpoint, httpClient));
        findings.addAll(testBodyParameterSsrf(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testQueryParameterSsrf(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        String baseUrl = endpoint.getFullUrl();

        for (String param : URL_PARAMETERS) {
            for (String payload : SSRF_PAYLOADS) {
                String testUrl = baseUrl + (baseUrl.contains("?") ? "&" : "?") +
                        param + "=" + urlEncode(payload);
                try {
                    HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());

                    if (response != null && containsSsrfIndicator(response.getBody())) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Server Side Request Forgery (SSRF) via Query Parameter",
                                String.format("The API parameter '%s' appears to be vulnerable to SSRF. " +
                                        "The server fetched the URL '%s' and returned content that matches " +
                                        "known internal/metadata service response patterns.",
                                        param, payload),
                                Severity.CRITICAL,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Validate and sanitize all user-supplied URLs. Use an allowlist of permitted " +
                                "domains/IPs. Block requests to private IP ranges (RFC 1918) and cloud metadata " +
                                "endpoints. Disable unnecessary URL-fetching functionality."
                        );
                        finding.setRequestDetails("GET " + testUrl);
                        finding.setEvidence("Response contained SSRF indicator from payload: " + payload);
                        findings.add(finding);
                        return findings; // One confirmed SSRF is enough
                    }
                } catch (Exception e) {
                    logger.debug("Error testing SSRF param {} on {}: {}", param, endpoint, e.getMessage());
                }
            }
        }

        return findings;
    }

    private List<Finding> testBodyParameterSsrf(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String method = endpoint.getMethod().toUpperCase();

        if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
            return findings;
        }

        for (String param : URL_PARAMETERS) {
            for (String payload : SSRF_PAYLOADS) {
                String body = String.format("{\"%s\":\"%s\"}", param, payload);
                try {
                    HttpResponse response = switch (method) {
                        case "POST"  -> httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                        case "PUT"   -> httpClient.putWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                        case "PATCH" -> httpClient.patchWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                        default      -> null;
                    };

                    if (response != null && containsSsrfIndicator(response.getBody())) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Server Side Request Forgery (SSRF) via Request Body",
                                String.format("The API body parameter '%s' appears to be vulnerable to SSRF. " +
                                        "The server fetched the URL '%s' and returned content that matches " +
                                        "known internal/metadata service response patterns.",
                                        param, payload),
                                Severity.CRITICAL,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Validate and sanitize all user-supplied URLs in request bodies. " +
                                "Use a URL allowlist and block requests to internal network ranges."
                        );
                        finding.setRequestDetails(method + " " + endpoint.getFullUrl() + "\nBody: " + body);
                        finding.setEvidence("Response contained SSRF indicator from payload: " + payload);
                        findings.add(finding);
                        return findings;
                    }
                } catch (Exception e) {
                    logger.debug("Error testing body SSRF param {} on {}: {}", param, endpoint, e.getMessage());
                }
            }
        }

        return findings;
    }

    private boolean containsSsrfIndicator(String body) {
        if (body == null || body.isEmpty()) return false;
        String lower = body.toLowerCase();
        return SSRF_INDICATORS.stream().anyMatch(indicator -> lower.contains(indicator.toLowerCase()));
    }

    private String urlEncode(String value) {
        return value.replace(":", "%3A").replace("/", "%2F").replace("?", "%3F")
                .replace("=", "%3D").replace("&", "%26").replace(" ", "%20");
    }
}
