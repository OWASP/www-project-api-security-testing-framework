package org.owasp.astf.core.discovery;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Service responsible for discovering API endpoints through various methods.
 * <p>
 * This class implements multiple discovery strategies:
 * <ul>
 *   <li>OpenAPI/Swagger specification parsing</li>
 *   <li>Common endpoint pattern testing</li>
 *   <li>API root path exploration</li>
 *   <li>Fallback to common endpoints for testing</li>
 * </ul>
 * </p>
 */
public class EndpointDiscoveryService {
    private static final Logger logger = LogManager.getLogger(EndpointDiscoveryService.class);

    private final ScanConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    // Paths where API specifications are commonly found
    private static final List<String> SPEC_PATHS = List.of(
            "/swagger/v1/swagger.json",
            "/swagger.json",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/openapi.json",
            "/swagger/index.html",
            "/.well-known/openapi.json",
            "/openapi/v3/api-docs",
            "/api/swagger.json"
    );

    // Common API root paths to check
    private static final List<String> COMMON_API_ROOTS = List.of(
            "/api",
            "/api/v1",
            "/api/v2",
            "/rest",
            "/service",
            "/services",
            "/v1",
            "/v2"
    );

    // Common resource patterns for APIs
    private static final List<String> COMMON_RESOURCES = List.of(
            "users",
            "accounts",
            "customers",
            "products",
            "orders",
            "items",
            "transactions",
            "auth",
            "login",
            "register",
            "profile",
            "settings",
            "admin",
            "search",
            "comments",
            "posts",
            "articles",
            "categories",
            "tags"
    );

    // Default HTTP methods to test
    private static final List<String> COMMON_METHODS = List.of(
            "GET",
            "POST",
            "PUT",
            "DELETE"
    );

    /**
     * Creates a new endpoint discovery service.
     *
     * @param config The scan configuration
     * @param httpClient The HTTP client for making requests
     */
    public EndpointDiscoveryService(ScanConfig config, HttpClient httpClient) {
        this.config = config;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Discovers API endpoints using multiple strategies.
     *
     * @return A list of discovered endpoints
     */
    public List<EndpointInfo> discoverEndpoints() {
        logger.info("Starting API endpoint discovery for: {}", config.getTargetUrl());
        Set<EndpointInfo> discoveredEndpoints = new HashSet<>();

        try {
            // Strategy 1: Try to find and parse OpenAPI/Swagger specifications
            logger.debug("Attempting to discover OpenAPI/Swagger specifications");
            List<EndpointInfo> specEndpoints = discoverFromSpecifications();
            if (!specEndpoints.isEmpty()) {
                logger.info("Found {} endpoints from API specifications", specEndpoints.size());
                discoveredEndpoints.addAll(specEndpoints);
                return new ArrayList<>(discoveredEndpoints);
            }

            // Strategy 2: Explore common API roots
            logger.debug("Exploring common API root paths");
            List<EndpointInfo> rootEndpoints = exploreApiRoots();
            discoveredEndpoints.addAll(rootEndpoints);

            // Strategy 3: Test common resource patterns
            logger.debug("Testing common API resource patterns");
            List<EndpointInfo> resourceEndpoints = testCommonResourcePatterns();
            discoveredEndpoints.addAll(resourceEndpoints);

            if (discoveredEndpoints.isEmpty()) {
                logger.warn("No endpoints discovered through automatic methods");
                // Fallback strategy: Use common endpoints for testing
                logger.info("Using fallback common endpoints for testing");
                discoveredEndpoints.addAll(getFallbackEndpoints());
            } else {
                logger.info("Discovered {} unique endpoints", discoveredEndpoints.size());
            }

        } catch (Exception e) {
            logger.error("Error during endpoint discovery: {}", e.getMessage());
            logger.debug("Exception details:", e);
            // Fallback to common endpoints on error
            discoveredEndpoints.addAll(getFallbackEndpoints());
        }

        return new ArrayList<>(discoveredEndpoints);
    }

    /**
     * Attempts to discover endpoints by finding and parsing OpenAPI/Swagger specifications.
     *
     * @return List of endpoints discovered from specifications
     */
    private List<EndpointInfo> discoverFromSpecifications() {
        List<EndpointInfo> endpoints = new ArrayList<>();

        for (String specPath : SPEC_PATHS) {
            try {
                String url = config.getTargetUrl() + specPath;
                logger.debug("Checking for API specification at: {}", url);

                String response = httpClient.get(url, Map.of());

                if (response != null && !response.isEmpty()) {
                    logger.info("Found potential API specification at: {}", url);

                    // Check if it's a valid JSON response that might be an OpenAPI spec
                    if (isValidJson(response) && (response.contains("\"swagger\"") ||
                            response.contains("\"openapi\""))) {

                        // Parse the specification and extract endpoints
                        endpoints.addAll(parseOpenApiSpec(response));

                        if (!endpoints.isEmpty()) {
                            return endpoints;
                        }
                    } else if (response.contains("<html") && response.contains("swagger")) {
                        // This might be Swagger UI - try to extract the spec URL
                        String specUrl = extractSpecUrlFromSwaggerUi(response);
                        if (specUrl != null) {
                            String baseUrl = extractBaseUrl(url);
                            String fullSpecUrl = specUrl.startsWith("http") ? specUrl : baseUrl + specUrl;

                            logger.debug("Extracted spec URL from Swagger UI: {}", fullSpecUrl);
                            String specResponse = httpClient.get(fullSpecUrl, Map.of());

                            if (specResponse != null && !specResponse.isEmpty() && isValidJson(specResponse)) {
                                endpoints.addAll(parseOpenApiSpec(specResponse));

                                if (!endpoints.isEmpty()) {
                                    return endpoints;
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                logger.debug("Error checking spec path {}: {}", specPath, e.getMessage());
                // Continue with next path
            }
        }

        return endpoints;
    }

    /**
     * Parses an OpenAPI/Swagger specification to extract endpoints.
     *
     * @param specJson The specification JSON string
     * @return List of endpoints extracted from the specification
     */
    private List<EndpointInfo> parseOpenApiSpec(String specJson) {
        List<EndpointInfo> endpoints = new ArrayList<>();

        try {
            JsonNode root = objectMapper.readTree(specJson);

            // Determine if this is Swagger 2.0 or OpenAPI 3.x
            boolean isSwagger2 = root.has("swagger") && root.get("swagger").asText().startsWith("2");

            if (isSwagger2) {
                // Parse Swagger 2.0
                JsonNode paths = root.path("paths");
                if (paths.isObject()) {
                    paths.fields().forEachRemaining(entry -> {
                        String path = entry.getKey();
                        JsonNode pathItem = entry.getValue();

                        pathItem.fields().forEachRemaining(methodEntry -> {
                            String method = methodEntry.getKey().toUpperCase();
                            // Skip non-HTTP method fields
                            if (Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
                                    .contains(method)) {

                                EndpointInfo endpoint = new EndpointInfo(path, method);
                                endpoints.add(endpoint);
                            }
                        });
                    });
                }
            } else {
                // Parse OpenAPI 3.x
                JsonNode paths = root.path("paths");
                if (paths.isObject()) {
                    paths.fields().forEachRemaining(entry -> {
                        String path = entry.getKey();
                        JsonNode pathItem = entry.getValue();

                        pathItem.fields().forEachRemaining(methodEntry -> {
                            String method = methodEntry.getKey().toUpperCase();
                            // Skip non-HTTP method fields
                            if (Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
                                    .contains(method)) {

                                boolean requiresAuth = false;

                                // Check for security requirements
                                JsonNode security = methodEntry.getValue().path("security");
                                if (!security.isMissingNode() && security.isArray() && security.size() > 0) {
                                    requiresAuth = true;
                                }

                                EndpointInfo endpoint = new EndpointInfo(
                                        path, method, "application/json", null, requiresAuth);
                                endpoints.add(endpoint);
                            }
                        });
                    });
                }
            }

            logger.info("Extracted {} endpoints from OpenAPI specification", endpoints.size());

        } catch (Exception e) {
            logger.error("Error parsing OpenAPI specification: {}", e.getMessage());
        }

        return endpoints;
    }

    /**
     * Extracts the specification URL from Swagger UI HTML.
     *
     * @param html The Swagger UI HTML
     * @return The specification URL or null if not found
     */
    private String extractSpecUrlFromSwaggerUi(String html) {
        // Look for the spec URL in the Swagger UI HTML
        Pattern pattern = Pattern.compile("url:\\s*['\"]([^'\"]+)['\"]");
        Matcher matcher = pattern.matcher(html);

        if (matcher.find()) {
            return matcher.group(1);
        }

        return null;
    }

    /**
     * Extracts the base URL from a full URL.
     *
     * @param url The full URL
     * @return The base URL
     */
    private String extractBaseUrl(String url) {
        int pathStart = url.indexOf("/", 8); // Skip "http://" or "https://"
        if (pathStart != -1) {
            return url.substring(0, pathStart);
        }
        return url;
    }

    /**
     * Explores common API root paths to find valid API endpoints.
     *
     * @return List of endpoints discovered from root paths
     */
    private List<EndpointInfo> exploreApiRoots() {
        List<EndpointInfo> endpoints = new ArrayList<>();

        for (String rootPath : COMMON_API_ROOTS) {
            try {
                String url = config.getTargetUrl() + rootPath;
                logger.debug("Testing API root path: {}", url);

                String response = httpClient.get(url, Map.of());

                if (response != null && !response.isEmpty()) {
                    logger.info("Found potential API root at: {}", url);

                    // If we get a valid response, add the root path
                    endpoints.add(new EndpointInfo(rootPath, "GET"));

                    // If it's JSON, it might be an API that returns available endpoints
                    if (isValidJson(response)) {
                        try {
                            // Try to extract endpoints from the response
                            JsonNode root = objectMapper.readTree(response);
                            if (root.isArray() || (root.isObject() && root.size() > 0)) {
                                // This might be a listing of resources or endpoints
                                logger.debug("Root path returned JSON data, might contain API information");

                                // Add some child resource paths to test based on common patterns
                                for (String resource : COMMON_RESOURCES) {
                                    endpoints.add(new EndpointInfo(rootPath + "/" + resource, "GET"));
                                }
                            }
                        } catch (Exception e) {
                            logger.debug("Error parsing root path response: {}", e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing root path {}: {}", rootPath, e.getMessage());
                // Continue with next path
            }
        }

        return endpoints;
    }

    /**
     * Tests common API resource patterns to find valid endpoints.
     *
     * @return List of endpoints discovered from common patterns
     */
    private List<EndpointInfo> testCommonResourcePatterns() {
        List<EndpointInfo> endpoints = new ArrayList<>();

        // Combine API roots with common resources
        for (String rootPath : COMMON_API_ROOTS) {
            for (String resource : COMMON_RESOURCES) {
                String resourcePath = rootPath + "/" + resource;

                try {
                    String url = config.getTargetUrl() + resourcePath;
                    logger.debug("Testing resource path: {}", url);

                    String response = httpClient.get(url, Map.of());

                    if (response != null && !response.isEmpty() && !response.contains("error") &&
                            !response.contains("not found") && !response.contains("404")) {
                        logger.info("Found potential resource endpoint: {}", url);

                        // Add the base resource endpoint
                        endpoints.add(new EndpointInfo(resourcePath, "GET"));

                        // Add the resource with ID parameter for common methods
                        for (String method : COMMON_METHODS) {
                            endpoints.add(new EndpointInfo(resourcePath + "/{id}", method));
                        }

                        // If we found users, add some common user-related endpoints
                        if (resource.equals("users") || resource.equals("accounts")) {
                            endpoints.add(new EndpointInfo(resourcePath + "/me", "GET"));
                            endpoints.add(new EndpointInfo(resourcePath + "/{id}/profile", "GET"));
                        }

                        // If we found products, add some common product-related endpoints
                        if (resource.equals("products") || resource.equals("items")) {
                            endpoints.add(new EndpointInfo(resourcePath + "/search", "GET"));
                            endpoints.add(new EndpointInfo(resourcePath + "/categories", "GET"));
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Error testing resource path {}: {}", resourcePath, e.getMessage());
                    // Continue with next path
                }
            }
        }

        return endpoints;
    }

    /**
     * Gets a list of common fallback endpoints to use when discovery fails.
     *
     * @return List of common API endpoints
     */
    private List<EndpointInfo> getFallbackEndpoints() {
        List<EndpointInfo> endpoints = new ArrayList<>();

        // Default base path
        String basePath = "/api/v1";

        // Add common endpoints for testing
        endpoints.add(new EndpointInfo(basePath + "/users", "GET"));
        endpoints.add(new EndpointInfo(basePath + "/users/{id}", "GET"));
        endpoints.add(new EndpointInfo(basePath + "/users", "POST"));
        endpoints.add(new EndpointInfo(basePath + "/users/{id}", "PUT"));
        endpoints.add(new EndpointInfo(basePath + "/users/{id}", "DELETE"));

        endpoints.add(new EndpointInfo(basePath + "/auth/login", "POST"));
        endpoints.add(new EndpointInfo(basePath + "/auth/logout", "POST"));

        endpoints.add(new EndpointInfo(basePath + "/products", "GET"));
        endpoints.add(new EndpointInfo(basePath + "/products/{id}", "GET"));

        endpoints.add(new EndpointInfo(basePath + "/orders", "GET"));
        endpoints.add(new EndpointInfo(basePath + "/orders/{id}", "GET"));
        endpoints.add(new EndpointInfo(basePath + "/orders", "POST"));

        logger.info("Using {} fallback endpoints for testing", endpoints.size());
        return endpoints;
    }

    /**
     * Checks if a string is valid JSON.
     *
     * @param json The string to check
     * @return true if the string is valid JSON
     */
    private boolean isValidJson(String json) {
        try {
            objectMapper.readTree(json);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}