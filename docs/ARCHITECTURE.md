# Framework Architecture

## Overview

The OWASP API Security Testing Framework is designed with a modular architecture to allow for extensibility and maintainability. This document outlines the high-level architecture and key components of the framework.

## Component Architecture

```
+----------------------------+
|          CLI Layer         |
+----------------------------+
               |
+----------------------------+
|        Scanner Core        |
+----------------------------+
       /      |       \
      /       |        \
+--------+ +--------+ +--------+
| HTTP   | | Test   | | Report |
| Client | | Cases  | | Engine |
+--------+ +--------+ +--------+
```

### Key Components

1. **CLI Layer** (`org.owasp.astf.cli`)
    - Parses command-line arguments
    - Configures and initializes the scanner
    - Handles user interaction
    - Manages input/output

2. **Scanner Core** (`org.owasp.astf.core`)
    - Orchestrates the scanning process
    - Manages test case execution
    - Handles multi-threading and concurrency
    - Collects and processes results

3. **HTTP Client** (`org.owasp.astf.core.http`)
    - Manages API communications
    - Handles authentication
    - Processes requests and responses
    - Supports various HTTP methods and content types

4. **Test Cases** (`org.owasp.astf.testcases`)
    - Individual security test implementations
    - Each test case targets specific vulnerability types
    - Implements the TestCase interface
    - Registered and managed by TestCaseRegistry

5. **Report Engine** (`org.owasp.astf.reporting`)
    - Generates reports in various formats (JSON, HTML, XML, SARIF)
    - Formats findings with appropriate details
    - Supports different output destinations

6. **Integrations** (`org.owasp.astf.integrations`)
    - CI/CD integration components
    - External tool connectors
    - Notification systems

## Data Flow

1. User invokes the CLI with scan parameters
2. CLI configures the scanner with appropriate settings
3. Scanner discovers or loads target endpoints
4. For each endpoint, applicable test cases are executed
5. Test cases use the HTTP client to make API requests
6. Findings are collected by the scanner
7. Report engine generates the requested output format
8. Results are returned to the user

## Key Interfaces

### TestCase Interface

```java
public interface TestCase {
    String getId();
    String getName();
    String getDescription();
    List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException;
}
```

All test cases implement this interface, allowing the scanner to execute them uniformly.

### EndpointInfo Class

```java
public class EndpointInfo {
    private String path;
    private String method;
    private String contentType;
    private String requestBody;
    private boolean requiresAuthentication;
    
    // Constructors, getters, etc.
}
```

Represents an API endpoint to be tested, including path, method, and metadata.

### Finding Class

```java
public class Finding {
    private String id;
    private String title;
    private String description;
    private Severity severity;
    private String testCaseId;
    private String endpoint;
    private String requestDetails;
    private String responseDetails;
    private String remediation;
    private String evidence;
    
    // Constructors, getters, etc.
}
```

Represents a security finding with all relevant details.

## Design Principles

1. **Modularity**: Components are designed with clear boundaries
2. **Extensibility**: Easy to add new test cases and functionality
3. **Testability**: Components can be tested in isolation
4. **Performance**: Efficient execution for large API surfaces
5. **Usability**: Clear interfaces and documentation

## Thread Model

The scanner uses a thread pool to execute test cases concurrently:

1. One thread per endpoint-testcase combination
2. Configurable thread count via `--threads` option
3. Uses Java 21 virtual threads for efficiency
4. Results are synchronized to prevent race conditions

## Registered Test Cases

The `TestCaseRegistry` registers 12 test cases at startup:

| ID | Class | Category |
|---|---|---|
| `ASTF-API1-2023` | `BrokenObjectLevelAuthorizationTestCase` | API1:2023 |
| `ASTF-API2-2023` | `BrokenAuthenticationTestCase` | API2:2023 |
| `ASTF-API3-2023` | `BrokenObjectPropertyLevelAuthorizationTestCase` | API3:2023 |
| `ASTF-API4-2023` | `UnrestrictedResourceConsumptionTestCase` | API4:2023 |
| `ASTF-API5-2023` | `BrokenFunctionLevelAuthorizationTestCase` | API5:2023 |
| `ASTF-API6-2023` | `UnrestrictedAccessToSensitiveFlowsTestCase` | API6:2023 |
| `ASTF-API7-2023` | `ServerSideRequestForgeryTestCase` | API7:2023 |
| `ASTF-API8-2023` | `SecurityMisconfigurationTestCase` | API8:2023 |
| `ASTF-API9-2023` | `ImproperInventoryManagementTestCase` | API9:2023 |
| `ASTF-API10-2023` | `UnsafeConsumptionOfApisTestCase` | API10:2023 |
| `ASTF-GRAPHQL-2023` | `GraphQLSecurityTestCase` | API3/4/8:2023 |
| `ASTF-GRPC-2023` | `GrpcEndpointDetectionTestCase` | API8/9:2023 |

## Adding New Test Cases

To add a new test case:

1. Create a class implementing the `TestCase` interface in `src/main/java/org/owasp/astf/testcases/`
2. Implement the four required methods
3. Register the test case in `TestCaseRegistry.registerDefaultTestCases()`
4. Add unit tests (see any existing `*TestCaseTest.java` for the Mockito pattern)

Example skeleton:

```java
public class NewVulnerabilityTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(NewVulnerabilityTestCase.class);

    @Override
    public String getId() { return "ASTF-API11-2023"; }

    @Override
    public String getName() { return "New Vulnerability"; }

    @Override
    public String getDescription() { return "Tests for a new type of API vulnerability."; }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse response = httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());
            if (response != null && /* detection condition */) {
                findings.add(new Finding(
                    UUID.randomUUID().toString(),
                    "Finding Title",
                    "Description of what is wrong and why it matters.",
                    Severity.HIGH,
                    getId(),
                    "GET " + endpoint.getPath(),
                    "How to fix this vulnerability."
                ));
            }
        } catch (Exception e) {
            logger.debug("Error in {}: {}", getId(), e.getMessage());
        }
        return findings;
    }
}
```

## Test Coverage

The framework has **229 passing unit tests** across 25 test suites, covering:

- All 12 test case implementations (positive and negative cases)
- Core scanner, HTTP client, configuration loader
- All 4 report generators (JSON, HTML, SARIF, XML)
- GitHub Actions result processor
- Endpoint discovery service

Run the full suite:
```bash
mvn test
```

## Future Architecture Enhancements

1. Plugin system for custom test cases loaded from JARs
2. Distributed scanning capabilities for large API surfaces
3. Real-time reporting and notification webhooks
4. OpenAPI/Swagger spec import for precise endpoint targeting
5. Integration with vulnerability management platforms (Defect Dojo, Jira)