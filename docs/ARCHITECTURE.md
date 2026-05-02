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

## Adding New Test Cases

To add a new test case:

1. Create a class implementing the `TestCase` interface
2. Implement the required methods
3. Register the test case in `TestCaseRegistry.registerDefaultTestCases()`
4. Add unit tests for the new test case

Example:

```java
public class NewVulnerabilityTestCase implements TestCase {
    @Override
    public String getId() {
        return "ASTF-API11-2023";
    }

    @Override
    public String getName() {
        return "New Vulnerability";
    }

    @Override
    public String getDescription() {
        return "Tests for a new type of vulnerability";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        // Implement vulnerability detection logic
        // Return list of findings (or empty list if none found)
    }
}
```

## Future Architecture Enhancements

1. Plugin system for custom test cases
2. Distributed scanning capabilities
3. Real-time reporting and notification
4. Machine learning-based detection improvements
5. Integration with vulnerability management platforms