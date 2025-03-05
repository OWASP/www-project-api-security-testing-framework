# OWASP API Security Testing Framework

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/www-project-api-security-testing-framework/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A comprehensive automated testing framework for detecting API security vulnerabilities based on the OWASP API Security Top 10.

## Overview

The OWASP API Security Testing Framework (ASTF) helps security professionals and developers identify vulnerabilities in their APIs through automated testing. Built with enterprise needs in mind, it provides detailed security analysis and integrates with modern CI/CD pipelines.

## Features

- Automated detection of API-specific vulnerabilities
- Comprehensive test coverage of OWASP API Security Top 10
- Support for REST, GraphQL, and gRPC APIs
- CI/CD integration capabilities
- Detailed vulnerability reporting
- Custom rule creation
- Remediation guidance

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.6+

### Installation

```bash
# Clone the repository
git clone https://github.com/OWASP/api-security-testing-framework.git

# Build the project
cd api-security-testing-framework
mvn clean install
```

### Basic Usage

```bash
# Run a basic scan
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar scan \
  --target https://api.example.com \
  --auth-header "Authorization: Bearer YOUR_TOKEN"
```

## Project Structure

```
api-security-testing-framework/
├── src/
│   ├── main/
│   │   ├── java/org/owasp/astf/
│   │   │   ├── core/          # Core scanning engine
│   │   │   ├── testcases/     # API security test cases
│   │   │   ├── integrations/  # CI/CD integrations
│   │   │   └── cli/           # Command line interface
│   │   └── resources/         # Configuration files
│   └── test/                  # Test cases
├── docs/                      # Documentation
└── examples/                  # Usage examples
```

## Documentation

For more detailed information, please refer to our [Documentation](docs/README.md).

## Framework Overview

For detailed understand on the framework, please refer to our [Framework Overview](docs/FRAMEWORK_OVERVIEW.md).

## Architecture

Please refer to our [Architecture](docs/ARCHITECTURE.md).

## Contributing

We welcome contributions from the community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for more information on how to get involved.

## Roadmap

See our [Project Roadmap](https://owasp.org/www-project-api-security-testing-framework/#roadmap) for upcoming features and plans.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Code of Conduct

This project adheres to the [OWASP Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Contact

- Project Leader: [Govindarajan Lakshmikanthan]
- GitHub: [@GovindarajanL](https://github.com/GovindarajanL)
- OWASP Project Page: [OWASP API Security Testing Framework](https://owasp.org/www-project-api-security-testing-framework/)
- Slack: [#project-api-security-testing-framework]()
