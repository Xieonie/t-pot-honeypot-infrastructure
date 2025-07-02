# Contributing to T-Pot Honeypot Infrastructure 🤝

Thank you for your interest in contributing to the T-Pot Honeypot Infrastructure project! This document provides guidelines for contributing to this repository.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Security Considerations](#security-considerations)
- [Documentation Standards](#documentation-standards)
- [Testing Requirements](#testing-requirements)

## Code of Conduct

This project adheres to a code of conduct that promotes a welcoming and inclusive environment:

- **Be respectful**: Treat all contributors with respect and professionalism
- **Be constructive**: Provide helpful feedback and suggestions
- **Be collaborative**: Work together to improve the project
- **Be responsible**: Consider the security implications of all contributions

## How to Contribute

### 🐛 Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating new issues
3. **Provide detailed information**:
   - Operating system and version
   - Proxmox VE version
   - T-Pot version
   - OPNsense version
   - Steps to reproduce
   - Expected vs actual behavior
   - Log files and error messages

### 💡 Suggesting Enhancements

1. **Check existing feature requests** to avoid duplicates
2. **Use the feature request template**
3. **Provide detailed description**:
   - Use case and motivation
   - Proposed solution
   - Alternative solutions considered
   - Additional context

### 🔧 Contributing Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** following our guidelines
4. **Test thoroughly** in a lab environment
5. **Commit with clear messages**: `git commit -m 'Add amazing feature'`
6. **Push to your fork**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

## Development Setup

### Prerequisites

- Proxmox VE 8.0+ test environment
- Basic knowledge of:
  - Linux system administration
  - Docker and containerization
  - Network security concepts
  - Firewall configuration

### Local Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/t-pot-honeypot-infrastructure.git
cd t-pot-honeypot-infrastructure

# Create development branch
git checkout -b feature/your-feature-name

# Set up pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### Testing Environment

- **Isolated Network**: Use a separate test network
- **Virtual Machines**: Test with fresh VM deployments
- **Backup Configurations**: Always backup before testing
- **Documentation**: Document test procedures and results

## Contribution Guidelines

### 📝 Code Style

#### Shell Scripts
```bash
#!/bin/bash
# Script description
# Author: Your Name
# Version: 1.0

set -euo pipefail

# Use meaningful variable names
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="config/environment.conf"

# Function naming: lowercase with underscores
check_prerequisites() {
    # Function implementation
}

# Error handling
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found" >&2
    exit 1
fi
```

#### Documentation
- Use clear, concise language
- Include code examples
- Provide step-by-step instructions
- Add troubleshooting sections
- Use proper Markdown formatting

#### Configuration Files
- Use consistent naming conventions
- Include comprehensive comments
- Provide example values
- Document all parameters

### 🔒 Security Guidelines

#### Security-First Approach
- **Principle of Least Privilege**: Grant minimal necessary permissions
- **Defense in Depth**: Implement multiple security layers
- **Secure by Default**: Default configurations should be secure
- **Input Validation**: Validate all user inputs
- **Error Handling**: Don't expose sensitive information in errors

#### Sensitive Information
- **Never commit secrets**: Use environment variables or config files
- **Sanitize logs**: Remove sensitive data from log outputs
- **Secure communications**: Use encrypted connections where possible
- **Access controls**: Implement proper authentication and authorization

### 📚 Documentation Standards

#### README Files
- Clear project description
- Installation instructions
- Usage examples
- Troubleshooting section
- Contributing guidelines

#### Code Documentation
```bash
# Function: check_network_connectivity
# Description: Tests network connectivity to specified hosts
# Parameters:
#   $1 - Target IP address
#   $2 - Port number (optional, default: 80)
# Returns:
#   0 - Success
#   1 - Connection failed
# Example:
#   check_network_connectivity "192.168.1.1" "443"
check_network_connectivity() {
    local target_ip="$1"
    local port="${2:-80}"
    # Implementation...
}
```

#### Configuration Documentation
```yaml
# Network Configuration
network:
  # Primary network bridge for LAN connectivity
  wan_bridge: "vmbr0"
  
  # Isolated bridge for honeypot network
  # SECURITY: This bridge should have no physical connections
  lan_bridge: "vmbr1"
  
  # Honeypot network range (RFC 1918 private range)
  honeypot_network: "10.0.100.0/24"
```

## Testing Requirements

### 🧪 Test Categories

#### Unit Tests
- Individual script functions
- Configuration validation
- Input sanitization

#### Integration Tests
- VM deployment process
- Network connectivity
- Service interactions

#### Security Tests
- Network isolation verification
- Access control validation
- Attack simulation

#### Performance Tests
- Resource utilization
- Response times
- Scalability limits

### Test Environment Setup

```bash
# Create test configuration
cp config/environment.conf.example config/test.conf
# Edit test.conf with test-specific values

# Run connectivity tests
./scripts/testing/connectivity-test.sh

# Run attack simulation
./scripts/testing/attack-simulation.sh

# Verify security hardening
./scripts/security/security-audit.sh
```

### Test Documentation

Document all tests with:
- **Purpose**: What the test validates
- **Prerequisites**: Required setup
- **Procedure**: Step-by-step instructions
- **Expected Results**: What should happen
- **Troubleshooting**: Common issues and solutions

## Pull Request Process

### 📋 PR Checklist

- [ ] **Code follows style guidelines**
- [ ] **All tests pass**
- [ ] **Documentation updated**
- [ ] **Security review completed**
- [ ] **Breaking changes documented**
- [ ] **Commit messages are clear**

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Security improvement

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass
- [ ] Manual testing completed

## Security Considerations
- [ ] No sensitive information exposed
- [ ] Access controls maintained
- [ ] Network isolation preserved
- [ ] Input validation implemented

## Documentation
- [ ] README updated
- [ ] Code documented
- [ ] Configuration documented
- [ ] Troubleshooting guide updated

## Additional Notes
Any additional information or context
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests
2. **Security Review**: Security implications assessed
3. **Code Review**: Maintainers review code quality
4. **Testing**: Changes tested in lab environment
5. **Documentation Review**: Documentation completeness checked
6. **Approval**: Approved by project maintainers
7. **Merge**: Changes merged to main branch

## Recognition

Contributors will be recognized in:
- **README.md**: Contributors section
- **Release Notes**: Major contributions highlighted
- **Documentation**: Author attribution where appropriate

## Getting Help

### 💬 Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Issues**: Use private security reporting

### 📖 Resources

- **Project Documentation**: `/docs` directory
- **T-Pot Documentation**: [Official T-Pot Docs](https://github.com/telekom-security/tpotce)
- **OPNsense Documentation**: [OPNsense Docs](https://docs.opnsense.org/)
- **Proxmox Documentation**: [Proxmox VE Docs](https://pve.proxmox.com/pve-docs/)

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

**Thank you for contributing to the T-Pot Honeypot Infrastructure project! 🙏**

Your contributions help make cybersecurity research and education more accessible to everyone.