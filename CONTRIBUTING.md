# Contributing to PowerShell for Azure Intune Management

Thank you for your interest in contributing to the PowerShell for Azure Intune Management project! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and professional environment for all contributors.

## How to Contribute

### Reporting Issues

Before creating an issue, please:
1. Check if the issue has already been reported
2. Provide clear and detailed information about the problem
3. Include PowerShell version, Azure module versions, and Intune module versions
4. Provide steps to reproduce the issue

### Suggesting Enhancements

We welcome suggestions for improvements! Please:
1. Check if the enhancement has already been suggested
2. Provide a clear description of the proposed feature
3. Explain why this enhancement would be useful
4. Consider the impact on existing functionality

### Pull Requests

1. **Fork the repository** and create your feature branch from `main`
2. **Write clear, descriptive commit messages**
3. **Test your changes** thoroughly
4. **Update documentation** as needed
5. **Follow PowerShell best practices**
6. **Ensure your code is properly commented**

## Development Guidelines

### PowerShell Standards
- Use approved PowerShell verbs
- Include comprehensive help documentation
- Implement proper error handling
- Use meaningful variable names
- Follow PowerShell formatting conventions

### Code Style
- Use 4-space indentation
- Keep lines under 120 characters when possible
- Use consistent naming conventions
- Add comments for complex logic

### Testing
- Test with different Azure and Intune configurations
- Verify functionality with various user permissions
- Test error handling scenarios
- Ensure scripts work with different tenant configurations

## Development Setup

### Prerequisites
- PowerShell 5.1 or later
- Azure PowerShell module
- Microsoft.Graph.Intune module
- Appropriate Azure and Intune administrative permissions

### Local Development
1. Fork and clone the repository
2. Set up Azure authentication
3. Configure Intune access
4. Test your changes thoroughly

## Script Categories

### Azure Authentication
Scripts for secure Azure connection and authentication

### Intune Management
Scripts for device enrollment, policy deployment, and compliance

### Azure Visualizations
Scripts for reporting and dashboard creation

### Infrastructure Mapping
Scripts for network and resource discovery

### Windows Image Creation
Scripts for automated image preparation and deployment

## Submission Guidelines

### Commit Messages
Use clear, descriptive commit messages:
```
Add script for bulk device enrollment

- Implement CSV-based device enrollment
- Add error handling for duplicate devices
- Update documentation with usage examples
```

### Pull Request Process
1. Update documentation if needed
2. Ensure code follows style guidelines
3. Test thoroughly before submitting
4. Provide clear description of changes

## Recognition

Contributors will be acknowledged in the project documentation and release notes.

## Questions?

If you have questions about contributing, please:
- Open an issue with the "question" label
- Contact Wesley Ellis at wes@wesellis.com

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to PowerShell for Azure Intune Management!