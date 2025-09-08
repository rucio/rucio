# Pull Request Template Selection

**Choose the appropriate template for your change:**

- **🐛 Bug Fix**: [Use Bug Fix Template](./pull_request_templates/bugfix.md)
- **✨ New Feature**: [Use Feature Template](./pull_request_templates/feature.md)  
- **⚡ Enhancement**: [Use Enhancement Template](./pull_request_templates/enhancement.md)
- **🚨 Hotfix**: [Use Hotfix Template](./pull_request_templates/hotfix.md)

---

## Or use this general template:

### Basic Requirements
- [ ] Issue exists: #___
- [ ] Branch naming: `patch-[issue]-[desc]` OR `feature-[issue]-[desc]`
- [ ] Title format: `<component>: <message> #<issue>`

### Code & Testing
- [ ] Flake8/Pylint compliant
- [ ] Tests written (if new feature)
- [ ] CI passing
- [ ] No breaking changes

### Type of Change
- [ ] Patch (bug fix)
- [ ] Feature (new functionality)

---

## Description
**Related Issue:** #___

**Change Summary:**
<!-- Brief description -->

**Testing Done:**
<!-- How you tested -->

---

*By submitting this PR, I confirm I have followed the [Contributing Guide](https://rucio.cern.ch/documentation/contributing/).*