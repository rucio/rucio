const rucioComponents = [
  'Core',
  'Clients', 
  'Database',
  'Authentication',
  'Authorisation',
  'Consistency',
  'Deletion',
  'Metadata',
  'Monitoring',
  'Traces',
  'Messaging',
  'Policies',
  'Docker',
  'Kubernetes',
  'Documentation',
  'DIRAC',
  'MultiVO',
  'Lifetime',
  'Overview',
  'Dependencies',
  'GitHubActions',
  'Opendata',
  'CI'
];

const rucioTypes = [
  'feat',     // New feature
  'fix',      // Bug fix
  'docs',     // Documentation only changes
  'style',    // Changes that do not affect the meaning of the code
  'refactor', // Code change that neither fixes a bug nor adds a feature
  'perf',     // Code change that improves performance
  'test',     // Adding missing tests or correcting existing tests
  'build',    // Changes that affect the build system or external dependencies
  'ci',       // Changes to CI configuration files and scripts
  'chore',    // Other changes that don't modify src or test files
  'revert',   // Reverts a previous commit
  'patch'     // Small fixes or improvements
];

const issueNumberPlugin = {
  rules: {
    'issue-number-required': (parsed, _when, _value) => {
      const { header } = parsed;
      if (!header) return [false, 'Header is required'];
      
      // Check if header ends with #<number>
      const issuePattern = /#\d+$/;
      if (!issuePattern.test(header)) {
        return [false, 'Commit message must end with issue number format: #<number>'];
      }
      
      return [true];
    }
  }
};

module.exports = {
  extends: ['@commitlint/config-conventional'],
  plugins: [issueNumberPlugin],
  rules: {
    'type-enum': [2, 'always', rucioTypes], // Require a valid type
    'scope-enum': [2, 'always', rucioComponents], // Require a valid scope
    'scope-case': [0], // Disable case checking since we use custom scopes
    'scope-empty': [2, 'never'], // Scope is required
    'subject-case': [0], // Disable subject case checking
    'subject-empty': [2, 'never'], // Subject is required
    'subject-full-stop': [2, 'never', '.'], // Subject should not end with a period
    'header-max-length': [1, 'always', 100], // Warn about exceeding 100 characters
    'body-max-line-length': [0], // Disable body line length limit
    'body-leading-blank': [1, 'always'], // Body should start with a blank line
    'footer-leading-blank': [1, 'always'], // Footer should start with a blank line
    'issue-number-required': [2, 'always'] // Issue number is required  
  },
  helpUrl: 'https://rucio.cern.ch/documentation/contributing/'
};
