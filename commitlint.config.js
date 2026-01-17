// NOTE: Any changes to this list should also be applied to the [GitHub labels](https://github.com/rucio/rucio/issues/labels) and the [documentation](https://rucio.cern.ch/documentation/contributing/)
const rucioComponents = [
  'Auth', // Authentication & Authorisation
  'API', // REST & API
  'CI', // Continuous Integration
  'Clients',
  'Consistency', // Consistency checks
  'Core', // Core & Internals
  'Containerization', // Docker, Kubernetes, and container-related functionality
  'Database',
  'DatasetDeletion', // Dataset deletion
  'Deletion',
  'DIRAC',
  'Documentation',
  'LifetimeModel', // Life time model
  'Messaging',
  'Metadata',
  'Monitoring', // Monitoring, observability, and traces
  'MultiVO', // Multi VO
  'OpenData', // Open data
  'Policies',
  'Probes', // Probes & Alarms
  'Protocols',
  'Rebalancing',
  'Recovery',
  'Replicas',
  'Rules',
  'Subscriptions',
  'Testing',
  'Transfers',
  'WebUI'
];

const rucioTypes = [
  // Functional changes
  'feat',     // New feature
  'fix',      // Bug fix

  // Non-functional changes
  'docs',     // Documentation only changes
  'style',    // Changes that do not affect the meaning of the code
  'refactor', // Code change that neither fixes a bug nor adds a feature
  'test',     // Adding missing tests or correcting existing tests
  'ci',       // Changes to CI configuration files and scripts

  // Miscellaneous
  'revert',   // Reverts a previous commit
];

const gitTrailerPlugin = {
  rules: {
    'issue-trailer-required': (parsed, _when, _value) => {
      const { body, footer } = parsed;
      const fullMessage = [body, footer].filter(Boolean).join('\n');

      if (!fullMessage) {
        return [false, 'Commit message must include an issue-related Git trailer'];
      }

      // Issue-related trailer tokens (case-insensitive)
      const issueTrailerTokens = [
        'issue', 'closes'
      ];

      // Create pattern for issue-related trailers: "Token: Value" or "Token #Value"
      const tokenPattern = issueTrailerTokens.join('|');
      const issueTrailerPattern = new RegExp(`^(${tokenPattern})\\s*[:#]\\s*.+$`, 'im');

      if (!issueTrailerPattern.test(fullMessage)) {
        return [false, 'Commit message must include an issue-related Git trailer (e.g., "Issue: #123", "Closes: #456"). You can add a trailer using: git commit -m "message" --trailer "Issue: #123"'];
      }

      return [true];
    },
    'breaking-change-consistency': (parsed, _when, _value) => {
      const { header = '', body, footer } = parsed;
      const fullMessage = [body, footer].filter(Boolean).join('\n');

      const headerHasBang = /^[^:]+!\s*:/.test(header);
      const breakingChangeMatch = fullMessage.match(/^BREAKING CHANGE\s*:\s*(.*)$/im);
      const hasBreakingFooter = Boolean(breakingChangeMatch);

      if (headerHasBang && !hasBreakingFooter) {
        return [false, 'Commit messages that use "!" must include a BREAKING CHANGE footer.'];
      }

      if (!headerHasBang && hasBreakingFooter) {
        return [false, 'BREAKING CHANGE footer requires "!" in the commit header (e.g., "feat(API)!: ...").'];
      }

      if (hasBreakingFooter) {
        const description = breakingChangeMatch[1].trim();
        if (!description) {
          return [false, 'BREAKING CHANGE footer must include a description (e.g., "BREAKING CHANGE: describe the impact").'];
        }
      }

      return [true];
    }
  }
};

module.exports = {
  extends: ['@commitlint/config-conventional'],
  plugins: [gitTrailerPlugin],
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
    'issue-trailer-required': [2, 'always'], // Issue-related Git trailer is required
    'breaking-change-consistency': [2, 'always'] // Ensure BREAKING CHANGE footer usage is consistent
  },
  helpUrl: 'https://rucio.cern.ch/documentation/contributing/'
};
