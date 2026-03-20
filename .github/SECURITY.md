# Security Policy

Vulnerabilities in Rucio's source code should be reported through GitHub's
advisory process (see links in the detailed process below for each project)
to improve efficiency and visibility of handling advisories.
Reports can be made for any of the supported versions as listed in our
[release policy](https://rucio.cern.ch/documentation/started/releasepolicy), but
there should be exactly one report per vulnerability, which can affect multiples
versions (see the CVE guidelines). Therefore, if multiple vulnerabilities were
found please split your findings into multiple reports. Each report should
contain applicable CWE (Common Weakness Enumeration) numbers for the flaw.

If reporting via GitHub is not an option or if it is unclear whether an issue
is a vulnerability, please mail the security team at rucio-security@cern.ch.
A vulnerability is always exploitable, which means a valid
proof-of-concept (PoC) should be included in the report. Due to the complexity
of software in general we understand that this might be difficult. If you need
help, please do not hesitate to contact us via the email above.<br>
Until a security issue is formally announced, no information about it should be
made public until the end of the reporting process as detailed below.><br>
At this time, unfortunately, we do not offer a bug bounty program.

Please always disclose whether LLMs/AI is involved in the creation or finding
of a vulnerability. Due to past reports and experiences from other Open Source
projects, we want to be aware of possibly false or missing information in
reports and respond as quick as possible.

Please note that, for the reason of transparency, all reports may be published,
regardless of whether they are correct or not. This is in line with
[curl's](https://curl.se) security policy and reasoning.

## Vulnerability Reporting Process

1. Depending on the source code that contains the vulnerability, please open a
   vulnerability report in one of the following repositories:
   * Fallback: [rucio/rucio](https://github.com/rucio/rucio/security/advisories/new)
   * [rucio/containers](https://github.com/rucio/containers/security/advisories/new)
   * NextJS-based webui [rucio/webui](https://github.com/rucio/webui/security/advisories/new)
     * *Note: for the Python-based webui, please use [rucio/rucio](https://github.com/rucio/rucio/security/advisories/new))*
   * [rucio/jupyterlab-extension](https://github.com/rucio/jupyterlab-extension/security/advisories/new)
   * Mail to rucio-security@cern.ch
     * *Note: please specify whether and how you would like to be credited
       at the end of the process*
2. We will acknowledge the reception of your report. Please note that it can
   take several days to explore the findings in a report, depending on the
   availability of experts and the amount of workload. Please help us by
   providing detailed information, and a proof-of-concept (PoC) with the
   necessary steps to reproduce the vulnerability.
3. We may get back to you with questions, if we cannot reproduce the PoC,
   or the vulnerability cannot be discovered on our side. You are free to
   respond whenever you have time, but please note that after several weeks
   without answer we might close the report and publish it at our disclosure.
   However, it can be reopened to follow-up on it at any later date.
4. If we can reproduce the vulnerability, we will accept the report and put it
   in a draft state to refine it and fix the underlying issue. Please be
   patient until we are ready to publish releases that will fix the
   vulnerability. This time also includes the discussion with experts, possible
   hotfixes that are applied to production instances and testing the fixes.<br>
   It can therefore take *multiple weeks* before a report can be published.
   We will also request a CVE for the reported vulnerability through GitHub, if
   applicable.
5. The report will be published after fixes are released for all vulnerable
   supported Rucio releases as listed in the
   [release policy](https://rucio.cern.ch/documentation/started/releasepolicy).
