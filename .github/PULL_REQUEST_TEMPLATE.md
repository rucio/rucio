*By submitting this PR, I confirm I have followed the [Contributing Guide](https://rucio.cern.ch/documentation/contributing/).*

## Description
<!-- Required. Summarise WHAT this PR changes. The WHY should already be
     covered by the linked issue and its discussion. A sufficiently detailed
     commit message may be reused here. If a checklist item below does not
     apply to this PR, briefly say why here. -->


## Checklist
<!-- Every box should be ticked before merge. Tick a box if the item is done
     OR does not apply to this PR (briefly say why in the description). -->

- [ ] This PR closes #____
      <!-- Every PR requires an issue; if none exists yet, please create one
           first. GitHub links the PR to the issue and closes it on merge.
           In the rare case the issue should remain open after the merge,
           write "Related to #____" here instead and briefly say why in the
           description. -->
- [ ] Tests cover the change, or no tests are needed (explain why in the description)
- [ ] Documentation is updated (link the docs PR here), or no documentation change is needed
- [ ] Database migrations are included, or the change touches no database schema
- [ ] This PR contains no breaking changes, or the breaking change is described
      in the description and the commit follows conventional commits

## Notes for contributors

- **Commit trailers**: Please also link the issue in the commit message (see
  the Contributing Guide): use `Closes: #____` on the commit that resolves
  the issue, and `Issue: #____` on intermediate commits or if the issue
  should remain open.
- **Reviewer**: After submitting, assign a reviewer if you know who is
  appropriate for the touched components; otherwise leave it empty and one
  will be assigned.
- **Stale PRs**: PRs with failing tests or an unresponsive author will be
  closed promptly.

## Additional notes for reviewer

*Note: This OPTIONAL section is only relevant for the REVIEWER, please leave it in the PR*

<details>
<summary>Reviewer template </summary>
Reviewers should copy&paste the code-block below and fill it out for APPROVED pull requests.
If the PR does not meet the standards the project sets out, the reasons should be WELL EXPLAINED in a CHANGE REQUEST (The answers below do not need to be answered in that case)

- **Confidence in review**: I am confident in my review concerning the components this PR touches: [*High 🟢, Medium 🟡 Low 🔴*]
- **Confidence in scope**: I am confident that this fits into the scope of the project and should be included: [*High 🟢, Medium 🟡, Low 🔴*]
  - For Medium and Low, explain in notes why this should be included
- **Quality**: The approach is sound, maintainable and addresses the issue in the best way: [*Agree 🟢*]
- **Security**: This PR does NOT require increased attention in terms of security (E.g. new dependencies): [*Agree 🟢, Disagree 🔴*]
  - If *Disagree* explain in notes.
- **Backwards compatibility**: This PR does NOT introduce backwards compatibility breaking changes: [*Agree 🟢, Disagree 🔴*]
  - If *Disagree* explain in notes
- **Testing**: This PR is well tested: [*Agree 🟢*]
- **Documentation**: Relevant documentation or comments are updated or not required: [*Agree 🟢*]



```
- **Confidence in review**: High 🟢 Medium 🟡 Low 🔴
- **Confidence in scope**: High 🟢 Medium 🟡 Low 🔴
- **Quality**: Agree 🟢
- **Security**: Agree 🟢 Disagree 🔴
- **Backwards compatibility**: Agree 🟢 Disagree 🔴
- **Testing**: Agree 🟢
- **Documentation**: Agree 🟢

# Notes for merger



```
</details>
