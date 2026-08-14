name: Pull request
description: Submit changes to Claude Sonar
title: ""
labels: []
body:
  - type: textarea
    id: summary
    attributes:
      label: Summary
      description: What does this change do and why?
    validations:
      required: true
  - type: textarea
    id: tests
    attributes:
      label: Tests
      description: What tests were added/updated, and what was the result?
      placeholder: |
        - pytest tests/ — 44 passed
    validations:
      required: true
  - type: checkboxes
    id: checks
    attributes:
      label: Checklist
      options:
        - label: Tests pass locally (pytest tests/)
        - label: No secrets or local identifiers added
        - label: CHANGELOG.md updated if behavior changed
        - label: Stays within project boundary (read-only audit, no spoofing, no ban guarantee)
          required: true
