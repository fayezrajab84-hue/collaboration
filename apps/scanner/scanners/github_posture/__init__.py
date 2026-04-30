# Phase 29 Slice C1 — GitHub posture scanner package wrapping Prowler
# for `--provider github`. 24 checks across organization (5) + repository
# (18) + githubactions (1) services.
from .scanner import GitHubPostureScanner

__all__ = ["GitHubPostureScanner"]
