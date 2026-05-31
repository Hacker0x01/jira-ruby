# Changelog

## 3.0.0

### Breaking Changes

- **Minimum Ruby version raised to 2.7.0** (was 1.9.3).
- **Removed `atlassian-jwt` dependency.** JWT canonicalization and claim building are now handled internally by `JIRA::Jwt`. If you were relying on `atlassian-jwt` being pulled in transitively, you'll need to add it to your own Gemfile.
- **Replaced `atlassian-jwt` with `jwt` gem** (`>= 2.1`) as a runtime dependency.

### Added

- `JIRA::Jwt` module — internal helper for building JWT claims and computing `qsh` (query string hash) per the Atlassian Connect spec.
- `JIRA::JwtHeaderClient` — authenticates via `Authorization: JWT ...` header (for Atlassian Connect apps that require header-based JWT).
- `ostruct` added as an explicit runtime dependency (required by Ruby 3.5+).

### Changed

- `JIRA::JwtClient` now uses `JIRA::Jwt.build_claims` instead of `AtlassianJwt::Token`.
- Development dependency versions updated (`guard`, `guard-rspec`, `rake`, `rspec`, `webmock`).
