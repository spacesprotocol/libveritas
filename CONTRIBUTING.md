# Contributing to libveritas

Everyone is welcome to contribute towards development in the form of peer review, testing, and patches. This document explains the practical process and guidelines.

## Getting started

Reviewing and testing is highly valued and the most effective way to contribute as a new contributor. It also teaches you much more about the code and process than opening pull requests.

### Good First Issue Label

The purpose of the good-first-issue label is to highlight issues suitable for new contributors without a deep understanding of the codebase.

You do not need to request permission to start working on an issue. However, it's helpful to leave a comment if you are planning to work on one — it helps other contributors track which issues are actively being addressed and is also a good way to request assistance.

## Communication channels

You can join the [Spaces telegram](https://t.me/spacesprotocol).

Discussion about codebase improvements happens in GitHub issues and pull requests.

## Contributor workflow

The codebase is maintained using the "contributor workflow" where everyone contributes patch proposals using pull requests.

To contribute a patch:

1. Fork the repository (only the first time)
2. Create a topic branch
3. Commit patches using [conventional commits](https://www.conventionalcommits.org/) — this is enforced by CI and drives the changelog and release versioning. Examples: `feat: add lookup helper`, `fix(builder): handle empty record sets`, `docs: clarify SIG record semantics`.

## Squashing commits

If your pull request contains fixup commits or too fine-grained commits, squash them before review. See [how to write good commit messages](https://cbea.ms/git-commit/).

## Pull request philosophy

Keep patchsets focused: a PR should add a feature, fix a bug, or refactor code — not a mixture. Avoid super pull requests that try to do too much.

## Releases

Releases are automated via [release-plz](https://release-plz.dev/). When commits land on `main`, a release PR is opened automatically with version bumps and changelog entries derived from your conventional commits. Merging that PR tags the release and publishes to crates.io.

## Copyright

By contributing to this repository, you agree to license your work under the Apache-2.0 license. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.