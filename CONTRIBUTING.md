# Contributing to vcdiff-python

## Contributing

### Initialising

vcdiff-python uses [Poetry](https://python-poetry.org/) for packaging and dependency management. Please refer to the [Poetry documentation](https://python-poetry.org/docs/#installation) for up to date instructions on how to install Poetry.

Perform the following operations after cloning the repository contents:

```shell
git submodule init
git submodule update
poetry install
```

The [`vcdiff-tests`](https://github.com/ably/vcdiff-tests) submodule holds the shared test cases used by all Ably VCDIFF decoder implementations, so the test suite cannot run without it.

### Running the test suite

```shell
poetry run pytest
```

### Updating the shared test suite

To pick up new test cases from [`vcdiff-tests`](https://github.com/ably/vcdiff-tests), move the submodule to the latest `main` and commit the new submodule reference:

```shell
git submodule update --remote submodules/vcdiff-tests
git add submodules/vcdiff-tests
```

## Release Process

Releases should always be made through a release pull request (PR), which needs to bump the version number and add to the [change log](CHANGELOG.md).

The release process must include the following steps:

1. Ensure that all work intended for this release has landed to `main`
2. Create a release branch named like `release/0.2.0`
3. Add a commit to bump the version number, updating [`pyproject.toml`](./pyproject.toml) and [`vcdiff_decoder/__init__.py`](./vcdiff_decoder/__init__.py)
4. Update the [CHANGELOG](./CHANGELOG.md): rename the "Unreleased" heading to the new version, linking it to the version tag and adding the release date, and make sure every change in the release is listed. Call out any breaking changes, including changes to internal modules that consumers may import directly, in a "Breaking changes" section
5. Commit this change: `git add CHANGELOG.md && git commit -m "Update change log."`
6. Push the release branch to GitHub
7. Create a release PR (ensure you include an SDK Team Engineering Lead and the SDK Team Product Manager as reviewers) and gain approvals for it, then merge that to `main`
8. Create a tag named like `v0.2.0` and push it to GitHub - e.g. `git tag v0.2.0 && git push origin v0.2.0`. The [Release Workflow](https://github.com/ably/vcdiff-python/actions/workflows/release.yml) checks that the tag matches the package version before publishing
9. Create the release on GitHub including populating the release notes
10. Go to the [Release Workflow](https://github.com/ably/vcdiff-python/actions/workflows/release.yml) and ask [ably/team-sdk](https://github.com/orgs/ably/teams/team-sdk) member to approve publishing to the PyPI registry
