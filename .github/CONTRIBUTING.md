## Contributing to AFLTriage

AFLTriage is for the community and contributions are welcome.

## Submitting a Pull Request

1. Please read the [code of conduct](../CODE-OF-CONDUCT.md) and [license](../LICENSE). All code you contribute must be brand new and not previously covered by any other license.
1. Fork the repository on GitHub and clone your fork to your local machine.
1. Create a new branch based on `main`: `git checkout -b <my-branch-name> main`.
1. Make your changes, add tests, and make sure all tests still pass.
1. Commit your changes using the [DCO](http://developercertificate.org/). You can attest to the DCO by commiting with the **-s** or **--signoff** options to `git commit` or manually adding the "Signed-off-by: <NAME> <EMAIL>" to the commit message.
1. Push to your fork and submit a pull request from your branch to `main`.

Here are a few things you can do that will increase the likelihood your pull request will be accepted:

- Follow the existing codestyle where possible. Use rustfmt and optionally Clippy and/or rust-analyzer
- Write tests when applicable. Untested code is likely to break
- Make sure your PR is a singled focused commit OR contains multiple minimized commits
- Larger changes MUST reference an issue. It's best to discuss the approach *before* writing code. Otherwise there is a risk that the code will not meet the project standards. WIP PRs are acceptable, but should reference an accompanying issue.

## Contributions to Avoid

While contributions are welcome, some are unlikely to be accepted. Here is a non-exhaustive list:

* Changes that introduce a large maintenance burden. This includes features that cannot be automatically tested via continuous integration or project maintainers (e.g. exotic platforms, architectures, or debuggers)
* Changes that affect the usability of AFLTriage (e.g. new required command lines, run-time dependencies)
* Changes that require a significant rearchitecture of the project. Open an issue instead
