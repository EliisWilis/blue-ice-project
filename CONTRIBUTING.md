# Contributing to Blue Ice Project

Thank you for considering a contribution. Blue Ice Project is alpha software, so clear scope, honest compatibility claims, and security-minded tests matter more than adding a large number of features quickly.

## Before you start

- Python 3.12 or newer is required for the proxy and tests.
- Node.js 20 or newer is required only when changing the TypeScript terminal client.
- Read the [README](README.md), [security review](docs/security-review.md), and relevant protocol notes before changing request routing.
- For a new provider integration, identify the exact API protocol, authentication header, model-list route, streaming behavior, and tool-call format. Do not claim native-protocol compatibility based only on an OpenAI-compatible base URL.

## Fork and set up a local checkout

1. Fork `EliisWilis/blu-ice-project` on GitHub.
2. Clone your fork and enter the project directory:

   ```sh
   git clone https://github.com/YOUR_GITHUB_NAME/blu-ice-project.git
   cd blu-ice-project
   ```

3. Create an isolated Python environment and install development dependencies:

   ```sh
   python -m venv .venv
   . .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -e '.[dev]'
   ```

4. If you are changing the TypeScript client, install and build it:

   ```sh
   cd cli-node
   npm ci
   npm run build
   cd ..
   ```

## Make a focused change

Create a short-lived branch from `main`, for example:

```sh
git switch -c feat/provider-model-discovery
```

Keep each pull request focused. Add tests for new behavior, failure paths, input validation, and secret handling. Never commit provider keys, local tokens, private policy files, audit logs, or real user prompts. Use fake credentials and fake HTTP clients in tests.

## Run checks

Run the Python suite and static checks before opening a pull request:

```sh
pytest
ruff check src tests
ruff format --check src tests
python -m compileall -q src tests
```

You can also run the no-network demonstration, which exercises local auth, model discovery, and a chat completion using a fake provider client:

```sh
python examples/offline_demo.py
```

The demo uses temporary synthetic credentials and does not contact an AI provider. Keep tests deterministic in the same way; never use a real API key or prompt in a test, demo recording, issue, or pull request.

For TypeScript changes, also run:

```sh
cd cli-node
npm ci
npm run build
```

## Open a pull request

1. Push your branch to your fork.
2. Open a pull request against `EliisWilis/blu-ice-project:main`.
3. Describe the problem, the change, the test evidence, and any behavior or security limitations.
4. For provider or agent support, include the official protocol documentation and identify which features were actually tested. Clearly label unverified behavior.
5. Do not include credentials, prompts, private source code, or unpublished vulnerability details in the issue or pull request. For security-sensitive reports, contact the maintainers privately instead of opening a public issue.

The project is licensed under the MIT License. By submitting a contribution, you agree that it may be distributed under that license.
