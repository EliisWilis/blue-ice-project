# Blue Ice Project TypeScript CLI

This package is an optional plain-text TypeScript front end for the Python service. It uses no decorative symbols or terminal graphics.

From this directory, install dependencies and compile the client:

```sh
npm ci
npm run build
```

Install the Python package first from the repository root with `python -m pip install .`. Then run `node dist/index.js help`, or link the Node executable with `npm link` and run `blue-ice-node help`. The `blue-ice-node` name is intentional: the Python service command remains `blue-ice`, which the Node client invokes for delegated commands.

The `models` command reads the private local bearer token from `~/.aegis/local-token` or `BLUE_ICE_TOKEN_FILE`, verifies restrictive file permissions, and connects only to `127.0.0.1`. Other commands delegate to the Python CLI. The Node client does not read or handle provider API keys.
