# Blue Ice Project TypeScript CLI

This package is a plain-text Node.js front end for the Python service. It uses no decorative symbols or terminal graphics.

From this directory, run `npm install` and `npm run build`. After installing the Python project with `pip install ..`, use `node dist/index.js help` or install the package locally with `npm link` to get the `blue-ice` command.

The `models` command reads the private local bearer token from `~/.aegis/local-token` or `BLUE_ICE_TOKEN_FILE`, verifies restrictive file permissions, and connects only to `127.0.0.1`. Other commands delegate to the Python CLI. The Node client does not read or handle provider API keys.
