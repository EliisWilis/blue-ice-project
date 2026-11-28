# Provider setup examples

These examples show how to connect a custom service or gateway that implements the OpenAI Chat Completions API and uses Bearer authentication. Blue Ice is not limited to its built-in provider list, but a provider using a different native protocol needs a dedicated adapter.

## Run the offline demonstration

To try the local authentication, model-list, and chat routes without an AI account, install the project and run the synthetic demonstration from the repository root:

```sh
python -m pip install .
python examples/offline_demo.py
```

The demo injects a fake provider client and uses temporary synthetic credentials and responses. It does not make an external network call or contact a real model provider. See [`offline_demo.py`](offline_demo.py) for the complete implementation.

## Register a custom provider

Replace the example host and model ID with values from a provider you trust. The `--url` value must be the HTTPS Chat Completions endpoint. `--models-url` is optional when the provider exposes the conventional `/models` route under the same API prefix. Blue Ice sends the upstream API key to both configured endpoints, so an explicit models URL must belong to the same trusted provider.

```sh
blue-ice provider add my-gateway \
  --url https://api.example.com/v1/chat/completions \
  --models-url https://api.example.com/v1/models \
  --model model-id-from-your-provider
```

The provider URL is saved in the private Blue Ice policy file. The API key is not accepted as a command-line argument and is not written to YAML. Set it in the same shell used to run the service:

```sh
read -r -s -p "Provider API key: " AEGIS_CUSTOM_MY_GATEWAY_API_KEY
printf '\n'
export AEGIS_CUSTOM_MY_GATEWAY_API_KEY
blue-ice start
```

Alternatively, run `blue-ice provider add ... --keyring` to enter the key with hidden input and store it in the configured OS keyring. Use this only when that keyring has a secure, working backend.

## Inspect the upstream model catalog

With the proxy running, list the model IDs exposed by the selected upstream:

```sh
blue-ice-node models
```

Clients that query `GET /v1/models` can use this catalog. Other clients may require you to copy a model ID into their own configuration. Model availability does not guarantee support for tools, streaming, or every API feature.

## Keep the two keys separate

- `AEGIS_CUSTOM_MY_GATEWAY_API_KEY` is the upstream provider key. It belongs only in the Blue Ice service environment or OS keyring.
- `~/.aegis/local-token` is the local gateway token. It belongs in the coding agent's secret store or process environment.

Do not put either credential in this directory, a repository file, shell history, a screenshot, an issue, or a log. Do not use a custom endpoint unless you control or trust its operator; the proxy sends request content that remains after its configured checks to that endpoint.
