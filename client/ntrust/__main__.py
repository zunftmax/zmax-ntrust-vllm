"""Command-line interface for the Ntrust Confidential Inference SDK."""
import argparse
import json
import sys

from .client import ConfidentialClient
from .exceptions import NtrustError


def main():
    parser = argparse.ArgumentParser(prog="ntrust", description="Ntrust Confidential AI CLI & SDK")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Chat command
    chat_p = subparsers.add_parser("chat", help="Send chat message to confidential inference VM")
    chat_p.add_argument("--endpoint", "-e", required=True, help="HTTPS base URL (e.g. https://inference.example.com)")
    chat_p.add_argument("--key", "-k", required=True, help="RAM-only bearer API key")
    chat_p.add_argument("--model", "-m", default="default", help="Model name or alias")
    chat_p.add_argument("--stream", "-s", action="store_true", help="Stream response using SSE")
    chat_p.add_argument("--attest", action="store_true", help="Verify hardware attestation before chatting")
    chat_p.add_argument("prompt", help="User prompt to send")

    # Attest command
    attest_p = subparsers.add_parser("attest", help="Verify hardware attestation of remote endpoint")
    attest_p.add_argument("--endpoint", "-e", required=True, help="HTTPS base URL")
    attest_p.add_argument("--value-x", help="Expected Value X hash")
    attest_p.add_argument("--measurement", help="Expected CPU measurement hash")

    # Models command
    models_p = subparsers.add_parser("models", help="List served models")
    models_p.add_argument("--endpoint", "-e", required=True, help="HTTPS base URL")
    models_p.add_argument("--key", "-k", required=True, help="RAM-only bearer API key")

    args = parser.parse_args()

    try:
        if args.command == "chat":
            client = ConfidentialClient(base_url=args.endpoint, api_key=args.key, verify_attestation=args.attest)
            messages = [{"role": "user", "content": args.prompt}]
            if args.stream:
                for chunk in client.chat.completions.stream(model=args.model, messages=messages):
                    sys.stdout.write(chunk.delta_text)
                    sys.stdout.flush()
                sys.stdout.write("\n")
            else:
                resp = client.chat.completions.create(model=args.model, messages=messages)
                print(resp.text)

        elif args.command == "attest":
            client = ConfidentialClient(base_url=args.endpoint, expected_value_x=args.value_x, expected_measurement=args.measurement)
            verdict = client.verify_attestation()
            print(json.dumps(verdict, indent=2))

        elif args.command == "models":
            client = ConfidentialClient(base_url=args.endpoint, api_key=args.key)
            models = client.models.list()
            print(json.dumps(models, indent=2))

    except NtrustError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
