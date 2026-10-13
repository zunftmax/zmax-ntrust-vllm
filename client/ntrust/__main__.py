"""Command-line interface for the Ntrust Confidential Inference SDK."""
import argparse
import json
import sys

from .client import ConfidentialClient
from .exceptions import NtrustError



def add_attestation_options(parser, *, required):
    parser.add_argument("--value-x", required=required, help="Independent approved Value X (96 hex)")
    parser.add_argument("--measurement", required=required, help="Independent approved CPU measurement (96 hex)")
    selection = parser.add_mutually_exclusive_group(required=required)
    selection.add_argument("--gpu-policy", help="Local enrolled GPU inventory policy JSON")
    selection.add_argument("--cpu-only", action="store_true", help="Authenticate only the relay CPU, not origin hardware")
    parser.add_argument("--uq-bin", help="Installed trusted Rust uq executable at an absolute path")
    parser.add_argument("--boot-policy", help="Local measured-boot policy JSON")
    parser.add_argument("--uki", help="Local UKI image; requires --boot-policy")
    parser.add_argument("--google-boot-verifier", help="Local trusted helper executable; requires --boot-policy")
    parser.add_argument("--prior-stage-policy", help="Local prior-stage policy JSON")
    parser.add_argument("--platform", choices=("tdx", "sev-snp", "azure-snp-vtpm", "aws-snp-nitrotpm"))
    parser.add_argument("--cpu-collateral", help="Local authenticated CPU collateral JSON")
    parser.add_argument("--cpu-tcb-policy", help="Local independent CPU rollback policy JSON")
    parser.add_argument("--azure-policy", help="Independent Azure AK, VM, paravisor and PCR policy JSON")
    parser.add_argument("--nitrotpm-policy", help="Independent AWS NitroTPM PCR/freshness policy JSON")
    parser.add_argument("--cafile", help="Explicit trusted TLS CA bundle")


def attestation_options(args):
    return dict(expected_value_x=args.value_x, expected_measurement=args.measurement,
                gpu_policy=args.gpu_policy, cpu_only=args.cpu_only, uq_binary=args.uq_bin,
                boot_policy=args.boot_policy, uki=args.uki,
                google_boot_verifier=args.google_boot_verifier, prior_stage_policy=args.prior_stage_policy,
                platform=args.platform, cpu_collateral=args.cpu_collateral,
                cpu_tcb_policy=args.cpu_tcb_policy, azure_policy=args.azure_policy,
                nitrotpm_policy=args.nitrotpm_policy, cafile=args.cafile)

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
    add_attestation_options(chat_p, required=False)

    # Attest command
    attest_p = subparsers.add_parser("attest", help="Verify hardware attestation of remote endpoint")
    attest_p.add_argument("--endpoint", "-e", required=True, help="HTTPS base URL")
    add_attestation_options(attest_p, required=True)

    # Models command
    models_p = subparsers.add_parser("models", help="List served models")
    models_p.add_argument("--endpoint", "-e", required=True, help="HTTPS base URL")
    models_p.add_argument("--key", "-k", required=True, help="RAM-only bearer API key")

    args = parser.parse_args()

    try:
        if args.command == "chat":
            client = ConfidentialClient(base_url=args.endpoint, api_key=args.key, verify_attestation=args.attest, **attestation_options(args))
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
            client = ConfidentialClient(base_url=args.endpoint, **attestation_options(args))
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
