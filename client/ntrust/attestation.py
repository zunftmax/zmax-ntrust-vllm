"""Mandatory Rust-backed hardware attestation; parsing is never admission."""
import http.client
from pathlib import Path

from . import _attestation_transport as transport
from .exceptions import AttestationError, APIConnectionError


class AttestationVerifier:
    """Verify with an installed trusted Rust binary and independent policy."""

    def __init__(self, expected_value_x: str | None = None,
                 expected_measurement: str | None = None,
                 gpu_policy: str | Path | None = None, cpu_only: bool = False,
                 uq_binary: str | Path | None = None, cafile: str | None = None,
                 timeout: float = 30.0, *, boot_policy: str | Path | None = None,
                 uki: str | Path | None = None,
                 google_boot_verifier: str | Path | None = None,
                 prior_stage_policy: str | Path | None = None,
                 platform: str | None = None, cpu_collateral: str | Path | None = None,
                 cpu_tcb_policy: str | Path | None = None,
                 azure_policy: str | Path | None = None,
                 nitrotpm_policy: str | Path | None = None):
        self.expected_value_x = expected_value_x
        self.expected_measurement = expected_measurement
        self.gpu_policy = Path(gpu_policy) if gpu_policy is not None else None
        self.cpu_only = cpu_only
        self.uq_binary = Path(uq_binary) if uq_binary is not None else Path("/usr/local/bin/uq")
        self.cafile = cafile
        self.timeout = timeout
        self.boot_policy = Path(boot_policy) if boot_policy is not None else None
        self.uki = Path(uki) if uki is not None else None
        self.google_boot_verifier = Path(google_boot_verifier) if google_boot_verifier is not None else None
        self.prior_stage_policy = Path(prior_stage_policy) if prior_stage_policy is not None else None
        self.azure_policy = Path(azure_policy) if azure_policy is not None else None
        self.nitrotpm_policy = Path(nitrotpm_policy) if nitrotpm_policy is not None else None
        self.platform = platform
        self.cpu_collateral = Path(cpu_collateral) if cpu_collateral is not None else None
        self.cpu_tcb_policy = Path(cpu_tcb_policy) if cpu_tcb_policy is not None else None

    def verify(self, base_url: str) -> dict:
        """Reject absent policy/binary before connecting; never fall back to receipt fields."""
        try:
            return transport.fetch_and_verify(base_url,
                expected_value_x=self.expected_value_x, expected_measurement=self.expected_measurement,
                gpu_policy=self.gpu_policy, cpu_only=self.cpu_only, uq_binary=self.uq_binary,
                cafile=self.cafile, boot_policy=self.boot_policy, uki=self.uki,
                google_boot_verifier=self.google_boot_verifier, prior_stage_policy=self.prior_stage_policy,
                platform=self.platform, cpu_collateral=self.cpu_collateral,
                cpu_tcb_policy=self.cpu_tcb_policy, azure_policy=self.azure_policy,
                nitrotpm_policy=self.nitrotpm_policy, connection_timeout=self.timeout)
        except (OSError, http.client.HTTPException) as error:
            raise APIConnectionError(f"Attestation transport failed: {error}") from error
        except (ValueError, RuntimeError) as error:
            raise AttestationError(f"Attestation verification failed: {error}") from error
