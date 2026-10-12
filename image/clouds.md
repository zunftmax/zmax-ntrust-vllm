# Import the same guest into Azure and GCP

These are launch recipes for the shared image. They have not been exercised
against either cloud yet. NVIDIA CC requires both the correct instance and a
compatible guest/driver; converting a disk format alone does not establish that.

**Use synthetic inputs during bring-up.** The revised image removes the Azure Linux
provisioning daemon and optional reporting. Cloud-init performs initial setup.
The [review](../docs/SECURITY-REVIEW.md) records implemented fixes and the remaining
cloud hardware acceptance tests.

## Prerequisites and deployment contract

| Input | Required value / check |
| --- | --- |
| Hardware | Azure `Standard_NCC40ads_H100_v5` (40 vCPUs, one H100) or GCP `a3-highgpu-1g` with TDX. A CPU-only CVM cannot test inference |
| Quota and capacity | Azure NCC family and total regional vCPU quota sufficient for 40 cores, plus actual NCC capacity. GCP confidential A3 availability and the appropriate H100 Spot quota. Approval is not a capacity reservation |
| Account | Explicit Azure subscription or GCP project with image/storage/network/VM permissions and billing |
| Network | Public IPv4/DNS hostname, TCP 443 to guest, SSH only from operator CIDR, outbound DNS/time/ACME/NVIDIA verification and public model download |
| TLS routing | Direct VM IP or layer-4 pass-through that preserves TLS/ALPN. No cloud TLS termination, CDN TLS termination or WAF decryption |
| Model | Example public model for smoke testing; adequate root-disk space for a replacement Safetensors model directory. Do not pass private weights or tokens in cloud metadata |
| Operator | SSH key held outside cloud metadata; only its public half goes in cloud-init. Trust this administration path for the initial API-key retrieval |
| Tooling | Current `az` or `gcloud` supporting the documented flags. Record CLI versions and exact launch configuration with your evidence |

Commands below are shell examples, not actions already performed. Use a dedicated
resource group/VPC and unique image/VM names; do not overwrite a workload in use.
Prefer a reserved/static IP so DNS continues to reach the intended VM after a
stop/start. Review CAA records if issuance is restricted. Remove any stale AAAA
record: the current guest listener/recipe is IPv4-only.

Run `make check image export` on the Linux build machine first. Copy
`guest/cloud-init.example.yaml` to `cloud-init.yaml` and replace the public
hostname, email and SSH public key. The default public model is for bring-up.

From the repository root on the Linux builder, verify the existing artifacts:

```sh
sha256sum --check dist/SHA256SUMS
qemu-img check dist/qemu/ntrust.qcow2
qemu-img info -f vpc dist/ntrust-azure.vhd
cp guest/cloud-init.example.yaml cloud-init.yaml
```

Edit `cloud-init.yaml` before uploading it. It must not contain the placeholder
SSH key, `inference.example.com` or `admin@example.com`. Keep its staging CA
setting for initial DNS/port/restart tests. The operator's cloud-init `runcmd`
downloads, verifies and installs the public model before requesting application
startup. Provider metadata is not a confidential secret channel.

## Azure: SEV-SNP + one H100

Use an existing resource group, private storage account and container in a region
with NCC capacity. Set `RG`, `REGION`, `STORAGE`, `CONTAINER`, `GALLERY`,
`VERSION` (for example `0.1.0`) and `SSH_PUBLIC_KEY` (a local public-key path).
The commands create billable image storage and, in the second block, a GPU VM.

Select the intended subscription and inspect quota without changing resources:

```sh
az account set --subscription "$SUBSCRIPTION_ID"
az account show --query '{name:name,id:id}' -o table
az vm list-usage --location "$REGION" -o table
az vm list-skus --location "$REGION" --resource-type virtualMachines \
  --size Standard_NCC40ads_H100_v5 --all -o json
```

Ask Azure for **one confidential NCC40ads H100 v5 VM**, specifying subscription,
region and 40 vCPUs of family quota, and ask about capacity as well. Ordinary NC,
ND or DC CPU quota is not proof of this SKU's availability. To prepare a new
dedicated resource group and private image container when needed:

```sh
az group create --name "$RG" --location "$REGION"
az storage account create --resource-group "$RG" --name "$STORAGE" \
  --location "$REGION" --sku Standard_LRS --kind StorageV2 \
  --allow-blob-public-access false
az storage container create --auth-mode login --account-name "$STORAGE" \
  --name "$CONTAINER" --public-access off
```

The operator needs Storage Blob Data Contributor for login-based upload. Role
assignment propagation can take time. Gallery image versions must be unique.

```sh
az storage blob upload --auth-mode login --account-name "$STORAGE" \
  --container-name "$CONTAINER" --name ntrust.vhd --type page \
  --file dist/ntrust-azure.vhd
az sig create --resource-group "$RG" --gallery-name "$GALLERY" --location "$REGION"
az sig image-definition create --resource-group "$RG" --gallery-name "$GALLERY" \
  --gallery-image-definition ntrust --publisher ntrust --offer confidential-inference \
  --sku ubuntu-2404 --os-type Linux --os-state Generalized --hyper-v-generation V2 \
  --features SecurityType=ConfidentialVMSupported
storage_id=$(az storage account show --resource-group "$RG" --name "$STORAGE" --query id -o tsv)
az sig image-version create --resource-group "$RG" --gallery-name "$GALLERY" \
  --gallery-image-definition ntrust --gallery-image-version "$VERSION" \
  --os-vhd-storage-account "$storage_id" \
  --os-vhd-uri "https://$STORAGE.blob.core.windows.net/$CONTAINER/ntrust.vhd"
image_id=$(az sig image-version show --resource-group "$RG" --gallery-name "$GALLERY" \
  --gallery-image-definition ntrust --gallery-image-version "$VERSION" --query id -o tsv)
```

```sh
az vm create --resource-group "$RG" --name ntrust --location "$REGION" \
  --image "$image_id" --size Standard_NCC40ads_H100_v5 \
  --security-type ConfidentialVM --enable-secure-boot true --enable-vtpm true \
  --os-disk-security-encryption-type VMGuestStateOnly --public-ip-sku Standard \
  --admin-username operator --ssh-key-values "$SSH_PUBLIC_KEY" \
  --custom-data cloud-init.yaml --enable-agent false --nsg-rule NONE
az vm open-port --resource-group "$RG" --name ntrust --port 443 --priority 1000
```

The Azure Linux provisioning daemon (`walinuxagent`) is absent. The
`--enable-agent false` flag tells Azure not to wait for extension processing.
Cloud-init still handles networking, the operator account and the public model
download. This follows [Microsoft’s agentless-image deployment instructions](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disable-provisioning).
There is no AI agent, tool runner or remote command extension in this guest.

Add SSH ingress restricted to your operator address using your network policy.
No open SSH rule is created above. Point the domain at this VM's public IP.

```sh
az vm show --resource-group "$RG" --name ntrust \
  --query '{size:hardwareProfile.vmSize,security:securityProfile}' -o json
az vm show -d --resource-group "$RG" --name ntrust --query publicIps -o tsv
```

Add an NSG TCP 22 rule limited to `OPERATOR_CIDR` in the portal or your existing
network configuration. Check subnet as well as NIC NSGs. A successful control-plane
`ConfidentialVM` field still does not prove GPU CC or an approved guest image.
`VMGuestStateOnly` is the supported initial custom-image path; the root disk is
not guest-encrypted. TLS private keys remain in `/run` inside the guest.

Microsoft documents customized confidential Ubuntu images with the Azure kernel.
The common image currently attempts Ubuntu's generic kernel with Hyper-V/SNP
support and signed NVIDIA modules. **That combination still needs an actual NCC
boot.** If it fails, the observed kernel/driver constraint will determine the
smallest necessary adaptation; do not silently claim the common image works.

## GCP: Intel TDX + one H100

Use an existing project, bucket and VPC. Set `PROJECT`, `BUCKET`, `NETWORK`, and
`ZONE` to a zone with confidential `a3-highgpu-1g` capacity and GPU Spot quota.
Use an image name such as `ntrust-0-1-0` for `IMAGE`.

```sh
gcloud config list
gcloud compute regions describe "$REGION" --project "$PROJECT" \
  --format='table(quotas.metric,quotas.limit,quotas.usage)'
gcloud compute machine-types describe a3-highgpu-1g --zone "$ZONE" --project "$PROJECT"
```

Use the region containing `ZONE`; obtain quota/capacity for the supported TDX
GPU combination. Select a VPC/subnet that has no inherited broad SSH rule. The
examples assume an existing private bucket and subnet suitable for the zone;
custom-mode VPCs may need an explicit `subnet=...` in the NIC flag.

```sh
gcloud storage cp dist/ntrust-gcp.tar.gz "gs://$BUCKET/$IMAGE.tar.gz"
gcloud compute images create "$IMAGE" --project "$PROJECT" \
  --source-uri "gs://$BUCKET/$IMAGE.tar.gz" \
  --guest-os-features UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE
gcloud compute firewall-rules create ntrust-https --project "$PROJECT" \
  --network "$NETWORK" --direction INGRESS --action ALLOW \
  --rules tcp:443 --source-ranges 0.0.0.0/0 --target-tags ntrust-https
gcloud compute instances create ntrust --project "$PROJECT" --zone "$ZONE" \
  --machine-type a3-highgpu-1g --confidential-compute-type TDX \
  --provisioning-model SPOT --maintenance-policy TERMINATE \
  --instance-termination-action STOP --no-restart-on-failure \
  --image "$IMAGE" --image-project "$PROJECT" --boot-disk-size 64GB \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --network-interface "network=$NETWORK,nic-type=GVNIC" --tags ntrust-https \
  --metadata-from-file user-data=cloud-init.yaml \
  --no-service-account --no-scopes
```

Add your restricted SSH ingress rule and point the domain at the VM's public IP.
The example uses an explicit cloud-init SSH user, without depending on a managed
OS Login service. Existing VPC rules remain the deployer's responsibility.

GCP's stock H100 walkthrough uses Ubuntu 22.04; its custom TDX image requirements
permit kernels >=6.6 with the relevant network/storage drivers. The shared image
uses Ubuntu 24.04 with signed HWE 7.0 and matching NVIDIA modules. **A custom-image H100 boot is still
required.** A3's Spot/flex-start scheduling limitations apply regardless of image.

## Validate the first boot

Connect using the supplied operator key and run these inside the guest. Keep
verification JSON in RAM; if exporting evidence, handle device identifiers as
operational metadata. Never collect real prompts for diagnostics.

```sh
sudo cloud-init status --wait
uname -r
systemd-detect-virt --cvm
cat /proc/swaps
nvidia-smi --query-gpu=uuid,name,driver_version --format=csv
nvidia-smi conf-compute -f
nvidia-smi conf-compute -grs
sudo systemctl status ntrust-gpu ntrust-inference ntrust-https --no-pager
sudo journalctl -u ntrust-gpu --no-pager
sudo test -s /run/ntrust-gpu/attestation.json
sudo test -s /run/ntrust-gpu/api-key
sudo ss -ltnp
```

Require `sev-snp` on Azure or `tdx` on GCP, no swap entry, exactly one GPU, CC-On,
successful native verification and ready state. Ports: guest HTTPS 443, engine
**127.0.0.1:8080**, plus the restricted SSH administration listener. Do not bypass
the GPU gate to make the endpoint appear healthy. `active` and an existing JSON
file are not substitutes for checking a successful verifier result and an actual
authenticated model request.

For staging, obtain the applicable test roots from [Let's Encrypt's official
staging page](https://letsencrypt.org/docs/staging-environment/) and use a dedicated
test CA bundle with curl `--cacert staging-roots.pem`. Never install staging roots
into a general trust store or use `--insecure` with credentials. The README's
synthetic request can be used with this per-command test trust bundle.

Once DNS, routing and staged issuance work, edit `/etc/ntrust/runtime.env` inside
the guest and remove `NTRUST_ACME_DIRECTORY`. Then:

```sh
sudo systemctl restart ntrust-https.service
```

That **full restart deliberately creates fresh ACME/TLS state** and requests a
production certificate. Wait for a successful normal TLS handshake, then use
the [authenticated example](../README.md#run) without a staging bundle. Verify:

1. Missing/incorrect bearer key is rejected; valid key returns the `model` alias.
2. Synthetic chat returns JSON and SSE, and client cancellation releases work.
3. Other paths/methods are rejected; port 8080 is unreachable from outside.
4. A staging full restart changes the TLS public key/certificate; reload has the
   separately documented retained-state behavior. Reboot changes the API key.
5. Losing GPU verification prevents serving; driver reset/loss does not leave
   a stale healthy endpoint. Verify application network denial and absence of
   payload/key writes using synthetic data and the actual cloud kernel.

Production repeated issuance has limits; use staging for lifecycle loops. CT
records certificate issuance, not approval of the running image. Current clients
still trust the provisioned guest/operator until remote attestation is added.

## Recovery and replacement

| Symptom | Check / action |
| --- | --- |
| Allocation denied | Separate quota denial from region capacity/Spot availability. Do not substitute an ordinary GPU VM and label it confidential |
| Boot or NVIDIA module failure | Inspect serial/boot evidence, Secure Boot signature, kernel/module compatibility and storage/network drivers. Preserve failure evidence before changing the shared image |
| GPU gate fails | Check clock, DNS, RIM/OCSP reachability, actual CVM type, GPU count and CC mode. After correcting a transient pre-ready failure, explicitly start GPU then inference/HTTPS again; do not ignore verifier failure |
| Driver/persistenced reset after use | Follow [NVIDIA/GCP recovery semantics](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-confidential-computing-mode-on-gpu); a VM reboot may be required. Do not reset a live GPU casually |
| Model absent / cloud-init fails | Inspect cloud-init's public bootstrap log. Rerun `/usr/local/lib/ntrust/fetch-model` as root; never promote an unchecked `.part` file. First-instance runcmd is not a retry on every boot |
| TLS issuance fails | Check DNS A/AAAA/CAA, correct hostname, TCP 443, ALPN pass-through, resolver/time and CA limits. HTTP/error logs are suppressed; avoid enabling payload-bearing logs |
| API 502 or no response | Check engine state/model load and memory. systemd process-active does not mean model-ready. Avoid a loop of full production HTTPS restarts while diagnosing |
| Rebooted VM rejects old key | Retrieve the new RAM-only key over trusted SSH. Update clients; do not persist the old key to avoid rotation |

Patch through a new reviewed build and new image version. Validate the replacement
with synthetic traffic before changing DNS; clients must receive its new API key.
Retain the previous immutable artifact/version for rollback, but do not restore
old TLS/API secrets. Stop/deallocate the test VM when finished; disks, public IPs,
gallery images and object storage can remain billable. Delete only resources
created for this deployment after recording their identifiers.

## Remote attestation — reserved next phase

The next phase is [customer verification](../docs/REMOTE-ATTESTATION.md): approved
image/configuration measurement, fresh CPU/GPU evidence bound to this TLS
connection, verifier policy and rejection tests. Neither the launch flag nor
the in-guest `nvattest` JSON currently supplies this customer-facing proof.

## Sources

- [Azure custom confidential images](https://learn.microsoft.com/en-us/azure/confidential-computing/how-to-create-custom-image-confidential-vm)
- [Azure ConfidentialVMSupported gallery images](https://learn.microsoft.com/en-us/azure/confidential-computing/create-confidential-vm-from-compute-gallery)
- [Azure confidential H100 launch configuration](https://github.com/Azure/az-cgpu-onboarding/blob/main/docs/Confidential-GPU-H100-VMI-Creation-CLI.md)
- [GCP custom confidential-image requirements](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-custom-confidential-vm-images)
- [GCP confidential GPU launch and driver setup](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance-with-gpu)
- [GCP manual disk import](https://docs.cloud.google.com/compute/docs/import/import-existing-image)

## Payload-free local diagnostics

Run `sudo ntrust-status` to see clock, driver, GPU gate, model and HTTPS process
states without printing application logs, requests, responses or keys. Inference
startup waits for the local model health endpoint before HTTPS starts. The clock
wait is limited to 90 seconds; GPU verification allows three attempts of at most
45 seconds each. After resolving DNS, time or vendor connectivity, run
`sudo systemctl restart ntrust-gpu ntrust-inference ntrust-https`. This full HTTPS
restart deliberately obtains a new key and certificate; use the staging CA during
repeated bring-up.
