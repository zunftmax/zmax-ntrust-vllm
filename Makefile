.PHONY: image export check check-host sbom scan

check:
	python3 -m unittest discover -s tests -v
	shellcheck guest/gpu-ready guest/https-start guest/inference-ready guest/status image/*.sh tests/*.sh

check-host:
	test "$$(uname -s)" = Linux
	test "$$(uname -m)" = x86_64
	test -r /dev/kvm -a -w /dev/kvm

# Run on the Linux build machine. Packer and QEMU/KVM are existing build tools.
image: check-host build/image-key
	packer init image/ntrust.pkr.hcl
	packer build image/ntrust.pkr.hcl

build/image-key:
	mkdir -p build
	ssh-keygen -q -t ed25519 -N '' -f $@

export: check-host
	bash image/export.sh

sbom: check-host
	bash image/inventory.sh

scan: check-host
	bash image/scan.sh
