#!/bin/sh
set -eu
# Run via the final build SSH session. No builder identity goes into the image.
cloud-init clean --logs --machine-id --seed
rm -f /root/.ssh/authorized_keys /etc/ssh/ssh_host_* /root/.bash_history
# Stop first so shutdown cannot save a new entropy seed into the shared image.
systemctl stop systemd-random-seed.service
rm -f /var/lib/systemd/random-seed
rm -f /etc/netplan/50-cloud-init.yaml
printf 'PermitRootLogin no\nPasswordAuthentication no\n' > /etc/ssh/sshd_config.d/00-ntrust.conf
rm -rf /tmp/ntrust /tmp/packer* /var/tmp/*
find /var/log -type f -exec truncate -s 0 {} +
fstrim -av || true
sync
poweroff
