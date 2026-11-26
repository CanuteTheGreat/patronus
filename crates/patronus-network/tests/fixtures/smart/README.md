# smartctl JSON fixtures

Real captures (smartctl 7.3, QEMU 8.2 guest with an `ide-hd`, an `nvme` and a `virtio-blk` disk, see
`tools/vmtest/smart-capture.sh`): `scan`, `ata_healthy`, `nvme_healthy`, `virtio_nosmart`,
`test_start_short`, `test_start_refused`.

Crafted from those captures (or, for `scsi_sas`, from the documented schema of `smartctl --json`) because a
QEMU disk never fails: `ata_failing`, `ata_pending`, `nvme_worn`, `scsi_sas`, `scan_empty`.
