#ifndef SCANNER_H
#define SCANNER_H

/*
 * scan_drives()
 *
 * Enumerates all physical storage devices visible to the OS and writes
 * a single JSON object to stdout:
 *
 *   {"type": "scan_result", "drives": ["<path> (<N> GiB)", ...]}
 *
 * On Windows : probes \\.\PhysicalDrive0 … \\.\PhysicalDrive31 via
 *              CreateFile + IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.
 * On Linux   : reads /sys/block for sd*, hd*, vd*, nvme* devices and
 *              derives sizes from the per-device "size" attribute.
 *
 * All diagnostic / error text is sent to stderr so stdout stays clean
 * for the Python JSON parser.
 */
void scan_drives(void);

#endif /* SCANNER_H */
