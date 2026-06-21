/*
 * scanner.c — Cross-platform physical drive enumerator
 *
 * Outputs a single JSON object to stdout.  All diagnostics go to stderr.
 *
 * Compile (Windows / MinGW):
 *   gcc -O2 -Wall -o imager.exe main.c scanner.c
 *
 * Compile (Linux):
 *   gcc -O2 -Wall -o imager main.c scanner.c
 */

#include "scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Common helper ────────────────────────────────────────────────────────── */

/*
 * Writes a JSON-encoded string (with surrounding double-quotes) to stdout.
 * Escapes backslashes, double-quotes, and common control characters so that
 * Windows drive paths like \\.\PhysicalDrive0 are transmitted correctly.
 */
static void print_json_string(const char *s)
{
    putchar('"');
    for (; *s != '\0'; ++s) {
        switch (*s) {
        case '\\': fputs("\\\\", stdout); break;
        case '"':  fputs("\\\"", stdout); break;
        case '\n': fputs("\\n",  stdout); break;
        case '\r': fputs("\\r",  stdout); break;
        case '\t': fputs("\\t",  stdout); break;
        default:   putchar((unsigned char)*s); break;
        }
    }
    putchar('"');
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Windows Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifdef _WIN32

/*
 * Target Windows 7+ for DISK_GEOMETRY_EX / IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.
 * These defines must appear before any Windows headers.
 */
#ifndef WINVER
#  define WINVER       0x0601
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winioctl.h>  /* IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, DISK_GEOMETRY_EX */

/*
 * Maximum number of PhysicalDrive indices to probe.
 * Windows numbers drives consecutively but we scan all to handle hot-plug
 * gaps (e.g., after removing a drive that was PhysicalDrive1).
 */
#define MAX_DRIVES 32

void scan_drives(void)
{
    int   first = 1;
    int   i;

    fputs("{\"type\": \"scan_result\", \"drives\": [", stdout);

    for (i = 0; i < MAX_DRIVES; ++i) {
        char   path[48];
        HANDLE hDev;
        DISK_GEOMETRY_EX geo;
        DWORD  bytesRet = 0;

        /* Build the device path: \\.\PhysicalDriveN */
        snprintf(path, sizeof(path), "\\\\.\\PhysicalDrive%d", i);

        /*
         * Open with no read/write access — just enough to issue IOCTLs.
         * FILE_SHARE_READ|WRITE allows opening a drive that is in use.
         */
        hDev = CreateFileA(
            path,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hDev == INVALID_HANDLE_VALUE) {
            /*
             * Access denied on a drive we know exists is still a drive.
             * Report it with unknown size rather than skipping silently.
             */
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                char entry[64];
                snprintf(entry, sizeof(entry),
                         "\\\\.\\PhysicalDrive%d (access denied)", i);
                if (!first) fputs(", ", stdout);
                print_json_string(entry);
                first = 0;
            }
            /* ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND → drive does not exist */
            continue;
        }

        memset(&geo, 0, sizeof(geo));

        if (DeviceIoControl(
                hDev,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                NULL, 0,
                &geo, sizeof(geo),
                &bytesRet, NULL))
        {
            long long sizeBytes = (long long)geo.DiskSize.QuadPart;
            long      sizeGiB   = (long)(sizeBytes / (1024LL * 1024LL * 1024LL));
            char entry[80];

            snprintf(entry, sizeof(entry),
                     "\\\\.\\PhysicalDrive%d (%ld GiB)", i, sizeGiB);

            if (!first) fputs(", ", stdout);
            print_json_string(entry);
            first = 0;
        } else {
            fprintf(stderr,
                    "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX failed for %s "
                    "(error %lu)\n",
                    path, (unsigned long)GetLastError());
        }

        CloseHandle(hDev);
    }

    fputs("]}", stdout);
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Linux Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */
#elif defined(__linux__)

#include <ctype.h>
#include <dirent.h>
#include <limits.h>

/*
 * Returns non-zero if `name` looks like a whole-disk block device.
 *
 * Accepted patterns (entries seen directly under /sys/block/):
 *   sda, sdb, …        SCSI / SATA / USB storage
 *   hda, hdb, …        Legacy PATA / IDE
 *   vda, vdb, …        VirtIO block (KVM/QEMU VMs)
 *   nvme0n1, nvme1n1   NVMe namespaces  (no trailing 'p' = not a partition)
 *
 * Partitions such as sda1 do NOT appear directly in /sys/block — they live
 * under /sys/block/sda/ — so the length-based guard is a safety net only.
 */
static int is_target_drive(const char *name)
{
    size_t len = strlen(name);

    /* sd[a-z][a-z]? — SCSI/SATA/USB */
    if (len >= 3 && name[0] == 's' && name[1] == 'd' &&
            isalpha((unsigned char)name[2]))
        return 1;

    /* hd[a-z] — legacy IDE */
    if (len >= 3 && name[0] == 'h' && name[1] == 'd' &&
            isalpha((unsigned char)name[2]))
        return 1;

    /* vd[a-z] — virtio */
    if (len >= 3 && name[0] == 'v' && name[1] == 'd' &&
            isalpha((unsigned char)name[2]))
        return 1;

    /*
     * nvme[0-9]+n[0-9]+ — NVMe namespace (e.g. nvme0n1).
     * Reject nvme0n1p1 style entries (contain 'p' after the namespace digit).
     * The strstr check for 'n' ensures we skip the bare controller nodes.
     */
    if (strncmp(name, "nvme", 4) == 0 && len >= 7 &&
            isdigit((unsigned char)name[4])) {
        const char *np = strchr(name + 4, 'n');
        if (np != NULL && isdigit((unsigned char)*(np + 1))) {
            /* Ensure no 'p' appears after the namespace number */
            const char *pp = strchr(np + 1, 'p');
            if (pp == NULL)
                return 1;
        }
    }

    return 0;
}

void scan_drives(void)
{
    DIR           *dir;
    struct dirent *de;
    int            first = 1;

    fputs("{\"type\": \"scan_result\", \"drives\": [", stdout);

    dir = opendir("/sys/block");
    if (dir == NULL) {
        fprintf(stderr, "Cannot open /sys/block: check permissions\n");
        fputs("]}", stdout);
        fflush(stdout);
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        char     sizepath[PATH_MAX];
        char     entry[PATH_MAX];
        FILE    *sf;
        long long sectors  = 0;
        long long sizeGiB;

        if (!is_target_drive(de->d_name))
            continue;

        /* /sys/block/<dev>/size contains the number of 512-byte logical blocks */
        snprintf(sizepath, sizeof(sizepath),
                 "/sys/block/%s/size", de->d_name);

        sf = fopen(sizepath, "r");
        if (sf == NULL) {
            fprintf(stderr, "Cannot read %s\n", sizepath);
            continue;
        }
        if (fscanf(sf, "%lld", &sectors) != 1 || sectors <= 0) {
            fclose(sf);
            continue;
        }
        fclose(sf);

        sizeGiB = (sectors * 512LL) / (1024LL * 1024LL * 1024LL);

        snprintf(entry, sizeof(entry),
                 "/dev/%s (%lld GiB)", de->d_name, sizeGiB);

        if (!first) fputs(", ", stdout);
        print_json_string(entry);
        first = 0;
    }

    closedir(dir);
    fputs("]}", stdout);
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Unsupported Platform Guard
 * ═══════════════════════════════════════════════════════════════════════════ */
#else
#  error "Unsupported platform.  scanner.c supports Windows (_WIN32) and Linux (__linux__) only."
#endif
