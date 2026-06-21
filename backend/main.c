/*
 * main.c — Forensic Disk Imager Backend Entry Point
 *
 * Receives sub-commands from the Python GUI via subprocess and dispatches
 * them to the appropriate C module.  All output intended for the GUI is
 * strict JSON on stdout; all diagnostics go to stderr.
 *
 * Usage:
 *   imager scan
 *       Enumerate physical drives → JSON scan_result to stdout.
 *
 *   imager image <source> <destination>
 *       Copy every byte of <source> to <destination>, streaming JSON
 *       progress lines to stdout in real time.
 *       Paths containing spaces do NOT need quoting here — the shell
 *       (or Python subprocess) already splits argv correctly.
 */

#include <stdio.h>
#include <string.h>

#include "scanner.h"
#include "imager.h"

static void print_usage(const char *prog)
{
    const char *p = prog ? prog : "imager";
    fprintf(stderr, "Forensic Disk Imager — C Backend\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s scan\n", p);
    fprintf(stderr, "      Enumerate physical drives (JSON to stdout)\n\n");
    fprintf(stderr, "  %s image <source> <destination> [format] [compression]\n", p);
    fprintf(stderr, "      Acquire image, stream JSON progress to stdout\n");
    fprintf(stderr, "      format       DD (default) | E01\n");
    fprintf(stderr, "      compression  0 (none, default) | 1 (fast) | 9 (best); E01 only\n\n");
    fprintf(stderr, "All JSON goes to stdout.  Diagnostics go to stderr.\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* ── scan ─────────────────────────────────────────────────────────── */
    if (strcmp(argv[1], "scan") == 0) {
        scan_drives();
        fputc('\n', stdout);
        fflush(stdout);
        return 0;
    }

    /* ── verify <e01_path> [expected_sha256] ──────────────────────────── */
    if (strcmp(argv[1], "verify") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s verify <e01_file> [expected_sha256]\n",
                    argv[0]);
            return 1;
        }
        {
            const char *expected = (argc >= 4) ? argv[3] : "";
            return verify_e01(argv[2], expected);
        }
    }

    /* ── image <src> <dst> ────────────────────────────────────────────── */
    if (strcmp(argv[1], "image") == 0) {
        if (argc < 4) {
            fprintf(stderr,
                    "Usage: %s image <source_drive> <destination_file>\n",
                    argv[0]);
            fprintf(stderr,
                    "Example: %s image \"\\\\.\\PhysicalDrive1\" "
                    "\"D:\\evidence\\disk.dd\"\n",
                    argv[0]);
            return 1;
        }
        /*
         * argv[2] and argv[3] are the raw C strings passed by the OS
         * after shell / subprocess argument splitting.  Paths with spaces
         * arrive here already as single strings — no extra parsing needed.
         *
         * argv[4] (format) and argv[5] (compression) are OPTIONAL so the
         * legacy 4-argument invocation still produces a raw DD image
         * (Golden Master compatibility).
         */
        {
            const char *fmt  = (argc >= 5) ? argv[4] : "DD";
            const char *comp = (argc >= 6) ? argv[5] : "0";
            /* Optional chain-of-custody metadata (E01 header). */
            const char *case_no  = (argc >= 7)  ? argv[6] : "";
            const char *evidence = (argc >= 8)  ? argv[7] : "";
            const char *examiner = (argc >= 9)  ? argv[8] : "";
            const char *notes    = (argc >= 10) ? argv[9] : "";
            return image_drive(argv[2], argv[3], fmt, comp,
                               case_no, evidence, examiner, notes);
        }
    }

    fprintf(stderr, "Unknown command: '%s'\n\n", argv[1]);
    print_usage(argv[0]);
    return 1;
}
