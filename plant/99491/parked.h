#ifndef CVE99491_PARKED_H
#define CVE99491_PARKED_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static inline int cve99491_boot_id(char *buf, size_t cap)
{
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    char *p;

    if (!f)
        return -1;
    if (!fgets(buf, (int)cap, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    p = strpbrk(buf, "\r\n");
    if (p)
        *p = 0;
    return buf[0] ? 0 : -1;
}

/* A holder writes PARKED with the current boot_id.  A matching marker means
 * the same boot already holds an anchor/zombie; another exploit run can
 * panic, so the caller must refuse until reboot.  `dir` is the effective
 * workdir (profile or --workdir override). */
static inline int cve99491_parked_same_boot_in(const char *dir)
{
    char boot[64], saved[64] = "";
    char path[256];
    FILE *f;
    char *p;

    if (cve99491_boot_id(boot, sizeof boot) != 0)
        return 0;
    snprintf(path, sizeof path, "%s/PARKED", dir);
    f = fopen(path, "r");
    if (!f)
        return 0;
    if (!fgets(saved, sizeof saved, f))
        saved[0] = 0;
    fclose(f);
    p = strpbrk(saved, "\r\n");
    if (p)
        *p = 0;
    if (saved[0] && strcmp(saved, boot) != 0) {
        unlink(path);
        return 0;
    }
    return saved[0] && !strcmp(saved, boot);
}

static inline int cve99491_parked_mark_in(const char *dir)
{
    char boot[64];
    char path[256];
    FILE *f;
    int ok;

    if (cve99491_boot_id(boot, sizeof boot) != 0)
        return -1;
    (void)mkdir(dir, 0755);
    snprintf(path, sizeof path, "%s/PARKED", dir);
    f = fopen(path, "w");
    if (!f)
        return -1;
    ok = fprintf(f, "%s\n", boot) > 0;
    if (fclose(f) != 0)
        ok = 0;
    (void)chmod(path, 0644);
    return ok ? 0 : -1;
}

#endif /* CVE99491_PARKED_H */
