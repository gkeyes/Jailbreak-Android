# plant 源码可替换性验证

- commit: `a2f31d5b`
- 结果: **success**
- 方法: zig cc -target aarch64-linux-musl -O2 -static -pthread

## 编译日志

```text
downloading zig
zig=/tmp/zig-linux-x86_64-0.13.0/zig
== zig cc plant/pc98260-su.c -> plant/out/pc98260-su
In file included from /tmp/zig-linux-x86_64-0.13.0/lib/libc/musl/crt/rcrt1.c:3:
/tmp/zig-linux-x86_64-0.13.0/lib/libc/musl/crt/../ldso/dlstart.c:146:20: warning: a function declaration without a prototype is deprecated in all versions of C and is treated as a zero-parameter prototype in C23, conflicting with a subsequent definition [-Wdeprecated-non-prototype]
  146 |         GETFUNCSYM(&dls2, __dls2, base+dyn[DT_PLTGOT]);
      |                           ^
/tmp/zig-linux-x86_64-0.13.0/lib/libc/musl/crt/rcrt1.c:11:13: note: conflicting prototype is here
   11 | hidden void __dls2(unsigned char *base, size_t *sp)
      |             ^
1 warning generated.
plant/out/pc98260-su: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped
== zig cc plant/perf_slide.c -> plant/out/perf_slide
plant/out/perf_slide: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped
== zig cc plant/reach_probe.c -> plant/out/reach_probe
plant/out/reach_probe: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped
== zig cc plant/slide_probe.c -> plant/out/slide_probe
plant/out/slide_probe: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped
built=4 failed=0
total 4272
-rwxr-xr-x 1 runner runner 1007656 Nov 22 04:20 pc98260-su
-rwxr-xr-x 1 runner runner 1097320 Nov 22 04:20 perf_slide
-rwxr-xr-x 1 runner runner 1097296 Nov 22 04:20 reach_probe
-rwxr-xr-x 1 runner runner 1166264 Nov 22 04:20 slide_probe
```
