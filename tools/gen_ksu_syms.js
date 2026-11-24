#!/usr/bin/env node
/*
 * gen_ksu_syms.js —— 从本机 kallsyms 生成 ksu.ko 的符号绑定表。
 *
 * 为什么需要它：
 *   KernelSU 的 KO 引用了 225 个内核符号，其中一部分未被内核导出，
 *   直接 finit_module 会 ENOENT。上游用离线表把未定义符号改成
 *   SHN_ABS + 绝对地址；本脚本就是为**本机构建**生成这张表。
 *
 * 输入：
 *   --kallsyms <file>   root 下 `cat /proc/kallsyms` 的转储
 *   --undef <file>      由 kosyms.js 生成的未定义符号名列表（每行一个）
 *   --slide <hex>       本次开机的 KASLR slide（slide_probe 实测）
 *   --out <file>        输出的头文件
 *
 * 输出：C 头文件，形如
 *   static const struct { const char *name; unsigned long long addr; } ksu_syms[] = {
 *       { "prepare_creds", 0xffffffc08026c000ULL },
 *       ...
 *   };
 *   #define KSU_SYM_COUNT 225
 * 其中 addr 是**链接期地址**（运行时地址 − slide），
 * 由 c99491_load 在运行时再加 slide 得到真实地址。
 */
const fs = require('fs');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}

const kf = arg('--kallsyms');
const uf = arg('--undef');
const slide = BigInt(arg('--slide', '0x0'));
const out = arg('--out', 'plant/cve99491/ksu_syms.h');
if (!kf || !uf) {
  console.error('用法: gen_ksu_syms.js --kallsyms k.txt --undef u.txt --slide 0x.. --out h.h');
  process.exit(2);
}

// 解析 kallsyms：<addr> <type> <name>
const map = new Map();
for (const line of fs.readFileSync(kf, 'utf8').split('\n')) {
  const m = line.trim().match(/^([0-9a-fA-F]+)\s+(\S)\s+(\S+)$/);
  if (!m) continue;
  const addr = BigInt('0x' + m[1]);
  if (addr === 0n) continue; // kptr_restrict 隐藏的行
  map.set(m[3], addr);
}
console.log('kallsyms 条目:', map.size);

const names = fs.readFileSync(uf, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
const found = [];
const missing = [];
for (const n of names) {
  const a = map.get(n);
  if (a === undefined) {
    missing.push(n);
    continue;
  }
  const link = a - slide;
  found.push([n, link]);
}

console.log('需要绑定:', names.length, ' 找到:', found.length, ' 缺失:', missing.length);
if (missing.length) console.log('缺失示例:', missing.slice(0, 10).join(', '));

const lines = [];
lines.push('/* 自动生成：tools/gen_ksu_syms.js —— 请勿手改 */');
lines.push('/* 源：本机 /proc/kallsyms（root）+ ksu.ko 未定义符号表 */');
lines.push('/* slide 已在生成时扣除；运行时 addr + slide 得到真实地址 */');
lines.push('#ifndef KSU_SYMS_H');
lines.push('#define KSU_SYMS_H');
lines.push('');
lines.push('struct ksu_sym { const char *name; unsigned long long addr; };');
lines.push('');
lines.push('static const struct ksu_sym ksu_syms[] = {');
for (const [n, a] of found.sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
  lines.push(`\t{ "${n}", 0x${a.toString(16)}ULL },`);
}
lines.push('};');
lines.push('');
lines.push(`#define KSU_SYM_COUNT ${found.length}`);
lines.push('');
lines.push('#endif');
fs.writeFileSync(out, lines.join('\n') + '\n');
console.log('已写出', out, '(', found.length, '项 )');
if (missing.length) fs.writeFileSync(out + '.missing', missing.join('\n') + '\n');
