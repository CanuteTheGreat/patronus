/*
 * ubsim: the GL-AR750S U-Boot boot flow on a host, running GL's OWN hush parser, `test`, `echo` and `run` (fetched from
 * gl-inet/uboot-for-qca95xx at the commit pinned in gl-src.pin; this file is only the board glue around them).
 *
 *   ubsim <nor.bin> <default-env> [--ping-ok]
 *
 * <nor.bin> is a 16 MiB image of the NOR flash (u-boot 0x0, u-boot-env 0x40000 (64 KiB), art 0x50000, kernel 0x60000,
 * nor_reserved 0x460000). One run = one power-on:
 *   1. environment: CRC32 (stored big-endian, MIPS) over 0x10000-4 bytes at 0x40000; bad CRC -> the default environment
 *      (the build's compiled-in one, given as <default-env>, one name=value per line), like env_relocate() in U-Boot 1.1.4
 *   2. GL main_loop for CONFIG_AR750S (src/common/main.c + device_check.c of the pinned source): bootcount kept in RAM
 *      (bootcount_store() is AR300M-only), bootlimit check, calibration_status() -> "Booting image at: 0x9F060000",
 *      check_tftp_file() = run_command("run lf"), eth_halt(), nand_boot_failed -> run_command("bootm 0x9f060000"), then the
 *      environment's bootcmd, then the web failsafe (httpd)
 *   3. bootm ADDR: legacy uImage at ADDR (0x9f000000 + flash offset): magic, header CRC, data CRC (verify=y). A good image
 *      ends the run: prints "BOOT <addr> <image name>" and exits 0. A bad one prints the U-Boot error and returns 1.
 *   saveenv writes the RAM environment back to nor.bin (CRC + data, zero padded, like env_crc_update + saveenv).
 * Output ends with exactly one of: "BOOT 0x... <name>" or "FAILSAFE".
 * ping fails unless --ping-ok (no TFTP server on the house LAN); tftp/erase/cp.b/nand/nboot fail loudly if ever reached.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "common.h"
#include "command.h"
#include "hush.h"

#define FLASH_BASE 0x9f000000u
#define NOR_SIZE (16u << 20)
#define ENV_OFF 0x40000u
#define ENV_SIZE 0x10000u
#define GL_BOOT_ADDR 0x9f060000u

static unsigned char *nor; static const char *nor_path; static int ping_ok;
static char env[ENV_SIZE - 4];          /* RAM copy: "name=value\0...\0\0", like env_ptr->data */
char console_buffer[CFG_CBSIZE];

static uint32_t crc32_z(const unsigned char *p, size_t n) {
	uint32_t c = 0xffffffffu; size_t i; int k;
	for (i = 0; i < n; i++) { c ^= p[i]; for (k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320u & -(c & 1)); }
	return ~c;
}
static uint32_t be32(const unsigned char *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

/* ---- environment: same flat layout and setenv semantics as U-Boot 1.1.4 (_do_setenv: delete, then append at the end) ---- */
static char *env_end(void) { char *e = env; while (*e) e += strlen(e) + 1; return e; }
char *getenv(char *name) {
	char *e; size_t l = strlen(name);
	for (e = env; *e; e += strlen(e) + 1) if (!strncmp(e, name, l) && e[l] == '=') return e + l + 1;
	return NULL;
}
static void env_del(const char *name) {
	char *e; size_t l = strlen(name);
	for (e = env; *e; e += strlen(e) + 1) if (!strncmp(e, name, l) && e[l] == '=') {
		size_t n = strlen(e) + 1; char *end = env_end();
		memmove(e, e + n, (size_t)(end - (e + n)) + 1); memset(env_end() + 1, 0, n); return; }
}
void setenv(char *name, char *value) {
	char *end; size_t need;
	env_del(name); if (!value || !*value) return;
	end = env_end(); need = strlen(name) + 1 + strlen(value) + 1;
	if ((size_t)(end - env) + need + 1 > sizeof(env)) { printf("## Error: environment overflow, \"%s\" deleted\n", name); return; }
	sprintf(end, "%s=%s", name, value); end[need] = 0;
}
static int env_load(const char *defaults) {
	if (crc32_z(nor + ENV_OFF + 4, ENV_SIZE - 4) == be32(nor + ENV_OFF)) { memcpy(env, nor + ENV_OFF + 4, sizeof(env)); return 1; }
	printf("*** Warning - bad CRC, using default environment\n");
	{ FILE *f = fopen(defaults, "r"); char line[4096];
	  memset(env, 0, sizeof(env)); if (!f) { perror(defaults); exit(2); }
	  while (fgets(line, sizeof(line), f)) { char *eq; line[strcspn(line, "\n")] = 0; if (!(eq = strchr(line, '='))) continue;
		*eq = 0; setenv(line, eq + 1); }
	  fclose(f); }
	return 0;
}
static void nor_save(void) { FILE *f = fopen(nor_path, "wb"); if (!f || fwrite(nor, 1, NOR_SIZE, f) != NOR_SIZE) { perror(nor_path); exit(2); } fclose(f); }
static int do_saveenv(cmd_tbl_t *c, int flag, int argc, char *argv[]) {
	uint32_t crc = crc32_z((unsigned char *)env, sizeof(env));
	printf("Saving Environment to Flash...\n");
	nor[ENV_OFF] = crc >> 24; nor[ENV_OFF + 1] = crc >> 16; nor[ENV_OFF + 2] = crc >> 8; nor[ENV_OFF + 3] = crc;
	memcpy(nor + ENV_OFF + 4, env, sizeof(env)); nor_save(); return 0;
}
static int do_setenv(cmd_tbl_t *c, int flag, int argc, char *argv[]) {
	char buf[CFG_CBSIZE]; int i;
	if (argc < 2) { printf("Usage:\n%s\n", c->usage); return 1; }
	buf[0] = 0; for (i = 2; i < argc; i++) { if (i > 2) strcat(buf, " "); strcat(buf, argv[i]); }   /* argv joined by ' ' */
	setenv(argv[1], buf); return 0;
}
static int do_printenv(cmd_tbl_t *c, int flag, int argc, char *argv[]) { char *e; for (e = env; *e; e += strlen(e) + 1) printf("%s\n", e); return 0; }

/* ---- bootm on the legacy uImage at a flash address ---- */
static int do_bootm(cmd_tbl_t *c, int flag, int argc, char *argv[]) {
	unsigned long a = argc > 1 ? strtoul(argv[1], NULL, 16) : 0x80800000ul; unsigned char h[64]; uint32_t off, size;
	printf("## Booting image at %08lx ...\n", a);
	if (a < FLASH_BASE || a >= FLASH_BASE + NOR_SIZE - 64) { printf("## Bad address (not in NOR)\n"); return 1; }
	off = a - FLASH_BASE; memcpy(h, nor + off, 64);
	if (be32(h) != 0x27051956u) { printf("Bad Magic Number\n"); return 1; }
	{ uint32_t hc = be32(h + 4); memset(h + 4, 0, 4); if (crc32_z(h, 64) != hc) { printf("Bad Header Checksum\n"); return 1; } }
	size = be32(nor + off + 12);
	if (off + 64 + size > NOR_SIZE || crc32_z(nor + off + 64, size) != be32(nor + off + 24)) { printf("   Verifying Checksum ... Bad Data CRC\n"); return 1; }
	{ char name[33]; memcpy(name, nor + off + 32, 32); name[32] = 0; printf("BOOT 0x%08lx %s\n", a, name); }
	exit(0);
}
static int do_ping(cmd_tbl_t *c, int flag, int argc, char *argv[]) {
	if (ping_ok) { printf("host %s is alive\n", argc > 1 ? argv[1] : "?"); return 0; }
	printf("ping failed; host %s is not alive\n", argc > 1 ? argv[1] : "?"); return 1;
}
static int do_unreached(cmd_tbl_t *c, int flag, int argc, char *argv[]) { printf("UNEXPECTED: %s reached in the simulation\n", argv[0]); return 1; }

extern int do_test(cmd_tbl_t *, int, int, char *[]);
extern int do_echo(cmd_tbl_t *, int, int, char *[]);
extern int do_run(cmd_tbl_t *, int, int, char *[]);
static cmd_tbl_t cmds[] = {
	{ "echo", CFG_MAXARGS, 1, do_echo, "echo - echo args", 0 }, { "test", CFG_MAXARGS, 1, do_test, "test - minimal test", 0 },
	{ "run", CFG_MAXARGS, 1, do_run, "run - run commands in an environment variable", 0 },
	{ "setenv", CFG_MAXARGS, 0, do_setenv, "setenv - set environment variables", 0 }, { "saveenv", 1, 0, do_saveenv, "saveenv", 0 },
	{ "printenv", CFG_MAXARGS, 1, do_printenv, "printenv", 0 }, { "bootm", CFG_MAXARGS, 1, do_bootm, "bootm", 0 },
	{ "ping", 2, 1, do_ping, "ping", 0 }, { "tftp", 3, 1, do_unreached, "tftp", 0 }, { "erase", 3, 1, do_unreached, "erase", 0 },
	{ "cp.b", 4, 1, do_unreached, "cp", 0 }, { "nand", 5, 1, do_unreached, "nand", 0 }, { "nboot", 4, 1, do_unreached, "nboot", 0 },
	{ 0 } };
cmd_tbl_t *find_cmd(const char *name) { cmd_tbl_t *c; for (c = cmds; c->name; c++) if (!strcmp(c->name, name)) return c; return NULL; }
int run_command(const char *cmd, int flag) { return parse_string_outer((char *)cmd, FLAG_PARSE_SEMICOLON | FLAG_EXIT_FROM_LOOP); }
int readline(const char *prompt) { return -1; }
int ctrlc(void) { return 0; }
int had_ctrlc(void) { return 0; }
void clear_ctrlc(void) { }
int disable_ctrlc(int d) { return 0; }
void do_reset(void *a, int b, int c, void *d) { printf("RESET\n"); exit(3); }

int main(int argc, char **argv) {
	FILE *f; char bc[16], *s; unsigned long bootcount;
	if (argc < 3) { fprintf(stderr, "usage: ubsim <nor.bin> <default-env> [--ping-ok]\n"); return 2; }
	nor_path = argv[1]; ping_ok = argc > 3 && !strcmp(argv[3], "--ping-ok");
	nor = malloc(NOR_SIZE); f = fopen(nor_path, "rb");
	if (!f || fread(nor, 1, NOR_SIZE, f) != NOR_SIZE) { fprintf(stderr, "ubsim: %s must be a 16 MiB NOR image\n", nor_path); return 2; }
	fclose(f);
	env_load(argv[2]);
	u_boot_hush_start();
	/* main_loop, CONFIG_BOOTCOUNT_LIMIT: bootcount++ in RAM (bootcount_store is AR300M-only), bootlimit */
	s = getenv("bootcount"); bootcount = s ? strtoul(s, NULL, 10) : 0; bootcount++;
	sprintf(bc, "%lu", bootcount); setenv("bootcount", bc);
	s = getenv("bootlimit");
	if (s && strtoul(s, NULL, 10) && bootcount > strtoul(s, NULL, 10)) { char cmd[30]; sprintf(cmd, "bootm 0x%x", GL_BOOT_ADDR); setenv("bootcmd", cmd); }
	/* calibration_status() == 0 on a calibrated AR750S with NOR+NAND (nand_boot_failed forced to 1 for non-AR300M) */
	printf("Device have nor and nand flash,Booting standard firmware from nor flash...\nBooting image at: 0x%X\n", GL_BOOT_ADDR);
	run_command("run lf", 0);                   /* check_tftp_file() (no CONFIG_GL_RSA) */
	/* eth_halt(); select_boot_dev() is AR300M-only; nand_boot_failed: */
	{ char cmd[30]; sprintf(cmd, "bootm 0x%x", GL_BOOT_ADDR); run_command(cmd, 0); }
	s = getenv("bootcmd");
	if (s) { char *copy = strdup(s); parse_string_outer(copy, FLAG_PARSE_SEMICOLON | FLAG_EXIT_FROM_LOOP); free(copy); }
	printf("FAILSAFE\n");                       /* run_command("dhcpd start"); NetLoopHttpd(); */
	return 1;
}
