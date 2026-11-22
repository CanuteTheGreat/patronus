/* ubsim: the few U-Boot 1.1.4 declarations GL's hush.c / do_test / do_echo / do_run need on a host */
#ifndef UBSIM_COMMON_H
#define UBSIM_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
/* U-Boot's getenv/setenv differ from libc's: rename them for every file that includes this header (after the libc headers) */
#define getenv ub_getenv
#define setenv ub_setenv
#define CFG_HUSH_PARSER 1
#define CFG_CBSIZE 1024
#define CFG_MAXARGS 16
#define CFG_PROMPT "ath> "
#define CFG_PROMPT_HUSH_PS2 "hush>"
#define CONFIG_COMMANDS 0
#define CFG_CMD_BOOTD 0x1ULL
#define CFG_CMD_ECHO 0x2ULL
#define CFG_CMD_RUN 0x4ULL
typedef unsigned long ulong;
typedef unsigned char uchar;
#undef putc
#define putc(c) fputc((c), stdout)
char *getenv(char *name);
void setenv(char *name, char *value);
int readline(const char *prompt);
int ctrlc(void);
int had_ctrlc(void);
void clear_ctrlc(void);
int disable_ctrlc(int);
int run_command(const char *cmd, int flag);
#define simple_strtoul strtoul
#define simple_strtol strtol
#define max(a, b) ((a) > (b) ? (a) : (b))
/* relocation is a no-op on the host (u_boot_hush_reloc adds gd->reloc_off) */
typedef struct { unsigned long reloc_off; } gd_t;
static gd_t ubsim_gd; static gd_t *gd = &ubsim_gd;
#define DECLARE_GLOBAL_DATA_PTR
#endif
