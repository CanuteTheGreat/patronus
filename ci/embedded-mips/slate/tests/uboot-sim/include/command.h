/* ubsim: U-Boot 1.1.4 command table entry (same layout as include/command.h) */
#ifndef UBSIM_COMMAND_H
#define UBSIM_COMMAND_H
struct cmd_tbl_s {
	char *name;
	int maxargs;
	int repeatable;
	int (*cmd)(struct cmd_tbl_s *, int, int, char *[]);
	char *usage;
	char *help;
};
typedef struct cmd_tbl_s cmd_tbl_t;
#define CMD_FLAG_REPEAT 0x0001
#define CMD_FLAG_BOOTD 0x0002
cmd_tbl_t *find_cmd(const char *cmd);
#define U_BOOT_CMD(name, maxargs, rep, cmd, usage, help) extern int ubsim_unused_##name
#endif
