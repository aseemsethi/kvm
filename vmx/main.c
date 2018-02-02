#include "wiser.h"

MODULE_LICENSE("GPL");       // license type -- this affects runtime behavior
MODULE_AUTHOR("Aseem Sethi");// The author -- visible when you use modinfo
MODULE_DESCRIPTION("The wiser hypervisor");  // The description -- see modinfo
MODULE_VERSION("0.1");       // The version of the module

static char *name = "world";
module_param(name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(name, "Name to display");
void getProcCpuid(void);
int wiser_init(void) {
	printk("\n Module wiser %s loaded", name);
	getProcCpuid();
	return 0;
}

void wiser_cleanup(void) {
	printk("\n Module wiser %s unloaded", name);
}

module_init(wiser_init);
module_exit(wiser_cleanup);
