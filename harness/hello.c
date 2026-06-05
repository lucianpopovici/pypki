#include <linux/module.h>
#include <linux/init.h>

static int __init hello_init(void)
{
	pr_info("hello: loaded (ima-evm-harness test module)\n");
	return 0;
}

static void __exit hello_exit(void)
{
	pr_info("hello: unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PyPKI IMA/EVM harness — trivial test module for Phase B signing gates");
MODULE_AUTHOR("ima-evm-harness");
