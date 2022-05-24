#include "main.h"

static void reboot_cmd(void)
{
	ctrl_reset_write(1);
}

static void prompt(void)
{
	printf("\e[92;1mlitex-demo-app\e[0m> ");
}

int main(void)
{
	#ifdef CONFIG_CPU_HAS_INTERRUPT
		irq_setmask(0);
		irq_setie(1);
	#endif

	uart_init();
	prompt();

	run_tests();

	return 0;
}
