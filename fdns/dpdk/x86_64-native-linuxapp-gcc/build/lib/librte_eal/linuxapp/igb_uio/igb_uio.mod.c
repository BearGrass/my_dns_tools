#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x3dce2d18, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x29385c75, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x1a80987d, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0xad7177dc, __VMLINUX_SYMBOL_STR(pci_intx_mask_supported) },
	{ 0x4755f871, __VMLINUX_SYMBOL_STR(dev_set_drvdata) },
	{ 0x69e0e7e0, __VMLINUX_SYMBOL_STR(dma_set_mask) },
	{ 0x3e9dcfa6, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0x72d928af, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x547ca86d, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0x22fc34a6, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0x2fedccf8, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x35b6b772, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0x81ffb625, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x60ea2d6, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0x230a688a, __VMLINUX_SYMBOL_STR(pci_enable_msix) },
	{ 0x7efe108b, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x2a057f2d, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0x34f49681, __VMLINUX_SYMBOL_STR(dev_num_vf) },
	{ 0x4addf605, __VMLINUX_SYMBOL_STR(dev_notice) },
	{ 0xe316a87a, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xaa1dc0d0, __VMLINUX_SYMBOL_STR(pci_intx) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0xd5d4f701, __VMLINUX_SYMBOL_STR(pci_cfg_access_lock) },
	{ 0xff37f013, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0x9a07a092, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x8856edc5, __VMLINUX_SYMBOL_STR(__dynamic_dev_dbg) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x85982951, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x15b2fb0d, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0x96209bf, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xf4a9328b, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x3f224e94, __VMLINUX_SYMBOL_STR(pci_check_and_mask_intx) },
	{ 0xa5d91689, __VMLINUX_SYMBOL_STR(pci_enable_device) },
	{ 0xee60ff0a, __VMLINUX_SYMBOL_STR(dev_get_drvdata) },
	{ 0xffc430e6, __VMLINUX_SYMBOL_STR(pci_cfg_access_unlock) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";


MODULE_INFO(srcversion, "47AE41AD0F20FAA13A85D76");
MODULE_INFO(rhelversion, "7.2");
