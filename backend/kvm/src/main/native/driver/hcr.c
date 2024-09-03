#include "include/common_data.h"
#include "include/hook_framework.h"
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/kprobes.h>

//定义一个函数指针，函数名 kvm_arch_vcpu_ioctl ，参数  struct file *filp,unsigned int ioctl, unsigned long arg
typedef int (*kvm_arch_vcpu_ioctl_func)(struct file *filp,unsigned int ioctl, unsigned long arg);
static kvm_arch_vcpu_ioctl_func vcpu_ioctl;

HOOK_FUNC_TEMPLATE(vcpu_ioctl);

MODULE_DESCRIPTION("Enable HCR_EL2 with HCR_DC");
MODULE_AUTHOR("YiRan Zhao");
MODULE_LICENSE("GPL");

int hook_vcpu_ioctl(struct file *filp,unsigned int ioctl, unsigned long arg)
{
	kvm_arch_vcpu_ioctl_func origin_vcpu_ioctl = GET_CODESPACE_ADDERSS(vcpu_ioctl);

    if(ioctl == KVM_ARM_VCPU_INIT){
        struct kvm_vcpu *vcpu = filp->private_data;
        int result = origin_vcpu_ioctl(filp,ioctl,arg);
        if(result == 0){
            vcpu->arch.hcr_el2 = HCR_GUEST_FLAGS | HCR_DC;
        }
        printk(KERN_ALERT"hcr: in hooked kvm_arch_vcpu_ioctl, KVM_ARM_VCPU_INIT result = %d\n",result);
        return result;
    }

	return origin_vcpu_ioctl(filp,ioctl,arg);
}

kprobe_opcode_t *kprobe_get_addr(const char *symbol_name) {
    int ret;
    struct kprobe kp;
    kprobe_opcode_t * tmp = 0;
    kp.addr = 0;
    kp.symbol_name = symbol_name;
    ret = register_kprobe(&kp);
    tmp = kp.addr;
    if (ret < 0) {
        goto out; // not function, maybe symbol
    }
    unregister_kprobe(&kp);
out:
    return tmp;
}

static int error_quit(const char *msg){
	printk("hcr: %s\n", msg);
	return -EFAULT;
}

static int __init hcr_init(void) {
    vcpu_ioctl = (int (*)(struct file *, unsigned int,  long unsigned int)) kprobe_get_addr("kvm_arch_vcpu_ioctl");
	if (hijack_target_prepare(vcpu_ioctl, GET_TEMPLATE_ADDERSS(vcpu_ioctl), GET_CODESPACE_ADDERSS(vcpu_ioctl))) {
        printk(KERN_ALERT"kvm_arch_vcpu_ioctl prepare error!\n");
        goto out;
    }
    if (hijack_target_enable(vcpu_ioctl)) {
        printk(KERN_ALERT"kvm_arch_vcpu_ioctl enable error!\n");
        goto out;
    }
    printk(KERN_INFO "hcr: Installed Hook. kvm_arch_vcpu_ioctl=%lx\n",vcpu_ioctl);
    return 0;
    out:
    return -EFAULT;
}

static void __exit hcr_exit(void) {
    hijack_target_disable(vcpu_ioctl, true);
    printk(KERN_INFO "hcr: Uninstalled Hook. kvm_arch_vcpu_ioctl=%lx\n",vcpu_ioctl);
}

module_init(hcr_init);
module_exit(hcr_exit);
