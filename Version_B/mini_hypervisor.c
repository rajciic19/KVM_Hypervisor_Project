#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <pthread.h>

#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

struct vm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    char *mem;
    struct kvm_run *kvm_run;
};

struct thread_data {
    struct vm vm;
    char *guest_file;
    size_t mem_size;
    size_t page_size;
};

int init_vm(struct vm *vm, size_t mem_size)
{
    struct kvm_userspace_memory_region region;
    int kvm_run_mmap_size;

    vm->kvm_fd = open("/dev/kvm", O_RDWR);
    if (vm->kvm_fd < 0) {
        perror("open /dev/kvm");
        return -1;
    }

    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        return -1;
    }

    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        return -1;
    }

    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = mem_size;
    region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
    }

    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        return -1;
    }

    kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        return -1;
    }

    vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        return -1;
    }

    return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
    struct kvm_segment seg = {
        .base = 0,
        .limit = 0xffffffff,
        .present = 1,
        .type = 11,
        .dpl = 0,
        .db = 0,
        .s = 1,
        .l = 1,
        .g = 1,
    };

    sregs->cs = seg;

    seg.type = 3;
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs, size_t mem_size, size_t page_size)
{
    uint64_t page = 0;
    uint64_t pml4_addr = 0x1000;
    uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

    uint64_t pdpt_addr = 0x2000;
    uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

    uint64_t pd_addr = 0x3000;
    uint64_t *pd = (void *)(vm->mem + pd_addr);

    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

    if (page_size == 4 * 1024) {
        uint64_t pt_addr = 0x4000;
        uint64_t *pt = (void *)(vm->mem + pt_addr);

        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;

        pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;

        size_t num_pages = mem_size / page_size;
        for (size_t i = 0; i < num_pages; i++) {
            pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            page += page_size;
        }
    } else if (page_size == 2 * 1024 * 1024) {
        size_t num_pages = mem_size / page_size;
        for (size_t i = 0; i < num_pages; i++) {
            pd[i] = (page | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS);
            page += page_size;
        }
    } else {
        fprintf(stderr, "Invalid page size: %zu\n", page_size);
        exit(1);
    }

    sregs->cr3 = pml4_addr;
    sregs->cr4 = CR4_PAE;
    sregs->cr0 = CR0_PE | CR0_PG;
    sregs->efer = EFER_LME | EFER_LMA;

    setup_64bit_code_segment(sregs);
}

void *vm_thread(void *arg)
{
    struct thread_data *data = (struct thread_data *)arg;
    struct vm *vm = &data->vm;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int ret;
    int stop = 0;

    if (init_vm(vm, data->mem_size)) {
        printf("Failed to init the VM\n");
        return NULL;
    }

    if (ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return NULL;
    }

    setup_long_mode(vm, &sregs, data->mem_size, data->page_size);

    if (ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        return NULL;
    }

    memset(&regs, 0, sizeof(regs));
    regs.rflags = 2;
    regs.rip = 0;
    regs.rsp = 2 << 20;

    if (ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        return NULL;
    }

    FILE *img = fopen(data->guest_file, "r");
    if (img == NULL) {
        perror("Cannot open binary file");
        fprintf(stderr, "File path: %s\n", data->guest_file);
        return NULL;
    }

    char *p = vm->mem;
    while (feof(img) == 0) {
        int r = fread(p, 1, 1024, img);
        p += r;
    }
    fclose(img);

    while (stop == 0) {
        ret = ioctl(vm->vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            printf("KVM_RUN failed\n");
            return NULL;
        }

        switch (vm->kvm_run->exit_reason) {
            case KVM_EXIT_IO:
                if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0xE9) {
                    char *p = (char *)vm->kvm_run;
                    printf("%c", *(p + vm->kvm_run->io.data_offset));
                }
                continue;
            case KVM_EXIT_HLT:
                printf("KVM_EXIT_HLT\n");
                stop = 1;
                break;
            case KVM_EXIT_INTERNAL_ERROR:
                printf("Internal error: suberror = 0x%x\n", vm->kvm_run->internal.suberror);
                stop = 1;
                break;
            case KVM_EXIT_SHUTDOWN:
                printf("Shutdown\n");
                stop = 1;
                break;
            default:
                printf("Exit reason: %d\n", vm->kvm_run->exit_reason);
                break;
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    struct thread_data data[10];
    pthread_t threads[10];
    int num_guests = 0;
    size_t mem_size = 2 * 1024 * 1024;
    size_t page_size = 4 * 1024;
    char *guest_files[10];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--memory") == 0 || strcmp(argv[i], "-m") == 0) {
            if (i + 1 < argc) {
                int mem_arg = atoi(argv[++i]);
                if (mem_arg == 2 || mem_arg == 4 || mem_arg == 8) {
                    mem_size = mem_arg * 1024 * 1024;
                } else {
                    fprintf(stderr, "Invalid memory size: %dMB. Valid options are 2, 4, or 8 MB.\n", mem_arg);
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--page") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                int page_arg = atoi(argv[++i]);
                if (page_arg == 4 || page_arg == 2048) {
                    page_size = page_arg * 1024;
                } else {
                    fprintf(stderr, "Invalid page size: %dKB. Valid options are 4KB or 2MB.\n", page_arg);
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--guest") == 0 || strcmp(argv[i], "-g") == 0) {
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                guest_files[num_guests++] = argv[++i];
            }
        }
    }
    printf("Memory: %ld MB, Page Size: %ld KB, Guest Count: %d\n", mem_size/(1024*1024), page_size, num_guests);
    if (num_guests == 0) {
        fprintf(stderr, "No guest file specified.\n");
        return 1;
    }
    for (int i = 0; i < num_guests; i++) {
        printf("Guest file %d: %s\n", i, guest_files[i]);
        data[i].guest_file = guest_files[i];
        data[i].mem_size = mem_size;
        data[i].page_size = page_size;

        pthread_create(&threads[i], NULL, vm_thread, &data[i]);
    }

    for (int i = 0; i < num_guests; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
