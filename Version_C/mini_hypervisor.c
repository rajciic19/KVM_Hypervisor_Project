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
#include <sys/stat.h>
#include <sys/types.h>

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

#define OPEN 0x11
#define CLOSE 0x12
#define WRITE 0x13
#define READ 0x14
#define IDLE 0x15

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
    int vm_id;
    int numFiles;
    char **filepaths;
};

int init_vm(struct vm *vm, size_t mem_size) {
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

    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
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

    vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        return -1;
    }

    return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs) {
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

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs, size_t mem_size, size_t page_size) {
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

void make_dir(char **path, char **filepaths, int numFiles, int id) {
    for (int i = 0; i < numFiles; i++) {
        char *fp = filepaths[i];
        if (strcmp(path[0], fp) == 0) return;
    }

    int pathlen = strlen(path[0]);
    int new_pathlen = pathlen + 5;
    char *new_path = (char *)malloc(new_pathlen * sizeof(char));
    new_path[0] = '.';
    new_path[1] = '/';
    new_path[2] = 'g';
    new_path[3] = '0' + id % 10;
    new_path[4] = '/';

    memcpy(new_path + 5, path[0], pathlen);
    new_path[new_pathlen] = '\0';

    // Create the directory if it doesn't exist
    char dir_path[6] = {'g', '0' + id % 10, '\0'};
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        free(new_path);
        return;
    }

    path[0] = new_path;
}


void *vm_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct vm *vm = &data->vm;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int ret;
    int stop = 0;
    FILE *img;
    int numDescriptors = 0;
    FILE **fileDescriptors = (FILE **)malloc(data->numFiles * sizeof(FILE *));
    char currentAction = IDLE;
    char *bufferText = (char *)malloc(1);
    int bufferLen = 0;
    char *filePath = NULL;
    uint32_t ioResult = 0;

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

    img = fopen(data->guest_file, "r");
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
                if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.port == 0x0278) {
                    char *kvmPtr = (char *)vm->kvm_run;
                    *(kvmPtr + vm->kvm_run->io.data_offset) = (uint32_t)ioResult;
                } else if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0xE9) {
                    char *kvmPtr = (char *)vm->kvm_run;
                } else if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0x0278) {
                    char *kvmPtr = (char *)vm->kvm_run;
                    char ioChar = *(kvmPtr + vm->kvm_run->io.data_offset);

                    switch (currentAction) {
                        case IDLE:
                            currentAction = ioChar;
                            break;
                        default:
                            bufferLen++;
                            bufferText = (char *)realloc(bufferText, bufferLen * sizeof(char));
                            if (bufferText == NULL) {
                                fprintf(stderr, "Memory reallocation failed\n");
                                return (void *)-2;
                            }
                            bufferText[bufferLen - 1] = ioChar;
                            break;
                    }

                    if (ioChar == '\0') {
                        switch (currentAction) {
                            case OPEN:
                                if (filePath == NULL) {
                                    filePath = (char *)malloc(bufferLen * sizeof(char));
                                    strcpy(filePath, bufferText);
                                    bufferLen = 0;
                                } else {
                                    make_dir(&filePath, data->filepaths, data->numFiles, data->vm_id);
                                    FILE *filePtr = fopen(filePath, bufferText);
                                    if (filePtr == NULL) {
                                        perror("Failed to open file");
                                        fprintf(stderr, "filePath: %s\n", filePath);
                                        ioResult = (uint32_t)-1;
                                    } else {
                                        fileDescriptors = (FILE **)realloc(fileDescriptors, ++numDescriptors * sizeof(FILE *));
                                        ioResult = (uint32_t)(numDescriptors);
                                        fileDescriptors[numDescriptors - 1] = filePtr;
                                    }
                                    free(filePath);
                                    filePath = NULL;
                                    bufferLen = 0;
                                    currentAction = IDLE;
                                }
                                break;
                            case CLOSE:
                                {
                                    int fileId = atoi(bufferText);
                                    ioResult = (uint32_t)fclose(fileDescriptors[fileId - 1]);
                                    fileDescriptors[fileId - 1] = NULL;
                                    int toRemove = 0;
                                    for (int i = numDescriptors - 1; fileDescriptors[i] == NULL && i >= 0; i--) toRemove++;
                                    numDescriptors -= toRemove;
                                    fileDescriptors = (FILE **)realloc(fileDescriptors, numDescriptors * sizeof(FILE *));
                                    bufferLen = 0;
                                    currentAction = IDLE;
                                }
                                break;
                            case WRITE:
                                if (filePath == NULL) {
                                    filePath = (char *)malloc(bufferLen * sizeof(char));
                                    strcpy(filePath, bufferText);
                                    bufferLen = 0;
                                } else {
                                    int fileId = (int)filePath[0];
                                    FILE *fileDesc = fileDescriptors[fileId - 1];
                                    int writeResult = fprintf(fileDesc, "%s", bufferText);
                                    if (writeResult < 0) {
                                        perror("Failed to write to file");
                                    }
                                    free(filePath);
                                    filePath = NULL;
                                    bufferLen = 0;
                                    currentAction = IDLE;
                                }
                                break;
                            case READ:
                                {
                                    int fileId = atoi(bufferText);
                                    int readChar = fgetc(fileDescriptors[fileId - 1]);
                                    ioResult = readChar;
                                    bufferLen = 0;
                                    currentAction = IDLE;
                                }
                                break;
                            default:
                                currentAction = IDLE;
                                break;
                        }
                    }
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


int main(int argc, char *argv[]) {
    struct thread_data data[10];
    pthread_t threads[10];
    int num_guests = 0;
    int mem_size = 0;
    int page_size = 0;
    int num_files = 0;
    char *guest_files[10] = {0};
    char *filepaths[10] = {0};

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
        } else if (strcmp(argv[i], "--file") == 0 || strcmp(argv[i], "-f") == 0) {
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                filepaths[num_files++] = argv[++i];
            }
        }
    }

    // Print memory size and page size
    printf("Memory Size: %dMB\n", mem_size / (1024 * 1024));
    printf("Page Size: %dKB\n", page_size / 1024);

    // Print guest files
    printf("Guest Files:\n");
    for (int i = 0; i < num_guests; i++) {
        printf("  %s\n", guest_files[i]);
    }

    // Print file paths
    printf("File Paths:\n");
    for (int i = 0; i < num_files; i++) {
        printf("  %s\n", filepaths[i]);
    }

    for (int i = 0; i < num_guests; i++) {
        data[i].guest_file = guest_files[i];
        data[i].mem_size = mem_size;
        data[i].page_size = page_size;
        data[i].vm_id = i;
        data[i].numFiles = num_files;
        data[i].filepaths = filepaths;

        pthread_create(&threads[i], NULL, vm_thread, &data[i]);
    }

    for (int i = 0; i < num_guests; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}