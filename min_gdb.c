/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <signal.h>
#include <capstone/capstone.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <gelf.h>
#include <fcntl.h>

#define TOOL "mdb"

#define die(...) \
    do { \
        fprintf(stderr, TOOL": " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


#define BREAKPOINT_ADDR 0x0000000000401155


typedef struct{
    long address;
    long original_bytes;
    int id;
}Breakpoint;

typedef struct {
    long        addr;
    char       *name;
} Symbol;

static Symbol *symtable = NULL;
static int     symcount = 0;

static Breakpoint *bptable = NULL;
static int bpcount;
static int next_bp_id = 0;

void show_regs(int);
void show_current(int);

const char *sym_lookup(long addr) {
    for (int i = 0; i < symcount; i++)
        if (symtable[i].addr == addr)
            return symtable[i].name;
    return NULL;
}


void load_symbols(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die("open: %s", strerror(errno));

    elf_version(EV_CURRENT);
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("elf_begin: %s", elf_errmsg(-1));

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        int count = shdr.sh_size / shdr.sh_entsize;

        for (int i = 0; i < count; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);

            if (sym.st_value == 0) continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || *name == '\0') continue;

            symtable = realloc(symtable, sizeof(Symbol) * (symcount + 1));
            symtable[symcount].addr = sym.st_value;
            symtable[symcount].name = strdup(name);
            symcount++;
        }
    }

    elf_end(elf);
    close(fd);
    fprintf(stderr, "Loaded %d symbols from %s\n", symcount, path);
    
}

void process_inspect(int pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("%s", strerror(errno));
  
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
    if (current_ins == -1) 
        die("(peekdata) %s", strerror(errno));
   
    fprintf(stderr, "=> 0x%llx: 0x%lx\n", regs.rip, current_ins);
 
}

int bp_add(int pid, long addr) {
    /* Backup current code.  */
    long original = 0; 
    original = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (original == -1)
    {
        die("(peekdata) %s", strerror(errno));
    }

    fprintf(stderr, "0x%p: 0x%lx\n", (void *)addr, original);

    /* Insert the breakpoint. */
    long trap = (original & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1) 
    {
        die("(pokedata) %s", strerror(errno));
    }
    
    bptable = realloc(bptable, sizeof(Breakpoint)*(bpcount + 1));
    if(!bptable)    die("realloc: %s", strerror(errno));

    bptable[bpcount].address = addr;
    bptable[bpcount].original_bytes = original;
    bptable[bpcount].id = next_bp_id++;
    bpcount++;

  
    /* Resume process.  */ 
    fprintf(stderr, "Breakpoint %d set at 0x%lx\n", bptable[bpcount - 1].id, addr);
    return bpcount - 1;
}


void bp_remove(int pid, int id) {
    int idx = -1;
    for (int i = 0; i < bpcount; i++) {
        if (bptable[i].id == id) { idx = i; break; }
    }
    if (idx == -1)
        die("No such breakpoint: %d", id);

    if (ptrace(PTRACE_POKEDATA, pid, (void *)bptable[idx].address,
               (void *)bptable[idx].original_bytes) == -1)
        die("(pokedata) %s", strerror(errno));

    /* Swap with last and shrink */
    bptable[idx] = bptable[bpcount - 1];
    bpcount--;
    bptable = realloc(bptable, sizeof(Breakpoint) * bpcount);
}

void bp_list(void) {
    if (bpcount == 0) {
        fprintf(stderr, "No breakpoints set.\n");
        return;
    }
    for (int i = 0; i < bpcount; i++)
        fprintf(stderr, "  [%d] 0x%lx\n", bptable[i].id, bptable[i].address);
}

void process_step(int pid) {

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));
 
    waitpid(pid, 0, 0);
}

void serve_breakpoint(int pid, long original_instruction) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("(getregs) %s", strerror(errno));
  
    process_inspect(pid); 
    getchar();

    fprintf(stderr, "Resuming.\n");

    if (ptrace(PTRACE_POKEDATA, pid, (void *)BREAKPOINT_ADDR, (void *)original_instruction)  == -1)
        die("(pokedata) %s", strerror(errno));
    
    regs.rip = BREAKPOINT_ADDR;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));

}

void show_regs(int pid) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) {
        fprintf(stderr, "(getregs) %s\n", strerror(errno));
        return;
    }
    fprintf(stderr,
        "  rip = 0x%016llx  rsp = 0x%016llx  rbp =    0x%016llx\n"
        "  rax = 0x%016llx  rbx = 0x%016llx  rcx =    0x%016llx\n"
        "  rdx = 0x%016llx  rsi = 0x%016llx  rdi =    0x%016llx\n"
        "  r8  = 0x%016llx  r9  = 0x%016llx  r10 =    0x%016llx\n"
        "  r11 = 0x%016llx  r12 = 0x%016llx  r13 =    0x%016llx\n"
        "  r14 = 0x%016llx  r15 = 0x%016llx  rflags = 0x%016llx\n",
        r.rip, r.rsp, r.rbp,
        r.rax, r.rbx, r.rcx,
        r.rdx, r.rsi, r.rdi,
        r.r8,  r.r9,  r.r10,
        r.r11, r.r12, r.r13,
        r.r14, r.r15, r.eflags);
        fprintf(stderr, TOOL"> ");
}


void show_current(int pid) {
    struct user_regs_struct r;
    ptrace(PTRACE_GETREGS, pid, 0, &r);
    errno = 0;
    long ins = ptrace(PTRACE_PEEKDATA, pid, (void *)r.rip, 0);
    fprintf(stderr, "=> 0x%llx:  0x%016lx\n", r.rip, ins);
}

void disassemble(int pid, long addr, int count) {
    /* Read enough bytes for count instructions */
    uint8_t bytes[count * 15];
    for (int i = 0; i < (count * 15) / 8 + 1; i++) {
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 8), 0);
        memcpy(bytes + i * 8, &word, 8);
    }

    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        die("capstone init failed");

    size_t n = cs_disasm(handle, bytes, sizeof(bytes), addr, count, &insn);
    if (n == 0)
        die("disasm failed");

    for (size_t i = 0; i < n; i++) 
    {
        char bytestr[64] = {0};
        int pos = 0;
        for (int j = 0; j < insn[i].size; j++)
            pos += sprintf(bytestr + pos, "%02x ", insn[i].bytes[j]);

        /* Try to resolve address in operands */
        char resolved_ops[256];
        strncpy(resolved_ops, insn[i].op_str, sizeof(resolved_ops));

        char *hex = strstr(resolved_ops, "0x");
        if (hex) {
            long ref_addr = strtol(hex, NULL, 16);
            const char *ref_sym = sym_lookup(ref_addr);
            if (ref_sym) {
                char tmp[512];
                *hex = '\0';
                snprintf(tmp, sizeof(tmp), "%s[%s]", resolved_ops, ref_sym);
                strncpy(resolved_ops, tmp, sizeof(resolved_ops));
            }
        }

        const char *sym = sym_lookup(insn[i].address);
        if (sym)
            fprintf(stderr, "  %s:\n", sym);

        fprintf(stderr, "  0x%016lx:  %-20s %s %s\n",
                insn[i].address, bytestr, insn[i].mnemonic, resolved_ops);
        if(!strncmp(insn[i].mnemonic, "ret", 3))
            break;
    }


    cs_free(insn, n);
    cs_close(&handle);
}


void bp_add_sym(int pid, char *symname)
{
    for(int i = 0; i<symcount; i++)
    {
        if(!strcmp(symname, symtable[i].name)){
            bp_add(pid, symtable[i].addr);
            return;
        }
    }
    fprintf(stderr, "symbol not found\n");
    return;
}


int main(int argc, char **argv)
{
    if (argc <= 1)
        die("min_strace <program>: %d", argc);
    load_symbols(argv[1]);



    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            die("%s", strerror(errno));
        case 0:  /* Code that is run by the child. */
            /* Start tracing.  */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* execvp() is a system call, the child will block and
               the parent must do waitpid().
               The waitpid() of the parent is in the label
               waitpid_for_execvp.
             */
            execvp(argv[1], argv + 1);
            die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    /* Pre-run REPL: set breakpoints before starting */
    char *line;
    while ((line = readline(TOOL"> ")) != NULL) {
        if (*line) add_history(line);
        
        long addr;
        int  id;
        char symname[256];

        if (sscanf(line, "b %lx", &addr) == 1) {
            bp_add(pid, addr);
        } else if(sscanf(line, "b %s", symname) == 1){
            bp_add_sym(pid, symname);
        } else if (sscanf(line, "d %d", &id) == 1) {
            bp_remove(pid, id);
        } else if (strncmp(line, "l", 4) == 0) {
            bp_list();
        } else if (strncmp(line, "r", 3) == 0) {
            free(line);
            break;
        } else {
            fprintf(stderr, "Commands: break <addr>, delete <id>, list, run\n");
        }

        free(line);
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
    die("(cont) %s", strerror(errno));

    int status;
    while (1) {
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
            break;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            long bp_addr = regs.rip - 1;

            /* find which breakpoint was hit */
            int idx = -1;
            for (int i = 0; i < bpcount; i++) {
                if (bptable[i].address == bp_addr) { idx = i; break; }
            }

            if (idx != -1) {
                fprintf(stderr, "Breakpoint %d hit at 0x%lx\n", bptable[idx].id, bp_addr);
                disassemble(pid, bp_addr, 10);
                
                /* Fix rip to point back to the breakpoint */
                regs.rip = bp_addr;
                ptrace(PTRACE_SETREGS, pid, 0, &regs);

                /* Restore original bytes */
                ptrace(PTRACE_POKEDATA, pid, (void *)bp_addr, (void *)bptable[idx].original_bytes);

                /* Post-run REPL */
                char *line;
                while ((line = readline(TOOL">"))!=NULL) {
                    if (*line) add_history(line);

                    int id;

                    if (strncmp(line, "c", 1) == 0) {
                        break;
                    } else if (strncmp(line, "s", 1) == 0) {
                        process_step(pid);
                        show_current(pid);
                    } else if (strncmp(line, "regs", 4) == 0) {
                        show_regs(pid);
                    } else if (sscanf(line, "d %d", &id) == 1) {
                        bp_remove(pid, id);
                    } else if (strncmp(line, "disas", 5) == 0) {
                        struct user_regs_struct cur;

                        if (ptrace(PTRACE_GETREGS, pid, 0, &cur) == -1)
                            die("(getregs) %s", strerror(errno));

                        disassemble(pid, cur.rip, 10);
                    } else if (strncmp(line, "l", 1) == 0) {
                        bp_list();
                    } else{
                        fprintf(stderr, "Commands: c, s, regs, d <id>, list\n");
                    }
                    free(line);
                }
            }

            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                die("(cont) %s", strerror(errno));
        }
    }

    waitpid(pid, 0, 0);
}
