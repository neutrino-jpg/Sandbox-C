#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <sys/mount.h>
#include <sched.h>

//тест: sudo ./sandbox -- ls -a

void setup_seccomp()
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); //инициализация фильтра

    //БЕЛЫЙ СПИСОК
    //Память и процесс
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);

    //Файловая система
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64), 0);
    
    seccomp_load(ctx); //загрузка в ядро
    seccomp_release(ctx); //освобождение userspace-памяти

}

int main(int argc, char *argv[]) 
{
    
    int opt;
    int status;
    
    static struct option long_opts[] = { //длинные -- функции утилиты
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0,0,0,0}
    };
    
    while ((opt = getopt_long(argc, argv, "hve:", long_opts, NULL)) != -1)
        {
            switch (opt)
            {
                case 'h':
                    printf("Данная программа предназначена для безопасного запуска подозрительных приложений\n");
                    break;
                case 'v':
                    printf("alpha 1.0 \n");
                    break;  
                default:
                {
                    printf("Неизвестная опция \n");
                    break;  
                }  
            }
        }

    if (optind >= argc) {
        printf("[ОШИБКА] Целевая программа не указана\n");
        return 0;
    }
    printf("\n============================================================\n");
    printf("            Запуск программы в защищенном режиме");
    printf("\n============================================================\n");
    printf("\nИнициализация дочернего процесса...\n");
    pid_t pid = fork();
    switch(pid)
    {
        case -1:
            printf("[ОШИБКА] Не удалось создать дочерний процесс\n");
            break;
        case 0:
            printf("Дочерний процесс запущен! PID процесса: %d\n", getpid());

            //создание нового пространства имен
            if (unshare(CLONE_NEWNS) == -1){ 
                perror("unshare");
                _exit(1);
            }
            
            //смена типа распространия монтирования
            if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) == -1){ 
                perror("mount private");
                _exit(1);
            }

            // Монтируем хостовые каталоги в jail (read-only)
            mount("/usr", "/home/user/jail/usr", NULL, MS_BIND | MS_RDONLY, NULL);
            mount("/lib", "/home/user/jail/lib", NULL, MS_BIND | MS_RDONLY, NULL);
            mount("/lib64", "/home/user/jail/lib64", NULL, MS_BIND | MS_RDONLY, NULL);
            mount("/bin", "/home/user/jail/bin", NULL, MS_BIND | MS_RDONLY, NULL);
            mount("/sbin", "/home/user/jail/sbin", NULL, MS_BIND | MS_RDONLY, NULL);
            mount("/etc", "/home/user/jail/etc", NULL, MS_BIND | MS_RDONLY, NULL);

            // Виртуальные ФС
            mount("proc", "/home/user/jail/proc", "proc", 0, NULL);
            mount("tmpfs", "/home/user/jail/tmp", "tmpfs", 0, NULL);
            mount("devtmpfs", "/home/user/jail/dev", "devtmpfs", 0, NULL);

            // Меняем корень на jail
            if (chroot("/home/user/jail") == -1) {
                perror("chroot");
                _exit(1);
            }
            chdir("/");   // переходим в новый корень

            setgid(1001);
            setuid(1001);
            if (getuid() == 0) {
                fprintf(stderr, "Не удалось сбросить привелегии!\n");
                _exit(1);
            }

            //Настройка фильтра
            printf("Инициализация фильтра..\n"); 
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            setup_seccomp(); //применение фильтра
            printf("Фильтр применен\n\n");
            printf("Результат работы программы:\n");
            printf("------------------------------------------------------------\n");
            //запуск
            execvp(argv[optind], &argv[optind]);
            perror("execvp");
            _exit(1);
        default:
            waitpid(pid, &status, 0);
            printf("------------------------------------------------------------\n");
            if (WIFEXITED(status)) {
                printf("\nДочерний процесс выполнен и завершен с кодом %d\n", WEXITSTATUS(status));
            }
            else if (WIFSIGNALED(status)) {
                if (WTERMSIG(status) == 31) {
                    printf("\nСработал фильтр! Процесс принудительно завершен сигналом %d\n", WTERMSIG(status));
                }
                else printf("\nДочерний процесс завершен сигналом %d\n", WTERMSIG(status));
            }
            break;
    }
    printf("Родительский процесс %d завершен\n", getpid());            
    
    return 0;          
}