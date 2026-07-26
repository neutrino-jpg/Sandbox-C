#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

//пытаемся открыть симлинки, указывающие наружу
//lstat - разрешенный утилитой системный вызов, может использоваться для
//перехода в "закрытую" часть системы и кражи персональных данных.


int main() {
    
    int fd1 = open("/etc/badlink", O_RDONLY);
    int fd2 = open("/home/user/secret/password.txt", O_RDONLY);
    int fd3 = open("/lib/goodlink", O_RDONLY);

    printf("\n  =================== РЕЗУЛЬТАТ ОТКРЫТИЯ ===================   \n\n");
    
    printf("Через симлинк наружу: /etc/badlink -> /secret/password.txt: "); 
    if (fd1 != -1) {
        char buf[256];
        read(fd1, buf, sizeof(buf));
        printf("         [УТЕЧКА ДАННЫХ] Значение дескриптора: %d\n",fd1);
        printf("Прочитано: %s\n", buf);
    }
    else printf("        [ОК] Доступ запрещен\n");
        
    printf("Напрямую наружу: /home/user/secret/passwords.txt: ");
    if (fd2 != -1) {
        char buf[256];
        read(fd2, buf, sizeof(buf));
        printf("                   [УТЕЧКА ДАННЫХ] Значение дескриптора: %d\n",fd2);
        printf("Прочитано: %s\n", buf);
    }
    else printf("                  [ОК] Доступ запрещен\n");

    printf("Симлинк в пределах изолятора: /lib/goodlink -> /usr/kolobok.txt:");
    if (fd3 != -1) {
        char buf[256];
        read(fd3, buf, sizeof(buf));
        printf("     [УТЕЧКА ДАННЫХ] Значение дескриптора: %d\n",fd3);
        printf("Прочитано: %s\n", buf);
    }
    else printf("   [ОК] Доступ запрещен\n");

    printf("\nПроверка завершена\n");

    return 0;
}