#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

//пытаемся использовать запрещенный системный вызов

int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        perror("socket заблокирован");
    else {
        printf("socket РАЗРЕШЁН — утечка!\n");
        close(fd);
    }

    return 0;
}
