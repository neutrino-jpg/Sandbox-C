#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

//пытается читать дескрипторы, доставшиеся в наследство от родителя
//перебираем все дескрипторы кроме начальных std

int main(){
    for (int fd = 3; fd <64; fd++){ 
        
        if (fcntl(fd, F_GETFD) != -1){
            printf("Дескриптор [%d]: %d     < утечка!\n",fd,fcntl(fd, F_GETFD));
        }
        
        else printf("Дескриптор [%d]: %d\n",fd,fcntl(fd, F_GETFD));
        
        return 0;
    }
} 