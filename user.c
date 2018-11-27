#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void main(){

char a[100];
char file[10],file2[10];
int i,f;

printf("Qual arquivo será manipulado ?\n");
file[0] = '\0';
file2[0] = '\0';
gets(file2);
strcat(file,"/mnt/point1/");
strcat(file,file2);

f = open(file,O_CREAT | O_RDWR); 
//printf("%s",file);
	
		printf("Qual operação é desejada no arquivo ?\n1 - escrever\n2 - ler\n");
		__fpurge(stdin); //Arrumar depois
		scanf("%c", &a[0]);
			if (a[0] == '1') {
				__fpurge(stdin); //Arrumar depois
				gets(a);
				__fpurge(stdin); //Arrumar depois
				write(f,a,sizeof(a));
			}else{

				read(f,a,sizeof(a));
				__fpurge(stdin); //Arrumar depois
				printf("%s\n",a);
			}

close(f);
}
