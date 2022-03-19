#include <pthread.h>

int main(){
	pthread_t tid;
	char buffer[16];
	pthread_getname_np(tid, buffer, sizeof(buffer));
}
