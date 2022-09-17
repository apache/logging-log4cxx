#include <pthread.h>

int main(){
	pthread_t tid;
	pthread_setname_np(tid, "name");
}
