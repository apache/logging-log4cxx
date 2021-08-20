#include <pthread.h>

int main(){
	pthread_t tid;
	pthread_set_name_np(tid, "name");
}
