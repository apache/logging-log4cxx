#include <stdlib.h>
#include <pthread.h>

int main(){
	int result = EXIT_SUCCESS;
	pthread_mutex_t m;
	pthread_mutexattr_t rrAttr;
	if (pthread_mutexattr_init(&rrAttr) != 0)
		result = EXIT_FAILURE;
	else if (pthread_mutexattr_setprotocol(&rrAttr, PTHREAD_PRIO_INHERIT) != 0)
		result = EXIT_FAILURE;
	else if (pthread_mutex_init(&m, &rrAttr) != 0)
		result = EXIT_FAILURE;
	else
		pthread_mutex_destroy(&m);
	pthread_mutexattr_destroy(&rrAttr);
	return result;
}
