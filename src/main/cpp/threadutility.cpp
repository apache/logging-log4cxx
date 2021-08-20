#include "log4cxx/helpers/threadutility.h"
#include "log4cxx/private/log4cxx_private.h"
#include "log4cxx/helpers/loglog.h"

#include <signal.h>

#if LOG4CXX_HAS_SETTHREADDESCRIPTION
#include <windows.h>
#include <processthreadsapi.h>
#endif

using log4cxx::ThreadUtility;

log4cxx::pre_thread_start ThreadUtility::pre_start = ThreadUtility::preThreadDoNothing;
log4cxx::thread_started ThreadUtility::thread_start = ThreadUtility::threadStartedDoNothing;
log4cxx::post_thread_start ThreadUtility::post_start = ThreadUtility::postThreadDoNothing;

ThreadUtility::ThreadUtility(){}

void ThreadUtility::configureThreadFunctions( pre_thread_start pre_start1,
							   thread_started started,
							   post_thread_start post_start1 ){
	if( pre_start1 == nullptr ){
		pre_start = ThreadUtility::preThreadDoNothing;
	}else{
		pre_start = pre_start1;
	}

	if( started == nullptr ){
		thread_start = ThreadUtility::threadStartedDoNothing;
	}else{
		thread_start = started;
	}

	if( post_start1 == nullptr ){
		post_start = ThreadUtility::postThreadDoNothing;
	}else{
		post_start = pre_start1;
	}
}

void ThreadUtility::preThreadDoNothing(){}

void ThreadUtility::preThreadBlockSignals(){
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	sigset_t set;
	sigfillset(&set);
	if( pthread_sigmask(SIG_SETMASK, &set, nullptr) < 0 ){
		LOGLOG_ERROR( "Unable to set thread sigmask" );
	}
#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}

void ThreadUtility::threadStartedDoNothing(LogString,
							std::thread::id,
							std::thread::native_handle_type){}

void ThreadUtility::threadStartedNameThread(LogString threadName,
							 std::thread::id /*thread_id*/,
							 std::thread::native_handle_type native_handle){
#if LOG4CXX_HAS_PTHREAD_SETNAME
	if( pthread_setname_np( static_cast<pthread_t>( native_handle ), threadName.c_str() ) < 0 ){
		LOGLOG_ERROR( "unable to set thread name" );
	}
#elif LOG4CXX_HAS_SETTHREADDESCRIPTION
	HRESULT hr = SetThreadDescription(static_cast<HANDLE>(native_handle), threadName.c_str());
	if(FAILED(hr)){
		LOGLOG_ERROR( "unable to set thread name" );
	}
#endif
}

void ThreadUtility::postThreadDoNothing(){}

void ThreadUtility::postThreadUnblockSignals(){
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	sigset_t set;
	sigemptyset(&set);
	if( pthread_sigmask(SIG_SETMASK, &set, nullptr) < 0 ){
		LOGLOG_ERROR( "Unable to set thread sigmask" );
	}
#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}
