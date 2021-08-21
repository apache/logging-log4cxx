#include "log4cxx/helpers/threadutility.h"
#include "log4cxx/private/log4cxx_private.h"
#include "log4cxx/helpers/loglog.h"

#include <signal.h>

#if LOG4CXX_HAS_SETTHREADDESCRIPTION
#include <windows.h>
#include <processthreadsapi.h>
#endif

using log4cxx::helpers::ThreadUtility;

struct ThreadUtility::priv_data{
	priv_data(){
		pre_start = nullptr;
		thread_start = nullptr;
		post_start = nullptr;
	}

	log4cxx::helpers::pre_thread_start pre_start;
	log4cxx::helpers::thread_started thread_start;
	log4cxx::helpers::post_thread_start post_start;
};

ThreadUtility::ThreadUtility() :
	m_priv( new priv_data() )
{}

ThreadUtility::~ThreadUtility(){}

std::shared_ptr<ThreadUtility> ThreadUtility::instance(){
	static std::shared_ptr<ThreadUtility> instance( new ThreadUtility() );
	return instance;
}

void ThreadUtility::configureThreadFunctions( pre_thread_start pre_start1,
							   thread_started started,
							   post_thread_start post_start1 ){
	m_priv->pre_start = pre_start1;
	m_priv->thread_start = started;
	m_priv->post_start = post_start1;
}

void ThreadUtility::preThreadBlockSignals(){
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	sigset_t set;
	sigfillset(&set);
	if( pthread_sigmask(SIG_SETMASK, &set, nullptr) < 0 ){
		LOGLOG_ERROR( LOG4CXX_STR("Unable to set thread sigmask") );
	}
#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}

void ThreadUtility::threadStartedNameThread(LogString threadName,
							 std::thread::id /*thread_id*/,
							 std::thread::native_handle_type native_handle){
#if LOG4CXX_HAS_PTHREAD_SETNAME
	if( pthread_setname_np( static_cast<pthread_t>( native_handle ), threadName.c_str() ) < 0 ){
		LOGLOG_ERROR( LOG4CXX_STR("unable to set thread name") );
	}
#elif LOG4CXX_HAS_SETTHREADDESCRIPTION
	HRESULT hr = SetThreadDescription(static_cast<HANDLE>(native_handle), threadName.c_str());
	if(FAILED(hr)){
		LOGLOG_ERROR( LOG4CXX_STR("unable to set thread name") );
	}
#endif
}

void ThreadUtility::postThreadUnblockSignals(){
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	sigset_t set;
	sigemptyset(&set);
	if( pthread_sigmask(SIG_SETMASK, &set, nullptr) < 0 ){
		LOGLOG_ERROR( LOG4CXX_STR("Unable to set thread sigmask") );
	}
#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}


log4cxx::helpers::pre_thread_start ThreadUtility::preStartFunction(){
	return m_priv->pre_start;
}

log4cxx::helpers::thread_started ThreadUtility::threadStartedFunction(){
	return m_priv->thread_start;
}

log4cxx::helpers::post_thread_start ThreadUtility::postStartFunction(){
	return m_priv->post_start;
}
