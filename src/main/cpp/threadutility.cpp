#include "log4cxx/helpers/threadutility.h"
#include "log4cxx/private/log4cxx_private.h"
#include "log4cxx/helpers/loglog.h"

#include <signal.h>
#include <mutex>

#if LOG4CXX_HAS_SETTHREADDESCRIPTION
#include <windows.h>
#include <processthreadsapi.h>
#endif

using log4cxx::helpers::ThreadUtility;

struct ThreadUtility::priv_data{
	priv_data(){
		start_pre = nullptr;
		started = nullptr;
		start_post = nullptr;
	}

	log4cxx::helpers::ThreadStartPre start_pre;
	log4cxx::helpers::ThreadStarted started;
	log4cxx::helpers::ThreadStartPost start_post;
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	std::mutex creation_mutex;
	sigset_t old_mask;
	bool sigmask_valid;
#endif
};

ThreadUtility::ThreadUtility() :
	m_priv( new priv_data() )
{}

ThreadUtility::~ThreadUtility(){}

std::shared_ptr<ThreadUtility> ThreadUtility::instance(){
	static std::shared_ptr<ThreadUtility> instance( new ThreadUtility() );
	return instance;
}

void ThreadUtility::configureFuncs( ThreadStartPre pre_start,
							   ThreadStarted started,
							   ThreadStartPost post_start ){
	m_priv->start_pre = pre_start;
	m_priv->started = started;
	m_priv->start_post = post_start;
}

void ThreadUtility::preThreadBlockSignals(){
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	m_priv->creation_mutex.lock();
	sigset_t set;
	sigfillset(&set);
	if( pthread_sigmask(SIG_SETMASK, &set, &m_priv->old_mask) < 0 ){
		LOGLOG_ERROR( LOG4CXX_STR("Unable to set thread sigmask") );
		m_priv->sigmask_valid = false;
	}else{
		m_priv->sigmask_valid = true;
	}
#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}

void ThreadUtility::threadStartedNameThread(LogString threadName,
							 std::thread::id /*threadId*/,
							 std::thread::native_handle_type nativeHandle){
#if LOG4CXX_HAS_PTHREAD_SETNAME
	if( pthread_setname_np( static_cast<pthread_t>( nativeHandle ), threadName.c_str() ) < 0 ){
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
	// Only restore the signal mask if we were able to set it in the first place.
	if( m_priv->sigmask_valid ){
		if( pthread_sigmask(SIG_SETMASK, &m_priv->old_mask, nullptr) < 0 ){
			LOGLOG_ERROR( LOG4CXX_STR("Unable to set thread sigmask") );
		}
	}
	m_priv->creation_mutex.unlock();
#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}


log4cxx::helpers::ThreadStartPre ThreadUtility::preStartFunction(){
	return m_priv->start_pre;
}

log4cxx::helpers::ThreadStarted ThreadUtility::threadStartedFunction(){
	return m_priv->started;
}

log4cxx::helpers::ThreadStartPost ThreadUtility::postStartFunction(){
	return m_priv->start_post;
}
