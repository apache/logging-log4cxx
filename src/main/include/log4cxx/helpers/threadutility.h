#ifndef _LOG4CXX_THREADUTILITY_H
#define _LOG4CXX_THREADUTILITY_H

#include <thread>
#include <functional>
#include <memory>

#include "log4cxx/logstring.h"

namespace log4cxx {
namespace helpers {

/**
 * A function that will be called before a thread is started.  This can
 * be used to (for example) block all of the signals in the thread, so
 * that when the thread is created it will have a correct signal mask.
 */
typedef std::function<void()> pre_thread_start;

/**
 * Called when a new thread has started.  This can be used to set
 * parameters for the thread in a platform-specific manner.
 *
 * @param threadName The name of the thread
 * @param thread_id The ID of the thread as reported by std::thread::get_id
 * @param native_handle The native handle of the thread, as reported by
 * std::thread::native_handle
 */
typedef std::function<void( LogString threadName,
                                std::thread::id thread_id,
                                std::thread::native_handle_type native_handle )> thread_started;

/**
 * Called after a thread has started. This can be used to (for example)
 * unblock the signals in the thread.
 */
typedef std::function<void()> post_thread_start;

class ThreadUtility;
LOG4CXX_PTR_DEF(ThreadUtility);

class LOG4CXX_EXPORT ThreadUtility {
private:
	ThreadUtility();

	log4cxx::helpers::pre_thread_start preStartFunction();
	log4cxx::helpers::thread_started threadStartedFunction();
	log4cxx::helpers::post_thread_start postStartFunction();

	struct priv_data;
	std::unique_ptr<priv_data> m_priv;

public:
	~ThreadUtility();

	static std::shared_ptr<ThreadUtility> instance();

	/**
	 * Configure the thread functions that log4cxx will use.
	 * Note that setting any of these parameters to nullptr is valid,
	 * and simply results in the callback not being called.	 *
	 */
	void configureThreadFunctions( pre_thread_start pre_start,
								   thread_started started,
								   post_thread_start post_start );

	/**
	 * A pre-start thread function that blocks signals to the new thread
	 * (if the system has pthreads).  If the system does not have pthreads,
	 * is equivalent to preThreadDoNothing();
	 */
	void preThreadBlockSignals();

	/**
	 * A thread_started function that names the thread using the appropriate
	 * system call.
	 */
	void threadStartedNameThread(LogString threadName,
								 std::thread::id thread_id,
								 std::thread::native_handle_type native_handle);

	/**
	 * A post-start thread function that unblocks signals that preThreadBlockSignals
	 * blocked before starting the thread.  If the system does not have pthreads,
	 * is equivalent to postThreadDoNothing();
	 */
	void postThreadUnblockSignals();

	/**
	 * Start a thread
	 */
	template<class Function, class... Args>
	std::thread createThread(LogString name,
							 Function&& f,
							 Args&&... args){
		log4cxx::helpers::pre_thread_start pre_start = preStartFunction();
		log4cxx::helpers::thread_started thread_start = threadStartedFunction();
		log4cxx::helpers::post_thread_start post_start = postStartFunction();

		if( pre_start ){
			pre_start();
		}
		std::thread t( f, args... );
		if( thread_start ){
			thread_start( name,
					  t.get_id(),
					  t.native_handle() );
		}
		if( post_start ){
			post_start();
		}
		return t;
	}
};

} /* namespace helpers */
} /* namespace log4cxx */

#endif
