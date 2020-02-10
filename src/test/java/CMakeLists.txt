include(FetchContent)
FetchContent_Declare(log4j
  URL https://www-us.apache.org/dist/logging/log4j/1.2.17/log4j-1.2.17.tar.gz
  URL_HASH MD5=8218714e41ee0c6509dcfeafa2e1f53f
)
FetchContent_GetProperties(log4j)
if(NOT log4j_POPULATED)
  FetchContent_Populate(log4j)
endif()
set(log4j_CLASSPATH "${log4j_SOURCE_DIR}/log4j-1.2.17.jar" )
set(SOCKET_SERVER_SOURCES org/apache/log4j/net/ShortSocketServer.java)
add_custom_target(test-classes
  COMMAND ${Java_JAVAC_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR}
          -classpath "${log4j_CLASSPATH}" ${SOCKET_SERVER_SOURCES}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
if(WIN32)
  set(SOCKET_SERVER_CLASSPATH "${CMAKE_CURRENT_BINARY_DIR};${log4j_CLASSPATH}")
else()
  set(SOCKET_SERVER_CLASSPATH "${CMAKE_CURRENT_BINARY_DIR}:${log4j_CLASSPATH}")
endif()

# Use a parameter file to avoid issues with processing ';'
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/StartSocketServerParams.txt
"${Java_JAVA_EXECUTABLE}
-classpath
${SOCKET_SERVER_CLASSPATH}
org.apache.log4j.net.ShortSocketServer
8
input/socketServer
"
)
set(START_SOCKET_SERVER_PARAMETER_FILE ${CMAKE_CURRENT_BINARY_DIR}/StartSocketServerParams.txt PARENT_SCOPE)
