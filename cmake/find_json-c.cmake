# - Try to find json-c
# Once done this will define
#
#  JSON_C_INCLUDE_DIRS - the json-c include directory
#  JSON_C_LIBRARIES - Link these to use json-c
#  JSON_C_DEFINITIONS - Compiler switches required for using json-c
#  HAVE_JSON_C_H - have json-c/json.h

find_path(JSON_C_INCLUDE_DIRS
  NAMES
    json.h
  PATH_SUFFIXES
    json-c
  PATHS
    ENV CPATH)

find_library(JSON_C_LIBRARIES
  NAMES
    json-c
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibJsonC "Please install the json-c development package"
	JSON_C_LIBRARIES
	JSON_C_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES json-c)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <json-c/json.h>
int main() {
	return 0;
}" HAVE_JSON_C_H)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(JSON_C_INCLUDE_DIRS JSON_C_LIBRARIES HAVE_JSON_C_H)
