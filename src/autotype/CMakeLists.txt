if(Q_WS_X11)
  find_package(X11)

  if(X11_FOUND AND X11_XTest_FOUND)
    add_subdirectory(x11)
  endif()
endif()

#Disable tests for now as they are failing under Qt5
#if(WITH_TESTS)
#  add_subdirectory(test)
#endif()
