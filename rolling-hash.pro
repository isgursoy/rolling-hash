TEMPLATE = app
CONFIG += console  c++2a c++20
CONFIG -= qt app_bundle
QMAKE_CXXFLAGS += -std=gnu++2a -std=gnu++20
QMAKE_CFLAGS_RELEASE +=-Ofast -ffast-math
QMAKE_CXXFLAGS_RELEASE += -Ofast -ffast-math -funroll-all-loops -fpeel-loops\
-ftracer -ftree-vectorize
SOURCES += \
        main.cpp
TARGET=rolling-hash-isgursoy
