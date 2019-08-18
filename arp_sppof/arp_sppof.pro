TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp \
        networkfuncs.cpp

LIBS += -lpcap -lpthread

HEADERS += \
    funcheader.h \
    protocol_header.h
