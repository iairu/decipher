#pragma once

#include <fcntl.h>
#include <io.h>

#include "../src/globals.h"

FILE* logfile;
wchar_t* outputBuffer;
size_t outputBufferElements, outputBufferElementsPosition;

void mEcho(PCWCHAR format, ...);
