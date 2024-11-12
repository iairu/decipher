#include "module_output.h"

FILE *logfile = NULL;
wchar_t *outputBuffer = NULL;
size_t outputBufferElements = 0, outputBufferElementsPosition = 0;

void mEcho(PCWCHAR format, ...) {
  int varBuf;
  size_t tempSize;
  wchar_t *tmpBuffer;
  va_list args;
  va_start(args, format);

  if (outputBuffer) {
    varBuf = _vscwprintf(format, args);
    if (varBuf > 0) {
      if ((size_t)varBuf >
          (outputBufferElements - outputBufferElementsPosition -
           1))  // NULL character
      {
        tempSize =
            (outputBufferElements + varBuf + 1) * 2;
        if (tmpBuffer =
                (wchar_t *)LocalAlloc(LPTR, tempSize * sizeof(wchar_t))) {
          RtlCopyMemory(tmpBuffer, outputBuffer,
                        outputBufferElementsPosition * sizeof(wchar_t));
          LocalFree(outputBuffer);
          outputBuffer = tmpBuffer;
          outputBufferElements = tempSize;
        } else
          wprintf(L"Erreur LocalAlloc: %u\n", GetLastError());
      }
      varBuf = vswprintf_s(outputBuffer + outputBufferElementsPosition,
                           outputBufferElements - outputBufferElementsPosition,
                           format, args);
      if (varBuf > 0) outputBufferElementsPosition += varBuf;
    }
  }
#ifndef _WINDLL
  else {
    vwprintf(format, args);
    fflush(stdout);
  }
#endif
  if (logfile) {
    vfwprintf(logfile, format, args);
    fflush(logfile);
  }
  va_end(args);
}
