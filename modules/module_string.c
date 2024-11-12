#include "module_string.h"

BOOL mStringArgsByName(const int argc, const wchar_t *argv[],
                       const wchar_t *name, const wchar_t **theArgs,
                       const wchar_t *defaultValue) {
  BOOL result = FALSE;
  const wchar_t *pArgName, *pSeparator;
  SIZE_T argLen, nameLen = wcslen(name);
  int i;
  for (i = 0; i < argc; i++) {
    if ((wcslen(argv[i]) > 1) &&
        ((argv[i][0] == L'/') || (argv[i][0] == L'-'))) {
      pArgName = argv[i] + 1;
      if (!(pSeparator = wcschr(argv[i], L':')))
        pSeparator = wcschr(argv[i], L'=');

      argLen = (pSeparator) ? (pSeparator - pArgName) : wcslen(pArgName);
      if ((argLen == nameLen) && _wcsnicmp(name, pArgName, argLen) == 0) {
        if (theArgs) {
          if (pSeparator) {
            *theArgs = pSeparator + 1;
            result = *theArgs[0] != L'\0';
          }
        } else
          result = TRUE;
        break;
      }
    }
  }
  if (!result && theArgs) {
    if (defaultValue) {
      *theArgs = defaultValue;
      result = TRUE;
    } else
      *theArgs = NULL;
  }
  return result;
}
