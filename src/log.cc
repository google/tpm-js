// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>

#if BUILDING_WASM
#include <emscripten/bind.h>
#include <emscripten/html5.h>
#endif

namespace tpm_js {

void LogMessage(const char *file, int line, int level, const char *fmt, ...) {
  va_list args1;
  va_start(args1, fmt);
  va_list args2;
  va_copy(args2, args1);

  std::vector<char> buf(1 + std::vsnprintf(NULL, 0, fmt, args1));
  va_end(args1);
  std::vsnprintf(buf.data(), buf.size(), fmt, args2);
  va_end(args2);

#if BUILDING_WASM
  emscripten::val jslogger = emscripten::val::global("LogMessage");
  if (!jslogger.isUndefined()) {
    std::string as_str(buf.begin(), buf.end() - 1);
    jslogger(level, as_str);
  }
#else
  printf("%s:%d: %.*s", file, line, buf.size(), buf.data());
#endif
}

} // namespace tpm_js
