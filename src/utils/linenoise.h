/* linenoise.h -- VERSION 1.0
 *
 * Guerrilla line editing library against the idea that a line editing lib
 * needs to be 20,000 lines of C code.
 *
 * See linenoise.c for more information.
 *
 * ------------------------------------------------------------------------
 *
 * Copyright (c) 2010-2014, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2010-2013, Pieter Noordhuis <pcnoordhuis at gmail dot com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  *  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  *  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __LINENOISE_H
#define __LINENOISE_H

#if BUILDING_LINENOISE && HAVE_VISIBILITY
#define LINENOISE_EXPORTED __attribute__((__visibility__("default")))
#else
#define LINENOISE_EXPORTED
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct linenoiseCompletions {
  size_t len;
  char **cvec;
} linenoiseCompletions;

typedef void(linenoiseCompletionCallback)(const char *, linenoiseCompletions *);
typedef char*(linenoiseHintsCallback)(const char *, int *color, int *bold);
typedef void(linenoiseFreeHintsCallback)(void *);
LINENOISE_EXPORTED void linenoiseSetCompletionCallback(linenoiseCompletionCallback *);
LINENOISE_EXPORTED void linenoiseSetHintsCallback(linenoiseHintsCallback *);
LINENOISE_EXPORTED void linenoiseSetFreeHintsCallback(linenoiseFreeHintsCallback *);
LINENOISE_EXPORTED void linenoiseAddCompletion(linenoiseCompletions *, const char *);

LINENOISE_EXPORTED char *linenoise(const char *prompt);
LINENOISE_EXPORTED void linenoiseFree(void *ptr);
LINENOISE_EXPORTED int linenoiseHistoryAdd(const char *line);
LINENOISE_EXPORTED int linenoiseHistorySetMaxLen(int len);
LINENOISE_EXPORTED int linenoiseHistorySave(const char *filename);
LINENOISE_EXPORTED int linenoiseHistoryLoad(const char *filename);
LINENOISE_EXPORTED void linenoiseClearScreen(void);
LINENOISE_EXPORTED void linenoiseSetMultiLine(int ml);
LINENOISE_EXPORTED void linenoisePrintKeyCodes(void);
LINENOISE_EXPORTED void linenoiseMaskModeEnable(void);
LINENOISE_EXPORTED void linenoiseMaskModeDisable(void);

#ifdef __cplusplus
}
#endif

#endif /* __LINENOISE_H */
