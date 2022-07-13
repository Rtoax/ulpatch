/**
 * @file demangle.h
 * @author Rong Tao
 * @brief 
 * @version 0.1
 * @date 2022-03-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef __ELFVIEW_UTILS_DEMANGLE_H
#define __ELFVIEW_UTILS_DEMANGLE_H 1

#ifdef __cplusplus
extern "C" {
#endif

void setup_demangler(void);
void finish_demangler(void);
bool demangler_enabled(void);

int demangle(const char *input, char *output, int outlen);

#ifdef __cplusplus
}
#endif

#endif /* __ELFVIEW_UTILS_DEMANGLE_H */
