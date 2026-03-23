//
// Copyright 2016 The ANGLE Project Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

// translator_fuzzer.cpp: A libfuzzer fuzzer for the shader translator.

#ifdef UNSAFE_BUFFERS_BUILD
#    pragma allow_unsafe_buffers
#endif

// Comment to disable debug messages...
#define DEBUGGING 1

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <unordered_map>

#include "angle_gl.h"
#include "anglebase/no_destructor.h"
#include "common/hash_containers.h"
#include "compiler/translator/Compiler.h"
#include "compiler/translator/util.h"

// #include "util/EGLWindow.h"
#include "util/shader_utils.h"
#include "util/util_gl.h"

#include "util/EGLWindow.h"
#include "util/OSWindow.h"
#include "util/gles_loader_autogen.h"

#include "util/random_utils.h"
#include "util/test_utils.h"

using namespace sh;

namespace
{
struct TranslatorCacheKey
{
    bool operator==(const TranslatorCacheKey &other) const
    {
        return type == other.type && spec == other.spec && output == other.output;
    }

    uint32_t type   = 0;
    uint32_t spec   = 0;
    uint32_t output = 0;
};
}  // anonymous namespace

namespace std
{

template <>
struct hash<TranslatorCacheKey>
{
    std::size_t operator()(const TranslatorCacheKey &k) const
    {
        return (hash<uint32_t>()(k.type) << 1) ^ (hash<uint32_t>()(k.spec) >> 1) ^
               hash<uint32_t>()(k.output);
    }
};
}  // namespace std

struct TCompilerDeleter
{
    void operator()(TCompiler *compiler) const { DeleteCompiler(compiler); }
};

void log(const char* msg) {
    /*
    FILE* fp = fopen("/home/oof/angle_log.txt", "w");
    fwrite(msg, strlen(msg), 1, fp);
    fclose(fp);
    */
#ifdef DEBUGGING
    fprintf(stderr, "%s", msg);
#endif
    return;
}

void log(const std::string msg) {
#ifdef DEBUGGING
    fprintf(stderr, "%s", msg.c_str()); // Convert to cstring...
#endif
    return;
}

#include "anglebase/no_destructor.h"
#include "util/OSWindow.h"
#include "util/EGLWindow.h"
#include "util/EGLPlatformParameters.h"
// #include "util/angle_util.h"

#include "common/system_utils.h"

static bool gInitialized = false;

/*
static OSWindow *GetOSWindow()
{
    static angle::base::NoDestructor<OSWindow*> window;
    return *window;
}

static EGLWindow *GetEGLWindow()
{
    static angle::base::NoDestructor<EGLWindow*> window;
    return *window;
}
*/

static void InitGL()
{
    if (gInitialized)
        return;

    OSWindow *osWindow = OSWindow::New();
    osWindow->initialize("shader_fuzzer", 1, 1);
    osWindow->setVisible(false);

    EGLWindow *eglWindow = EGLWindow::New(2, 0);

    ConfigParameters config;
    config.redBits     = 8;
    config.greenBits   = 8;
    config.blueBits    = 8;
    config.alphaBits   = 8;
    config.depthBits   = 24;
    config.stencilBits = 8;

    EGLPlatformParameters platform;
    platform.renderer = EGL_PLATFORM_ANGLE_TYPE_DEFAULT_ANGLE;

    /*
    mGLWindow->initializeGL(mOSWindow, mEntryPointsLib.get(), mDriverType, mPlatformParams,
                                 configParams))
    */

    if (!eglWindow->initializeGL(
            osWindow,
            angle::OpenSharedLibrary("libEGL.so", //ANGLE_EGL_LIBRARY_NAME,
                                     angle::SearchType::ModuleDir),
            angle::GLESDriverType::AngleEGL,
            platform,
            config))
    {
        abort();
    }

    eglWindow->setSwapInterval(0);

    // *GetOSWindow()  = osWindow;
    // *GetEGLWindow() = eglWindow;


    // OSWindow* mOSWindow = OSWindow::New();


    gInitialized = true;
}

/*
const char *kFixedVS = R"(#version 100
precision highp float;
layout(location = 0) in vec4 pos;
out vec4 v;
void main() {
    gl_Position = pos;
    v = vec4(1.0);
}
)";
*/

const char *kFixedVS = R"(#version 100
precision highp float;
attribute vec4 pos;
varying vec4 v;
void main() {
    gl_Position = pos;
    v = vec4(1.0);
}
)";


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    // Run init...

    InitGL();

    if (size == 0) return 0;

    // Ensure NUL-termination for CompileShader
    std::string src(reinterpret_cast<const char*>(data),
                    reinterpret_cast<const char*>(data) + size);
    src.push_back('\0');

    // GLuint program = CompileProgramInternal(



    // GLuint sh = CompileShader(GL_FRAGMENT_SHADER, src.c_str());
    
    GLuint prog = CompileProgram(kFixedVS, src.c_str()); // Try to compile the stuff...

    if (prog != 0)
    {
        log("Valid.\n");
        // glDeleteShader(sh);
        glDeleteProgram(prog);
        return 0;
    }
    log("Invalid.\n");
    return 0; // -1;
}
