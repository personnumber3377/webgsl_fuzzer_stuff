//
// directx_fuzzer.cpp
// GLSL → ANGLE → HLSL → DXC fuzzer
//

#ifdef UNSAFE_BUFFERS_BUILD
#    pragma allow_unsafe_buffers
#endif

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

#include <unistd.h>
#include <dlfcn.h>

#include "angle_gl.h"
#include "anglebase/no_destructor.h"
#include "common/hash_containers.h"
#include "compiler/translator/Compiler.h"
#include "compiler/translator/util.h"

#include "dxc_utils.cpp"

#define DEBUGGING 0

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
        return (hash<uint32_t>()(k.type) << 1) ^
               (hash<uint32_t>()(k.spec) >> 1) ^
               hash<uint32_t>()(k.output);
    }
};
}

struct TCompilerDeleter
{
    void operator()(TCompiler *compiler) const { DeleteCompiler(compiler); }
};

// -------------------------------------------------------------
// DXC setup
// -------------------------------------------------------------

static IDxcCompiler3* gDxcCompiler = nullptr;
static void* gDxCompilerLib = nullptr;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gDxCompilerLib = dlopen("libdxcompiler.so", RTLD_NOW | RTLD_GLOBAL);
    if (!gDxCompilerLib)
        abort();

    auto dxcCreateInstance =
        reinterpret_cast<DxcCreateInstanceProc>(
            dlsym(gDxCompilerLib, "DxcCreateInstance"));

    if (!dxcCreateInstance)
        abort();

    HRESULT hr = dxcCreateInstance(
        CLSID_DxcCompiler,
        IID_PPV_ARGS(&gDxcCompiler));

    if (FAILED(hr) || !gDxcCompiler)
        abort();

    if (!sh::Initialize())
        abort();

    return 0;
}

// -------------------------------------------------------------
// DXC compile helper
// -------------------------------------------------------------

static void CompileWithDXC(const std::string& hlsl,
                           const char* entry,
                           GLenum type)
{
    if (!gDxcCompiler)
        return;

    const wchar_t* stage_prefix = L"vs";

    if (type == GL_FRAGMENT_SHADER)
        stage_prefix = L"ps";
    else if (type == GL_VERTEX_SHADER)
        stage_prefix = L"vs";

    std::wstring profile = std::wstring(stage_prefix) + L"_6_6";
    std::wstring entry_w(entry, entry + strlen(entry));

    std::vector<const wchar_t*> args = {
        L"-T", profile.c_str(),
        L"-E", entry_w.c_str(),
        L"-HV", L"2018",
        L"/Zpr",
        L"/Gis"
    };

    DxcBuffer buf;
    buf.Ptr = hlsl.data();
    buf.Size = hlsl.size();
    buf.Encoding = DXC_CP_UTF8;

    IUnknown* result = nullptr;

    gDxcCompiler->Compile(
        &buf,
        args.data(),
        static_cast<UINT32>(args.size()),
        nullptr,
        __uuidof(IDxcResult),
        reinterpret_cast<void**>(&result));

    if (result)
        result->Release();
}

// -------------------------------------------------------------
// Main fuzzer entry
// -------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size <= sizeof(ShaderDumpHeader))
        return -1;

    if (data[size - 1] != 0)
        return -1;

    ShaderDumpHeader header{};
    memcpy(&header, data, sizeof(header));

    ShCompileOptions options{};
    memcpy(&options, &header.basicCompileOptions,
           offsetof(ShCompileOptions, metal));
    memcpy(&options.metal, &header.metalCompileOptions,
           sizeof(options.metal));
    memcpy(&options.pls, &header.plsCompileOptions,
           sizeof(options.pls));

    size -= sizeof(header);
    data += sizeof(header);

    uint32_t type = header.type;
    uint32_t spec = header.spec;

    if (type != GL_FRAGMENT_SHADER &&
        type != GL_VERTEX_SHADER)
        return -1;

    if (spec != SH_GLES2_SPEC &&
        spec != SH_WEBGL_SPEC &&
        spec != SH_GLES3_SPEC &&
        spec != SH_WEBGL2_SPEC)
        return -1;

    // -------------------------------------------------------------
    // FORCE HLSL OUTPUT
    // -------------------------------------------------------------

    ShShaderOutput shaderOutput = SH_HLSL_4_1_OUTPUT;

    // -------------------------------------------------------------
    // Only disable options incompatible with HLSL
    // -------------------------------------------------------------

    options.addVulkanXfbEmulationSupportCode = false;
    options.roundOutputAfterDithering = false;
    options.addAdvancedBlendEquationsEmulation = false;
    options.ensureLoopForwardProgress = false;
    options.skipAllValidationAndTransforms = false;

    // Performance optimization
    options.validateAST = false;

    // Force the actual object code generation...

    options.objectCode = true;

    // -------------------------------------------------------------
    // Translator caching
    // -------------------------------------------------------------

    TranslatorCacheKey key;
    key.type   = type;
    key.spec   = spec;
    key.output = shaderOutput;

    using UniqueTCompiler = std::unique_ptr<TCompiler, TCompilerDeleter>;
    static angle::base::NoDestructor<
        angle::HashMap<TranslatorCacheKey, UniqueTCompiler>> translators;

    if (translators->find(key) == translators->end())
    {
        UniqueTCompiler translator(
            ConstructCompiler(type,
                              static_cast<ShShaderSpec>(spec),
                              shaderOutput));

        if (!translator)
            return -1;

        ShBuiltInResources resources;
        sh::InitBuiltInResources(&resources);

        resources.OES_standard_derivatives = 1;
        resources.EXT_shader_texture_lod = 1;
        resources.EXT_draw_buffers = 1;
        resources.EXT_frag_depth = 1;
        resources.EXT_shader_framebuffer_fetch = 1;

        if (!translator->Init(resources))
            return -1;

        (*translators)[key] = std::move(translator);
    }

    auto &translator = (*translators)[key];

    const char *shaderStrings[] =
        {reinterpret_cast<const char *>(data)};

    TInfoSink &infoSink = translator->getInfoSink();

    if (translator->compile(shaderStrings, options) == 0)
        return -1;

    if (!infoSink.obj.isBinary())
    {
        std::string hlsl = infoSink.obj.c_str();

        fprintf(stderr, "Translated HLSL:\n%s\n", infoSink.obj.c_str());

        const char* entry = "main";

        CompileWithDXC(hlsl, entry, type);
    }

    return 0;
}
