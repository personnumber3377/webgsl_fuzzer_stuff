// webgsl_translator.cpp
// Standalone ANGLE GLSL → WGSL translator (header-driven)

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

#include "angle_gl.h"
#include "anglebase/no_destructor.h"
#include "common/hash_containers.h"
#include "compiler/translator/Compiler.h"
#include "compiler/translator/util.h"

using namespace sh;

// -------------------------------------------------------------
// Logging helpers
// -------------------------------------------------------------

static void print_error(const char* reason) {
    std::cerr << "ERROR: " << reason << std::endl;
}

static void print_valid() {
    std::cerr << "VALID" << std::endl;
}

// -------------------------------------------------------------
// Translator cache key
// -------------------------------------------------------------

namespace {
struct TranslatorCacheKey {
    bool operator==(const TranslatorCacheKey& other) const {
        return type == other.type &&
               spec == other.spec &&
               output == other.output;
    }

    uint32_t type   = 0;
    uint32_t spec   = 0;
    uint32_t output = 0;
};
}

namespace std {
template <>
struct hash<TranslatorCacheKey> {
    std::size_t operator()(const TranslatorCacheKey& k) const {
        return (hash<uint32_t>()(k.type) << 1) ^
               (hash<uint32_t>()(k.spec) >> 1) ^
               hash<uint32_t>()(k.output);
    }
};
}

struct TCompilerDeleter {
    void operator()(TCompiler* compiler) const {
        DeleteCompiler(compiler);
    }
};

// -------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

    if (size <= sizeof(ShaderDumpHeader)) {
        print_error("NOT_ENOUGH_DATA_FOR_HEADER");
        return -1;
    }

    if (data[size - 1] != 0x00) {
        print_error("NOT_NULL_TERMINATED");
        return -1;
    }

    ShaderDumpHeader header{};
    memcpy(&header, data, sizeof(header));

    ShCompileOptions options{};
    memcpy(&options, &header.basicCompileOptions,
           offsetof(ShCompileOptions, metal));
    memcpy(&options.metal, &header.metalCompileOptions,
           sizeof(options.metal));
    memcpy(&options.pls, &header.plsCompileOptions,
           sizeof(options.pls));

    const uint8_t* shaderData = data + sizeof(header);

    uint32_t type = header.type;
    uint32_t spec = header.spec;

    if (type != GL_FRAGMENT_SHADER &&
        type != GL_VERTEX_SHADER) {
        print_error("INVALID_SHADER_TYPE");
        return -1;
    }

    if (spec != SH_GLES2_SPEC &&
        spec != SH_WEBGL_SPEC &&
        spec != SH_GLES3_SPEC &&
        spec != SH_WEBGL2_SPEC) {
        print_error("INVALID_SHADER_SPEC");
        return -1;
    }

    // Force WGSL output
    ShShaderOutput shaderOutput = SH_WGSL_OUTPUT;

    // Match original fuzzer behavior
    options.limitExpressionComplexity = true;
    options.validateAST = false;

    options.addVulkanXfbEmulationSupportCode = false;
    options.roundOutputAfterDithering = false;
    options.addAdvancedBlendEquationsEmulation = false;
    options.ensureLoopForwardProgress = false;
    options.skipAllValidationAndTransforms = false;

    options.pls.fragmentSyncType =
        static_cast<ShFragmentSynchronizationType>(
            static_cast<uint32_t>(options.pls.fragmentSyncType) %
            static_cast<uint32_t>(ShFragmentSynchronizationType::InvalidEnum));

    if (options.pls.type == ShPixelLocalStorageType::NotSupported)
        options.pls.type = ShPixelLocalStorageType::ImageLoadStore;

    if (!sh::Initialize()) {
        print_error("ANGLE_INIT_FAILED");
        return -1;
    }

    TranslatorCacheKey key;
    key.type   = type;
    key.spec   = spec;
    key.output = shaderOutput;

    using UniqueTCompiler = std::unique_ptr<TCompiler, TCompilerDeleter>;
    static angle::base::NoDestructor<
        angle::HashMap<TranslatorCacheKey, UniqueTCompiler>> translators;

    if (translators->find(key) == translators->end()) {

        UniqueTCompiler translator(
            ConstructCompiler(type,
                              static_cast<ShShaderSpec>(spec),
                              shaderOutput));

        if (!translator) {
            print_error("CONSTRUCT_COMPILER_FAILED");
            return -1;
        }

        ShBuiltInResources resources;
        sh::InitBuiltInResources(&resources);

        // ---- Enable ALL extensions like original fuzzer ----

        resources.OES_standard_derivatives        = 1;
        resources.OES_EGL_image_external          = 1;
        resources.OES_EGL_image_external_essl3    = 1;
        resources.NV_EGL_stream_consumer_external = 1;
        resources.ARB_texture_rectangle           = 1;
        resources.EXT_blend_func_extended         = 1;
        resources.EXT_conservative_depth          = 1;
        resources.EXT_draw_buffers                = 1;
        resources.EXT_frag_depth                  = 1;
        resources.EXT_shader_texture_lod          = 1;
        resources.EXT_shader_framebuffer_fetch    = 1;
        resources.ARM_shader_framebuffer_fetch    = 1;
        resources.ARM_shader_framebuffer_fetch_depth_stencil = 1;
        resources.EXT_YUV_target                  = 1;
        resources.APPLE_clip_distance             = 1;
        resources.EXT_gpu_shader5                 = 1;
        resources.EXT_shadow_samplers             = 1;
        resources.EXT_clip_cull_distance          = 1;
        resources.ANGLE_clip_cull_distance        = 1;
        resources.EXT_primitive_bounding_box      = 1;
        resources.OES_primitive_bounding_box      = 1;
        resources.ANGLE_shader_pixel_local_storage = 1;

        resources.MaxClipDistances = 8;
        resources.MaxDrawBuffers = 8;
        resources.MaxDualSourceDrawBuffers = 1;

        resources.MaxPixelLocalStoragePlanes = 4;
        resources.MaxCombinedDrawBuffersAndPixelLocalStoragePlanes = 8;

        if (!translator->Init(resources)) {
            print_error("COMPILER_INIT_FAILED");
            return -1;
        }

        (*translators)[key] = std::move(translator);
    }

    auto& translator = (*translators)[key];

    const char* sources[] = {
        reinterpret_cast<const char*>(shaderData)
    };

    TInfoSink& infoSink = translator->getInfoSink();

    if (translator->compile(sources, options) == 0) {

        fprintf(stderr,
            "ANGLE COMPILE FAILED\n%s\nEND\n",
            infoSink.info.c_str());

        print_error("GLSL_COMPILE_FAILED");
        return -1;
    }

    if (!infoSink.obj.isBinary()) {
        std::cerr << "===== BEGIN WGSL =====\n";
        std::cerr << infoSink.obj.c_str() << "\n";
        std::cerr << "===== END WGSL =====\n";
    }

    print_valid();
    return 0;
}
