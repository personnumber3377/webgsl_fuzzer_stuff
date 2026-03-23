#define DXC_CP_UTF8 65001
typedef struct _GUID {
  uint32_t Data1;
  uint16_t Data2;
  uint16_t Data3;
  uint8_t Data4[8];
} GUID;
typedef signed int HRESULT;
typedef unsigned long ULONG;
typedef GUID CLSID;
typedef GUID IID;
typedef const IID &REFIID;
typedef const GUID &REFCLSID;
typedef void *LPVOID;
typedef const wchar_t *LPCWSTR;
typedef uint32_t UINT32;
typedef unsigned int UINT;
typedef size_t SIZE_T;
typedef const void *LPCVOID;
typedef unsigned int BOOL;

#ifndef S_OK
#define S_OK ((HRESULT)0)
#endif

#ifndef FAILED
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#endif

#ifndef SUCCEEDED
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#endif

template <typename interface> inline GUID __emulated_uuidof();
#define __uuidof(T) __emulated_uuidof<typename std::decay<T>::type>()
#define IID_PPV_ARGS(ppType)                                                  \
  __uuidof(decltype(**(ppType))), reinterpret_cast<void **>(ppType)

typedef HRESULT(*DxcCreateInstanceProc)(REFCLSID rclsid,
                                        REFIID riid,
                                        LPVOID *ppv);
const CLSID CLSID_DxcCompiler = {
    0x73e22d93,
    0xe6ce,
    0x47f3,
    {0xb5, 0xbf, 0xf0, 0x66, 0x4f, 0x39, 0xc1, 0xb0}};

constexpr uint8_t nybble_from_hex(char c) {
  return ((c >= '0' && c <= '9')
              ? (c - '0')
              : ((c >= 'a' && c <= 'f')
                     ? (c - 'a' + 10)
                     : ((c >= 'A' && c <= 'F') ? (c - 'A' + 10)
                                               : /* Should be an error */ -1)));
}

constexpr uint8_t byte_from_hexstr(const char str[2]) {
  return nybble_from_hex(str[0]) << 4 | nybble_from_hex(str[1]);
}

constexpr GUID guid_from_string(const char str[37]) {
  return GUID{static_cast<uint32_t>(byte_from_hexstr(str)) << 24 |
                  static_cast<uint32_t>(byte_from_hexstr(str + 2)) << 16 |
                  static_cast<uint32_t>(byte_from_hexstr(str + 4)) << 8 |
                  byte_from_hexstr(str + 6),
              static_cast<uint16_t>(
                  static_cast<uint16_t>(byte_from_hexstr(str + 9)) << 8 |
                  byte_from_hexstr(str + 11)),
              static_cast<uint16_t>(
                  static_cast<uint16_t>(byte_from_hexstr(str + 14)) << 8 |
                  byte_from_hexstr(str + 16)),
              {byte_from_hexstr(str + 19), byte_from_hexstr(str + 21),
               byte_from_hexstr(str + 24), byte_from_hexstr(str + 26),
               byte_from_hexstr(str + 28), byte_from_hexstr(str + 30),
               byte_from_hexstr(str + 32), byte_from_hexstr(str + 34)}};
}

#define CROSS_PLATFORM_UUIDOF(interface, spec)                                 \
  struct interface;                                                            \
  template <> inline GUID __emulated_uuidof<interface>() {                     \
    static const IID _IID = guid_from_string(spec);                            \
    return _IID;                                                               \
  }

CROSS_PLATFORM_UUIDOF(IDxcCompiler3, "228B4687-5A6A-4730-900C-9702B2203F54")
CROSS_PLATFORM_UUIDOF(IDxcResult, "58346CDA-DDE7-4497-9461-6F87AF5E0659")
CROSS_PLATFORM_UUIDOF(IUnknown, "00000000-0000-0000-C000-000000000046")

CROSS_PLATFORM_UUIDOF(IDxcOperationResult, "CEDB484A-D4E9-445A-B991-CA21CA157DC2")
CROSS_PLATFORM_UUIDOF(IDxcBlob,            "8BA5FB08-5195-40E2-AC58-0D989C3A0102")
CROSS_PLATFORM_UUIDOF(IDxcBlobEncoding,    "7241D424-2646-4191-97C0-98E96E42FC68")

struct IUnknown {
  IUnknown(){}
  virtual HRESULT QueryInterface(REFIID riid, void **ppvObject) = 0;
  virtual ULONG AddRef() = 0;
  virtual ULONG Release() = 0;
  template <class Q> HRESULT QueryInterface(Q **pp) {
    return QueryInterface(__uuidof(Q), (void **)pp);
  }

protected:
  virtual ~IUnknown() = default;
};

typedef struct DxcBuffer {
  LPCVOID Ptr;
  SIZE_T Size;
  UINT Encoding;
} DxcText;

struct IDxcCompiler3 : public IUnknown {
  virtual HRESULT Compile(
      const DxcBuffer *pSource, ///< Source text to compile.
      LPCWSTR *pArguments, ///< Array of pointers to arguments.
      UINT32 argCount,    ///< Number of arguments.
      void *pIncludeHandler,  ///< user-provided interface to handle include
      REFIID riid,      ///< Interface ID for the result.
      LPVOID *ppResult ///< IDxcResult: status, buffer, and errors.
      ) = 0;

  virtual HRESULT Disassemble(
      const DxcBuffer *pObject,     ///< Program to disassemble: dxil container or bitcode.
      REFIID riid, ///< Interface ID for the result.
      LPVOID *ppResult ///< IDxcResult: status, disassembly text, and errors.
      ) = 0;

};

// For printing errors...

struct IDxcOperationResult : public IUnknown {
    virtual HRESULT GetStatus(HRESULT* pStatus) = 0;
    virtual HRESULT GetResult(IUnknown** ppResult) = 0;
    virtual HRESULT GetErrorBuffer(IUnknown** ppErrors) = 0;
};

struct IDxcBlob : public IUnknown {
    virtual LPVOID GetBufferPointer() = 0;
    virtual SIZE_T GetBufferSize() = 0;
};

struct IDxcBlobEncoding : public IDxcBlob {
    virtual HRESULT GetEncoding(BOOL* pKnown, UINT32* pCodePage) = 0;
};
