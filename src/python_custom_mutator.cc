// Here is the custom mutator stuff start...


/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexit-time-destructors"
#pragma clang diagnostic ignored "-Wglobal-constructors"

#include <Python.h>

static void LLVMFuzzerFinalizePythonModule();
static void LLVMFuzzerInitPythonModule();

static PyObject* py_module = NULL;

class LLVMFuzzerPyContext {
  public:
    LLVMFuzzerPyContext() {
      if (!py_module) {
        LLVMFuzzerInitPythonModule();
      }
    }
    ~LLVMFuzzerPyContext() {
      if (py_module) {
        LLVMFuzzerFinalizePythonModule();
      }
    }
};

// This takes care of (de)initializing things properly
LLVMFuzzerPyContext init;

static void py_fatal_error() {
  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
  exit(1);
}

enum {
  /* 00 */ PY_FUNC_CUSTOM_MUTATOR,
  /* 01 */ PY_FUNC_CUSTOM_CROSSOVER,
  PY_FUNC_COUNT
};

static PyObject* py_functions[PY_FUNC_COUNT];

// Forward-declare the libFuzzer's mutator callback.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

// This function unwraps the Python arguments passed, which must be
//
// 1) A bytearray containing the data to be mutated
// 2) An int containing the maximum size of the new mutation
//
// The function will modify the bytearray in-place (and resize it accordingly)
// if necessary. It returns None.
PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
  PyObject* py_value;

  // Get MaxSize first, so we know how much memory we need to allocate
  py_value = PyTuple_GetItem(args, 1);
  if (!py_value) {
    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
    py_fatal_error();
  }
  size_t MaxSize = PyLong_AsSize_t(py_value);
  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
    PyErr_Print();
    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
    py_fatal_error();
  }

  // Now get the ByteArray with our data and resize it appropriately
  py_value = PyTuple_GetItem(args, 0);
  size_t Size = (size_t)PyByteArray_Size(py_value);
  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
    py_fatal_error();
  }

  // Call libFuzzer's native mutator
  size_t RetLen =
    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);

  if (PyByteArray_Resize(py_value, RetLen) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
    py_fatal_error();
  }

  Py_RETURN_NONE;
}

static PyMethodDef LLVMFuzzerMutatePyMethodDef = {
  "LLVMFuzzerMutate",
  LLVMFuzzerMutatePyCallback,
  METH_VARARGS | METH_STATIC,
  NULL
};

static void LLVMFuzzerInitPythonModule() {
  Py_Initialize();

  /* Ensure threading is set up; harmless on newer versions */
#if PY_VERSION_HEX < 0x030a0000
  PyEval_InitThreads();
#endif
  PyGILState_STATE gstate = PyGILState_Ensure();

  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");

  if (module_name) {
    PyObject* py_name = PyUnicode_FromString(module_name);

    py_module = PyImport_Import(py_name);
    Py_DECREF(py_name);

    if (py_module != NULL) {
      py_functions[PY_FUNC_CUSTOM_MUTATOR] =
        PyObject_GetAttrString(py_module, "custom_mutator");
      py_functions[PY_FUNC_CUSTOM_CROSSOVER] =
        PyObject_GetAttrString(py_module, "custom_crossover");

      if (!py_functions[PY_FUNC_CUSTOM_MUTATOR]
        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_MUTATOR])) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
                        " external Python module.\n");
        py_fatal_error();
      }

      if (!py_functions[PY_FUNC_CUSTOM_CROSSOVER]
        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_CROSSOVER])) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Warning: Python module does not implement crossover"
                        " API, standard crossover will be used.\n");
        py_functions[PY_FUNC_CUSTOM_CROSSOVER] = NULL;
      }
    } else {
      if (PyErr_Occurred())
        PyErr_Print();
      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
        module_name);
      py_fatal_error();
    }
  } else {
    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
    // py_fatal_error();
  }
  PyGILState_Release(gstate);


}

static void LLVMFuzzerFinalizePythonModule() {
  /*
  if (py_module != NULL) {
    uint32_t i;
    for (i = 0; i < PY_FUNC_COUNT; ++i)
      Py_XDECREF(py_functions[i]);
    Py_DECREF(py_module);
  }
  Py_Finalize();
  */

  /* For fuzzing, it's safer to avoid finalizing Python to prevent races
     during shutdown. If you insist on finalizing, uncomment the block and
     guard it with the GIL. */
  /*
  PyGILState_STATE gstate = PyGILState_Ensure();
  if (py_module != NULL) {
    for (uint32_t i = 0; i < PY_FUNC_COUNT; ++i)
      Py_XDECREF(py_functions[i]);
    Py_DECREF(py_module);
    py_module = NULL;
  }
  PyGILState_Release(gstate);
  Py_Finalize();
  */
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  // First check if the custom python mutator is specified:
  if (!py_module) { // No custom python mutator, so therefore just mutate regularly. (LLVMFuzzerMutate is the default mutator.)
    return LLVMFuzzerMutate(Data, Size, MaxSize);
  }

  PyGILState_STATE gstate = PyGILState_Ensure();

  PyObject* py_args = PyTuple_New(4);

  // Convert Data and Size to a ByteArray
  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert buffer.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 0, py_value);

  // Convert MaxSize to a PyLong
  py_value = PyLong_FromSize_t(MaxSize);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert maximum size.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 1, py_value);

  // Convert Seed to a PyLong
  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert seed.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 2, py_value);

  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
  if (!py_callback) {
    fprintf(stderr, "Failed to create native callback\n");
    py_fatal_error();
  }

  // Pass the native callback
  PyTuple_SetItem(py_args, 3, py_callback);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_MUTATOR], py_args);

  Py_DECREF(py_args);
  Py_DECREF(py_callback);

  if (py_value != NULL) {
    size_t ReturnedSize = PyByteArray_Size(py_value);
    if (ReturnedSize > MaxSize) {
      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
                      "the maximum size. Returning a truncated buffer.\n");
      ReturnedSize = MaxSize;
    }
    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
    Py_DECREF(py_value);
    // return ReturnedSize; // Instead of returning the python custom mutator, we should also try to use the original custom mutator too (maybe).
    if (getenv("FUZZ_ONLY_CUSTOM")) { // Only fuzz with the custom mutator
      return ReturnedSize;
    }


    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);

  } else {
    if (PyErr_Occurred())
      PyErr_Print();
    fprintf(stderr, "Error: Call failed\n");
    py_fatal_error();
  }

  PyGILState_Release(gstate);

  return 0;
}


// Also add the custom crossover function thing here:

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
  // If python module missing or python crossover missing -> fallback to default
  // NOTE: libFuzzer provides LLVMFuzzerCrossOver in some builds, but not always.
  // Safer fallback: just memcpy prefix/suffix or call LLVMFuzzerMutate on one.
  if (!py_module || !py_functions[PY_FUNC_CUSTOM_CROSSOVER]) {
    size_t n = Size1 < MaxOutSize ? Size1 : MaxOutSize;
    memcpy(Out, Data1, n);
    return n;
  }

  PyGILState_STATE gstate = PyGILState_Ensure();

  // args: (data1, data2, max_out_size, seed)
  PyObject *py_args = PyTuple_New(4);

  PyObject *py_d1 = PyByteArray_FromStringAndSize((const char *)Data1, Size1);
  PyObject *py_d2 = PyByteArray_FromStringAndSize((const char *)Data2, Size2);
  PyObject *py_max = PyLong_FromSize_t(MaxOutSize);
  PyObject *py_seed = PyLong_FromUnsignedLong((unsigned long)Seed);

  if (!py_d1 || !py_d2 || !py_max || !py_seed) {
    Py_XDECREF(py_d1); Py_XDECREF(py_d2); Py_XDECREF(py_max); Py_XDECREF(py_seed);
    Py_DECREF(py_args);
    PyGILState_Release(gstate);
    fprintf(stderr, "Error: Failed to build crossover args.\n");
    py_fatal_error();
  }

  PyTuple_SetItem(py_args, 0, py_d1);
  PyTuple_SetItem(py_args, 1, py_d2);
  PyTuple_SetItem(py_args, 2, py_max);
  PyTuple_SetItem(py_args, 3, py_seed);

  PyObject *py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_CROSSOVER], py_args);
  Py_DECREF(py_args);

  if (!py_value) {
    if (PyErr_Occurred()) PyErr_Print();
    PyGILState_Release(gstate);
    fprintf(stderr, "Error: Python custom_crossover call failed\n");
    py_fatal_error();
  }

  ssize_t ReturnedSize = PyByteArray_Size(py_value);
  if (ReturnedSize < 0) ReturnedSize = 0;
  if ((size_t)ReturnedSize > MaxOutSize) ReturnedSize = (ssize_t)MaxOutSize;

  memcpy(Out, PyByteArray_AsString(py_value), (size_t)ReturnedSize);
  Py_DECREF(py_value);

  PyGILState_Release(gstate);
  return (size_t)ReturnedSize;
}



// custom mutator end...

#pragma clang diagnostic pop

