{
  "targets": [
    {
      "target_name": "native",
      "include_dirs" : [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "sources": [
        "native/memoryprocess.cc",
        "native/memory.cc",
        "native/process.cc",
        "native/module.cc",
        "native/pattern.cc",
        "native/functions.cc",
        "native/debugger.cc"
      ],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
    }
  ]
}
