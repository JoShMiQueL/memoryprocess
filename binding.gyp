{
  "targets": [
    {
      "target_name": "memoryprocess",
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "sources": [
        "native/memoryprocess.cc",
        "native/process.cc",
        "native/memory.cc",
        "native/module.cc",
        "native/pattern.cc",
        "native/hde/hde64.c"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "NAPI_VERSION=<(napi_build_version)"
      ],
      "conditions": [
        ["OS==\"win\"", {
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalOptions!": [ "-flto=thin", "-flto=full", "-flto" ]
            },
            "VCLibrarianTool": {
              "AdditionalOptions!": [ "-flto=thin", "-flto=full", "-flto" ]
            },
            "VCLinkerTool": {
              "AdditionalOptions!": [ "-flto=thin", "-flto=full", "-flto", "/opt:lldltojobs=<(lto_jobs)" ]
            }
          }
        }]
      ],
      # Node 26 official builds ship thin-LTO flags (-flto=thin, /opt:lldltojobs)
      # that MSVC cannot link. The '%' lets these defaults be overridden but
      # neutralises them when Node reports them enabled.
      "variables": {
        "enable_lto%": "false",
        "enable_thin_lto%": "false",
        "lto_jobs%": ""
      }
    }
  ]
}
