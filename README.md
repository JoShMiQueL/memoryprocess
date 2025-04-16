> [!WARNING]
> This package relies heavily on **Bun's native FFI (`bun:ffi`)** for performance and interacting with system APIs.
>
> Currently, Bun does not provide a polyfill for `bun:ffi` when building for Node.js (`target: 'node'`). Therefore, this package is **only compatible with the Bun runtime** and **will not work** if run directly with Node.js.
>
> While Bun intends to add polyfills for `bun:*` modules in the future to improve Node.js compatibility for bundled code (see [Bundler Docs](https://bun.sh/docs/bundler#target)), this is not yet implemented for `bun:ffi`.
>
> **Requirements:**
> *   Bun v1.2.9 or later (required to run the code)

---

<p align="center">
  <img alt="Banner"  src="assets/banner.png">
  <code>MemoryProcess</code> is an NPM package to read and write process memory
  <br>
  This is a fork of the original <a href="https://github.com/Rob--/memoryjs">memoryjs</a> package, maintained by <a href="https://github.com/JoShMiQueL">JoShMiQueL</a>
</p>

<p align="center">
  <img alt="GitHub License" src="https://img.shields.io/github/license/JoShMiQueL/memoryprocess">
  <a href="https://github.com/JoShMiQueL/memoryprocess/actions/workflows/publish-npm.yml" target="_blank">
    <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/JoShMiQueL/memoryprocess/release.yml?branch=master&style=flat&logo=npm&label=Publish%20to%20npm">
  </a>
  <a href="https://www.npmjs.com/package/memoryprocess" target="_blank">
    <img alt="NPM Downloads" src="https://img.shields.io/npm/dy/%40memoryprocess">
  </a>
  <a href="https://www.npmjs.com/package/memoryprocess" target="_blank">
    <img alt="NPM Version" src="https://img.shields.io/npm/v/%40memoryprocess">
  </a>
</p>

> [!NOTE]
> W.I.P
