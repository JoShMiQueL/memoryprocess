#include "module.h"
#include "memory.h"
#include <string>
#include <vector>
#include <optional>

namespace mp {

struct PatternByte { std::uint8_t value; bool wildcard; };

static std::vector<PatternByte> ParsePattern(const std::string& pat) {
  std::vector<PatternByte> out;
  std::string tok;
  for (size_t i = 0; i <= pat.size(); i++) {
    char c = i < pat.size() ? pat[i] : ' ';
    if (c == ' ' || c == '\t') {
      if (!tok.empty()) {
        if (tok == "?" || tok == "??") out.push_back({0, true});
        else out.push_back({static_cast<std::uint8_t>(std::stoul(tok, nullptr, 16)), false});
        tok.clear();
      }
    } else tok += c;
  }
  return out;
}

static const std::size_t CHUNK = 64 * 1024;

class ScanWorker : public Napi::AsyncWorker {
public:
  ScanWorker(Napi::Env env, Napi::Promise::Deferred deferred, HANDLE proc,
             std::vector<PatternByte> pat, std::uintptr_t start, std::uintptr_t end, bool onlyReadable)
      : Napi::AsyncWorker(env), deferred_(deferred), proc_(proc), pat_(std::move(pat)),
        start_(start), end_(end), onlyReadable_(onlyReadable) {}

  void Execute() override {
    std::uintptr_t addr = start_;
    std::uintptr_t limit = end_ ? end_ : 0x7FFFFFFFFFFFULL;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < limit) {
      if (!VirtualQueryEx(proc_, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
      bool readable = (mbi.State == MEM_COMMIT) &&
                      !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                      (!onlyReadable_ || (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)));
      if (readable) {
        std::size_t regionSize = mbi.RegionSize;
        std::vector<std::uint8_t> buf;
        try {
          // read region in chunks to tolerate partially-readable regions
          std::uintptr_t base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
          std::size_t off = 0;
          while (off < regionSize) {
            std::size_t toRead = (regionSize - off > CHUNK) ? CHUNK : regionSize - off;
            SIZE_T got = 0;
            std::vector<std::uint8_t> chunk(toRead);
            if (ReadProcessMemory(proc_, reinterpret_cast<LPCVOID>(base + off), chunk.data(), toRead, &got) && got > 0) {
              chunk.resize(got);
              // append (keep pat_.size()-1 overlap for boundary matches)
              std::size_t overlap = buf.empty() ? 0 : (pat_.size() - 1);
              std::size_t keep = buf.size() > overlap ? buf.size() - overlap : 0;
              buf.resize(keep);
              buf.insert(buf.end(), chunk.begin(), chunk.end());
            }
            off += toRead;
          }
          // scan buf
          for (std::size_t i = 0; i + pat_.size() <= buf.size(); i++) {
            bool m = true;
            for (std::size_t j = 0; j < pat_.size(); j++) {
              if (!pat_[j].wildcard && buf[i + j] != pat_[j].value) { m = false; break; }
            }
            if (m) hits_.push_back(base + i);
          }
        } catch (...) { /* skip region */ }
      }
      addr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
      if (mbi.RegionSize == 0) break;
    }
  }

  void OnOK() override {
    auto arr = Napi::Array::New(Env(), hits_.size());
    for (size_t i = 0; i < hits_.size(); i++)
      arr.Set(i, Napi::BigInt::New(Env(), static_cast<std::uint64_t>(hits_[i])));
    deferred_.Resolve(arr);
  }

  void OnError(const Napi::Error& e) override {
    deferred_.Reject(e.Value());
  }

private:
  Napi::Promise::Deferred deferred_;
  HANDLE proc_;
  std::vector<PatternByte> pat_;
  std::uintptr_t start_, end_;
  bool onlyReadable_;
  std::vector<std::uintptr_t> hits_;
};

Napi::Value ScanAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  // scan(handle, pattern[, {start,end,module,onlyReadable}]) -> Promise<bigint[]>
  if (info.Length() < 2) { Napi::TypeError::New(env, "expected (handle, pattern[, opts])").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  std::string pat = info[1].As<Napi::String>().Utf8Value();
  auto bytes = ParsePattern(pat);
  if (bytes.empty()) { Napi::Error::New(env, "empty pattern").ThrowAsJavaScriptException(); return env.Null(); }

  std::uintptr_t start = 0, end = 0;
  bool onlyReadable = true;
  if (info.Length() > 2 && info[2].IsObject()) {
    auto o = info[2].As<Napi::Object>();
    if (o.Get("start").IsNumber()) start = static_cast<std::uintptr_t>(o.Get("start").As<Napi::Number>().DoubleValue());
    if (o.Get("end").IsNumber()) end = static_cast<std::uintptr_t>(o.Get("end").As<Napi::Number>().DoubleValue());
    if (o.Get("onlyReadable").IsBoolean()) onlyReadable = o.Get("onlyReadable").As<Napi::Boolean>().Value();
    // module support resolved in TS facade (gets module base+size)
  }

  auto deferred = Napi::Promise::Deferred::New(env);
  auto promise = deferred.Promise();

  auto* w = new ScanWorker(env, std::move(deferred), h, std::move(bytes), start, end, onlyReadable);
  w->Queue();
  return promise;
}

} // namespace mp
