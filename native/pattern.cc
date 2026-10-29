#include "module.h"
#include "memory.h"
#include <string>
#include <vector>
#include <optional>
#include <cstring>

namespace mp {

struct PatternByte { std::uint8_t value; bool wildcard; };

// Parse a hex-byte pattern ("DE AD ?? EF"). Tokens must be 1-2 hex digits or
// ?/?? wildcards. Returns nullopt on ANY malformed token — the caller turns
// this into a JS error; no C++ exception can cross the N-API boundary.
static std::optional<std::vector<PatternByte>> ParsePattern(const std::string& pat) {
  std::vector<PatternByte> out;
  std::string tok;
  auto flush = [&]() -> bool {
    if (tok.empty()) return true;
    if (tok == "?" || tok == "??") { out.push_back({0, true}); tok.clear(); return true; }
    if (tok.size() > 2 || tok.find('?') != std::string::npos) return false;
    unsigned long v = 0;
    for (char c : tok) {
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<unsigned long>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned long>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned long>(c - 'A' + 10);
      else return false;
    }
    out.push_back({static_cast<std::uint8_t>(v & 0xff), false});
    tok.clear();
    return true;
  };
  for (size_t i = 0; i <= pat.size(); i++) {
    char c = i < pat.size() ? pat[i] : ' ';
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      if (!flush()) return std::nullopt;
    } else tok += c;
  }
  if (out.empty()) return std::nullopt;
  return out;
}

static const std::size_t CHUNK = 64 * 1024;
static const std::uintptr_t USER_TOP = 0x7FFFFFFFFFFFULL;

static inline bool RegionReadable(const MEMORY_BASIC_INFORMATION& mbi) {
  return (mbi.State == MEM_COMMIT) &&
         !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
         (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}
static inline bool RegionWritable(const MEMORY_BASIC_INFORMATION& mbi) {
  return (mbi.State == MEM_COMMIT) &&
         !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
         (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}

// Async region-scan worker shared by the AOB scan and the typed-value scan.
// Runs with a PRIVATE least-privilege process handle opened from the pid (a
// JS-side close() can never invalidate it mid-scan), and scans each committed
// range with a rolling window — 64KB chunks plus a (needle-1)-byte overlap —
// so multi-hundred-MB regions never accumulate in memory.
class ScanWorker : public Napi::AsyncWorker {
public:
  ScanWorker(Napi::Env env, Napi::Promise::Deferred deferred, DWORD pid,
             std::vector<PatternByte> pat, std::uintptr_t start, std::uintptr_t end,
             bool onlyReadable)
      : Napi::AsyncWorker(env), deferred_(deferred), pid_(pid), pat_(std::move(pat)),
        start_(start), end_(end), onlyReadable_(onlyReadable) {}

  ScanWorker(Napi::Env env, Napi::Promise::Deferred deferred, DWORD pid,
             std::vector<std::uint8_t> needle, std::uintptr_t start, std::uintptr_t end,
             bool onlyWritable, std::size_t alignment)
      : Napi::AsyncWorker(env), deferred_(deferred), pid_(pid), needle_(std::move(needle)),
        start_(start), end_(end), valueMode_(true), onlyWritable_(onlyWritable),
        alignment_(alignment) {}

  ~ScanWorker() override { if (proc_) CloseHandle(proc_); }

  void Execute() override {
    proc_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid_);
    if (!proc_) { SetError("OpenProcess failed (pid gone or access denied)"); return; }

    // QA4 lifecycle-M1: a C++ exception (bad_alloc in hits_ growth or the
    // per-chunk vector) escaping Execute() used to skip CloseHandle — a real
    // handle leak under memory pressure, every scan call. Guard all exits.
    try {
      const std::uintptr_t limit = end_ ? end_ : USER_TOP;
      MEMORY_BASIC_INFORMATION mbi{};
      std::uintptr_t addr = start_;
      while (addr < limit) {
        if (!VirtualQueryEx(proc_, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
        const std::uintptr_t rBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t rEnd = rBase + mbi.RegionSize;
        if (mbi.RegionSize == 0) break;
        const bool ok = valueMode_
            ? (onlyWritable_ ? RegionWritable(mbi) : RegionReadable(mbi) ||
               ((mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))))
            : (onlyReadable_ ? RegionReadable(mbi)
                             : ((mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))));
        if (ok) {
          // clamp window to [start_, limit)
          const std::uintptr_t s = rBase > start_ ? rBase : start_;
          const std::uintptr_t e = rEnd < limit ? rEnd : limit;
          if (s < e) ScanRange(s, e);
        }
        addr = rEnd;
      }
    } catch (const std::exception& e) {
      CloseHandle(proc_);
      proc_ = nullptr;
      SetError(std::string("scan failed: ") + e.what());
      return;
    } catch (...) {
      CloseHandle(proc_);
      proc_ = nullptr;
      SetError("scan failed: unknown exception");
      return;
    }
    CloseHandle(proc_);
    proc_ = nullptr;
  }

  void OnOK() override {
    auto arr = Napi::Array::New(Env(), hits_.size());
    for (size_t i = 0; i < hits_.size(); i++)
      arr.Set(i, Napi::BigInt::New(Env(), static_cast<std::uint64_t>(hits_[i])));
    deferred_.Resolve(arr);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

private:
  std::size_t NeedleLen() const { return valueMode_ ? needle_.size() : pat_.size(); }

  bool MatchAt(const std::uint8_t* p) const {
    if (valueMode_) return std::memcmp(p, needle_.data(), needle_.size()) == 0;
    for (std::size_t j = 0; j < pat_.size(); j++)
      if (!pat_[j].wildcard && p[j] != pat_[j].value) return false;
    return true;
  }

  // Rolling-window scan of the committed VA range [lo, hi).
  void ScanRange(std::uintptr_t lo, std::uintptr_t hi) {
    const std::size_t patLen = NeedleLen();
    const std::size_t overlap = patLen - 1;
    std::vector<std::uint8_t> tail;   // last `overlap` bytes read (contiguity kept)
    std::uintptr_t pos = lo;
    while (pos < hi) {
      const std::size_t toRead =
          (hi - pos > CHUNK) ? CHUNK : static_cast<std::size_t>(hi - pos);
      std::vector<std::uint8_t> chunk(toRead);
      SIZE_T got = 0;
      if (!ReadProcessMemory(proc_, reinterpret_cast<LPCVOID>(pos),
                             chunk.data(), toRead, &got) || got == 0) {
        tail.clear(); // VA discontinuity: a match can't straddle a failed read
        // Don't blindly skip the whole 64KB chunk — a single inaccessible
        // page inside a readable region would drop signatures CE finds.
        // Re-query the sub-region at `pos`: skip only up to its end, or just
        // one 4KB page when the sub-region still claims to be readable (the
        // failure was a commit/protection race beyond the first page).
        MEMORY_BASIC_INFORMATION smbi{};
        std::uintptr_t next = pos + toRead;
        if (VirtualQueryEx(proc_, reinterpret_cast<LPCVOID>(pos), &smbi, sizeof(smbi))) {
          const std::uintptr_t sEnd =
              reinterpret_cast<std::uintptr_t>(smbi.BaseAddress) + smbi.RegionSize;
          const bool subOk = valueMode_
              ? (onlyWritable_ ? RegionWritable(smbi) : RegionReadable(smbi))
              : (onlyReadable_ ? RegionReadable(smbi)
                               : ((smbi.State == MEM_COMMIT) &&
                                  !(smbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))));
          next = subOk ? pos + 0x1000 : (sEnd > pos ? sEnd : pos + 0x1000);
        }
        if (next <= pos) next = pos + toRead; // never stall the walk
        pos = next > hi ? hi : next;
        continue;
      }
      chunk.resize(got);
      const std::size_t keep = tail.size() < overlap ? tail.size() : overlap;
      // window = tail(keep) + chunk(got); window[0] is at VA (pos - keep)
      std::vector<std::uint8_t> win;
      win.reserve(keep + got);
      win.insert(win.end(), tail.end() - static_cast<std::ptrdiff_t>(keep), tail.end());
      win.insert(win.end(), chunk.begin(), chunk.end());
      const std::uintptr_t winBase = pos - keep;
      // match starts that touch ≥1 new byte: i >= keep - overlap (clamped 0)
      const std::size_t firstI = keep > overlap ? keep - overlap : 0;
      if (win.size() >= patLen) {
        const std::size_t lastI = win.size() - patLen; // inclusive
        for (std::size_t i = firstI; i <= lastI; i++) {
          const std::uintptr_t va = winBase + i;
          if (va < start_ || va >= (end_ ? end_ : USER_TOP)) continue;
          if (valueMode_ && alignment_ > 1 && (va % alignment_) != 0) continue;
          if (MatchAt(win.data() + i)) hits_.push_back(va);
        }
      }
      // keep the last `overlap` bytes for the next iteration
      if (win.size() > overlap) tail.assign(win.end() - static_cast<std::ptrdiff_t>(overlap), win.end());
      else tail = std::move(win);
      pos += got; // short reads shrink the window, next read resumes at pos+got
    }
  }

  Napi::Promise::Deferred deferred_;
  DWORD pid_ = 0;
  HANDLE proc_ = nullptr;
  std::vector<PatternByte> pat_;
  std::vector<std::uint8_t> needle_;
  std::uintptr_t start_ = 0, end_ = 0;
  bool onlyReadable_ = true;
  bool valueMode_ = false;
  bool onlyWritable_ = false;
  std::size_t alignment_ = 0;
  std::vector<std::uintptr_t> hits_;
};

Napi::Value ScanAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  // scan(pid, pattern[, {start,end,onlyReadable}]) -> Promise<bigint[]>
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "expected (pid, pattern[, opts])").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  std::string pat = info[1].As<Napi::String>().Utf8Value();
  auto bytes = ParsePattern(pat);
  if (!bytes) {
    auto err = Napi::Error::New(env, "invalid pattern: expected hex bytes like \"DE AD ?? EF\"");
    err.Set("code", "INVALID_PATTERN");
    err.ThrowAsJavaScriptException();
    return env.Null();
  }

  std::uintptr_t start = 0, end = 0;
  bool onlyReadable = true;
  if (info.Length() > 2 && info[2].IsObject()) {
    auto o = info[2].As<Napi::Object>();
    if (o.Get("start").IsNumber()) start = static_cast<std::uintptr_t>(o.Get("start").As<Napi::Number>().DoubleValue());
    if (o.Get("end").IsNumber()) end = static_cast<std::uintptr_t>(o.Get("end").As<Napi::Number>().DoubleValue());
    if (o.Get("onlyReadable").IsBoolean()) onlyReadable = o.Get("onlyReadable").As<Napi::Boolean>().Value();
    // module/section ranges are resolved to start/end in the TS facade
  }

  auto deferred = Napi::Promise::Deferred::New(env);
  auto promise = deferred.Promise();
  auto* w = new ScanWorker(env, std::move(deferred), pid, std::move(*bytes), start, end, onlyReadable);
  w->Queue();
  return promise;
}

// scanValue(pid, needle[, {start,end,onlyWritable,alignment}]) -> Promise<bigint[]>
// `needle` is a Buffer/Uint8Array holding the little-endian value bytes.
Napi::Value ScanValueAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "expected (pid, needle[, opts])").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  if (!info[1].IsBuffer() && !info[1].IsTypedArray()) {
    Napi::TypeError::New(env, "needle must be a Buffer/Uint8Array").ThrowAsJavaScriptException();
    return env.Null();
  }
  std::vector<std::uint8_t> needle;
  if (info[1].IsBuffer()) {
    auto b = info[1].As<Napi::Buffer<std::uint8_t>>();
    needle.assign(b.Data(), b.Data() + b.Length());
  } else {
    auto ta = info[1].As<Napi::TypedArray>();
    const auto* p = static_cast<const std::uint8_t*>(ta.ArrayBuffer().Data()) + ta.ByteOffset();
    needle.assign(p, p + ta.ByteLength());
  }
  if (needle.empty() || needle.size() > 16) {
    Napi::RangeError::New(env, "needle must be 1..16 bytes").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::uintptr_t start = 0, end = 0;
  bool onlyWritable = true;
  std::size_t alignment = needle.size();
  if (info.Length() > 2 && info[2].IsObject()) {
    auto o = info[2].As<Napi::Object>();
    if (o.Get("start").IsNumber()) start = static_cast<std::uintptr_t>(o.Get("start").As<Napi::Number>().DoubleValue());
    if (o.Get("end").IsNumber()) end = static_cast<std::uintptr_t>(o.Get("end").As<Napi::Number>().DoubleValue());
    if (o.Get("onlyWritable").IsBoolean()) onlyWritable = o.Get("onlyWritable").As<Napi::Boolean>().Value();
    if (o.Get("onlyReadable").IsBoolean() && !o.Get("onlyWritable").IsBoolean())
      onlyWritable = !o.Get("onlyReadable").As<Napi::Boolean>().Value();
    if (o.Get("alignment").IsNumber()) {
      double a = o.Get("alignment").As<Napi::Number>().DoubleValue();
      if (a >= 1 && a <= 4096) alignment = static_cast<std::size_t>(a);
    }
  }

  auto deferred = Napi::Promise::Deferred::New(env);
  auto promise = deferred.Promise();
  auto* w = new ScanWorker(env, std::move(deferred), pid, std::move(needle),
                           start, end, onlyWritable, alignment);
  w->Queue();
  return promise;
}

} // namespace mp
