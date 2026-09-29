#!/bin/bash
# ============================================================================
# IPA分析器 —— Linux 交叉编译，产出「未签名裸 raw.ipa」
# host=linux target=arm64-apple-ios16.0
#   复用已验证的 iOS SDK 模块缓存(mcapp)规避 Dispatch overlay 问题
#   swiftc 交叉编译 + ld64.lld 链接 -> arm64 Mach-O
#   手动搭建 Payload/IPAAnalyzer.app + 规范化 zip -> 裸 IPA
#   设备端由 SideStore / AltStore 本地完成签名安装。
# ============================================================================
set -euo pipefail

APP_NAME="IPAAnalyzer"
DEPLOY="16.0"; SDK_VER="16.4"
TARGET="arm64-apple-ios${DEPLOY}"
MARK_VER="1.3.0"; CUR_VER="4"

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="${ROOT}/build-linux"
APP="${BUILD}/Payload/${APP_NAME}.app"
OUT_IPA="${BUILD}/${APP_NAME}-${MARK_VER}-raw-unsigned.ipa"

TC=/home/user/.doubao/agent_mode/workspace/toolchain/swift-5.8-RELEASE-ubuntu22.04/usr
SDK=/home/user/.doubao/agent_mode/workspace/toolchain/iPhoneOS16.4.sdk
SWIFTC="$TC/bin/swiftc"
# 复用已验证成功的模块缓存（含预编译 Dispatch/Foundation/UIKit，规避 overlay+apinotes 问题）
MC=/home/user/.doubao/agent_mode/workspace/ClipboardHistoryApp/build-linux/mcapp
LDID=/home/user/.doubao/agent_mode/workspace/toolchain/bin/ldid

[[ -x "$SWIFTC" ]] || { echo "❌ 未找到 swiftc"; exit 1; }
[[ -d "$SDK" ]] || { echo "❌ 未找到 iOS SDK"; exit 1; }
[[ -x "$LDID" ]] || { echo "❌ 未找到 ldid"; exit 1; }

# ---- ld 包装：swiftc 链接时默认调 /usr/bin/ld(GNU)，需转 ld64.lld ----
LINKBIN="$BUILD/linkbin"; mkdir -p "$LINKBIN"
cat > "$LINKBIN/ld" <<EOF
#!/bin/bash
exec "$TC/bin/ld64.lld" "\$@"
EOF
chmod +x "$LINKBIN/ld"
export PATH="$LINKBIN:$TC/bin:$PATH"

# ---- resource-dir（绝对路径，剔除冲突模块 + apinotes）----
RES="$BUILD/resource-dir"
if [[ ! -f "$RES/.prepared" ]]; then
  rm -rf "$RES"; mkdir -p "$RES"
  cp -R "$TC/lib/swift/"*.swift "$RES/" 2>/dev/null || true
  cp -R "$TC/lib/swift/linux" "$RES/" 2>/dev/null || true
  rm -rf "$RES/dispatch" "$RES/os" "$RES/CoreFoundation" "$RES/Block" "$RES/linux" 2>/dev/null || true
  CLANG_VER="$(ls "$TC/lib/clang" | head -1)"
  mkdir -p "$RES/clang"
  cp -R "$TC/lib/clang/${CLANG_VER}/include" "$RES/clang/" 2>/dev/null || true
  mkdir -p "$RES/apinotes"
  for ap in Dispatch.apinotes os.apinotes; do
    for cand in /home/user/.doubao/agent_mode/workspace/toolchain/swift-apinotes/apinotes/$ap; do
      [[ -f "$cand" ]] && cp "$cand" "$RES/apinotes/" && break
    done
  done
  touch "$RES/.prepared"
fi

# ---- zlib 辅助 C 模块 ----
mkdir -p "$BUILD/includemod"
cp "$ROOT/zlib/module.modulemap" "$BUILD/includemod/"
cp "$ROOT/zlib/zinflate.h" "$BUILD/includemod/"
"$TC/bin/clang" -target arm64-apple-ios16.0 -isysroot "$SDK" -O2 -c \
  "$ROOT/zlib/zinflate.c" -o "$BUILD/zinflate.o"

# ---- 编译主程序 ----
rm -rf "$APP"; mkdir -p "$APP"
echo "==> swiftc 交叉编译主程序"
mapfile -t SRCS < <(find "$ROOT/Sources" -name '*.swift' | sort)
"$SWIFTC" -target "$TARGET" -sdk "$SDK" -resource-dir "$RES" -O -parse-as-library \
  -Xcc -fmodules-cache-path="$MC" -I "$BUILD/includemod" \
  -module-name "$APP_NAME" -emit-executable \
  -Xlinker -adhoc_codesign -Xlinker -platform_version -Xlinker ios -Xlinker "$DEPLOY.0" -Xlinker "$SDK_VER" \
  -o "$APP/$APP_NAME" "$BUILD/zinflate.o" \
  -Xlinker -L -Xlinker "$SDK/usr/lib" -Xlinker -lz \
  "${SRCS[@]}"

# ---- ldid 嵌入 ad-hoc 签名（空 entitlements），SideStore 可重签 ----
echo "==> ldid 签名"
printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict/></plist>\n' > "$BUILD/empty.entitlements"
"$LDID" -S"$BUILD/empty.entitlements" "$APP/$APP_NAME"

# ---- 组装 Bundle ----
echo "==> 组装 Info.plist / PkgInfo"
sed -e "s/\\\$(EXECUTABLE_NAME)/$APP_NAME/g" -e "s/\\\$(PRODUCT_MODULE_NAME)/$APP_NAME/g" \
    -e "s/\\\$(PRODUCT_NAME)/$APP_NAME/g" -e "s/\\\$(PRODUCT_BUNDLE_IDENTIFIER)/com.ipaanalyzer.app/g" \
    -e "s/\\\$(MARKETING_VERSION)/${MARK_VER}/g" -e "s/\\\$(CURRENT_PROJECT_VERSION)/${CUR_VER}/g" \
    "$ROOT/Resources/Info.plist" > "$APP/Info.plist"
printf 'APPL????' > "$APP/PkgInfo"

# 补齐 installd 校验所需标准键
python3 - "$DEPLOY" "$SDK_VER" "$APP/Info.plist" <<'PY'
import sys, plistlib
minos, sdkver, path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path,"rb") as f: pl=plistlib.load(f)
std={"MinimumOSVersion":minos,"CFBundleSupportedPlatforms":["iPhoneOS"],
     "DTPlatformName":"iphoneos","DTPlatformVersion":sdkver,
     "DTSDKName":f"iphoneos{sdkver}","DTCompiler":"com.apple.compilers.llvm.clang.1_0"}
for k,v in std.items(): pl.setdefault(k,v)
with open(path,"wb") as f: plistlib.dump(pl,f,fmt=plistlib.FMT_XML)
PY

# 生成散件图标
python3 - "$APP" "$ROOT/Resources/Icon-1024.png" <<'PY'
import sys
from PIL import Image
app,src=sys.argv[1],sys.argv[2]
im=Image.open(src).convert("RGB")
specs=[("Icon-20","@2x",40),("Icon-20","@3x",60),("Icon-20~ipad","",20),("Icon-20@2x~ipad","",40),
("Icon-29","@2x",58),("Icon-29","@3x",87),("Icon-29~ipad","",29),("Icon-29@2x~ipad","",58),
("Icon-40","@2x",80),("Icon-40","@3x",120),("Icon-40~ipad","",40),("Icon-40@2x~ipad","",80),
("Icon-60","@2x",120),("Icon-60","@3x",180),("Icon-76~ipad","",76),("Icon-76@2x~ipad","",152),
("Icon-83.5@2x~ipad","",167),("Icon-1024","",1024)]
for base,suf,size in specs:
    im.resize((size,size),Image.LANCZOS).save(f"{app}/{base}{suf}.png","PNG",optimize=True)
PY

# ---- Mach-O 校验 ----
echo "==> Mach-O 校验"
python3 - "$APP" "$APP_NAME" <<'PY'
import struct,sys,os
app,bname=sys.argv[1],sys.argv[2]
d=open(os.path.join(app,bname),'rb').read()
magic,cput,sub,ft,n=struct.unpack('<IiiII',d[:20])
assert magic==0xfeedfacf and cput==0x0100000c, "非 arm64 Mach-O64"
assert ft==2, f"filetype={ft}，期望 MH_EXECUTE"
off=32;plat=None;sig=None;enc=None
for _ in range(n):
    cmd,cs=struct.unpack('<II',d[off:off+8])
    if cmd==0x32: plat=struct.unpack('<I',d[off+8:off+12])[0]
    if cmd==0x1d: sig=struct.unpack('<II',d[off+8:off+16])
    if cmd in (0x21,0x2c): enc=struct.unpack('<I',d[off+16:off+20])[0]
    off+=cs
assert plat==2, "平台非 iOS"
assert sig and sig[1]>0, "缺少 LC_CODE_SIGNATURE"
assert enc==0, "不应加密"
print(f"  ✓ {bname} arm64/iOS/MH_EXECUTE + ad-hoc签名槽({sig[1]}B)")
PY

# ---- 规范化打包裸 IPA ----
echo "==> 规范化打包 IPA"
rm -f "$OUT_IPA"
python3 - "$BUILD" "$OUT_IPA" "$APP_NAME" <<'PY'
import sys, os, zipfile
build, out, app_name = sys.argv[1], sys.argv[2], sys.argv[3]
root = os.path.join(build, "Payload")
exec_names = {app_name}
fixed = (2024, 1, 1, 0, 0, 0)

def add_dir(zf, arc):
    zi = zipfile.ZipInfo(arc + "/", fixed)
    zi.create_system = 3
    zi.external_attr = (0o40755 << 16) | 0o040000
    zi.compress_type = zipfile.ZIP_STORED
    zf.writestr(zi, b"")

entries = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort(); filenames.sort()
    rel_dir = os.path.relpath(dirpath, build)
    if rel_dir != ".":
        entries.append(("dir", rel_dir, None))
    for fn in filenames:
        full = os.path.join(dirpath, fn)
        arc = os.path.relpath(full, build)
        entries.append(("file", arc, full))

entries.sort(key=lambda e: (e[1].count("/"), e[1]))
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=False) as zf:
    seen = set()
    for kind, arc, full in entries:
        parts = arc.split("/")[:-1]
        for i in range(len(parts)):
            d = "/".join(parts[:i+1])
            if d not in seen: add_dir(zf, d); seen.add(d)
        if kind == "dir":
            if arc not in seen: add_dir(zf, arc); seen.add(arc)
            continue
        zi = zipfile.ZipInfo(arc, fixed)
        zi.create_system = 3
        base = os.path.basename(arc)
        mode = 0o755 if base in exec_names else 0o644
        zi.external_attr = (mode << 16) | 0o100000
        zi.compress_type = zipfile.ZIP_DEFLATED
        with open(full, "rb") as f:
            zf.writestr(zi, f.read(), compress_type=zipfile.ZIP_DEFLATED)

with zipfile.ZipFile(out) as z:
    bad = z.testzip(); assert bad is None
    n = len(z.namelist())
raw = open(out, "rb").read()
assert raw.rfind(b"PK\x05\x06") == len(raw) - 22, "EOCD 不在末尾"
assert b"PK\x06\x06" not in raw, "不应含 zip64"
print(f"  ✓ 规范化 zip 完成：{n} 条目")
PY
echo "✅ 完成: ${OUT_IPA}"
ls -lh "$OUT_IPA"
shasum -a 256 "$OUT_IPA" | awk '{print "SHA256:",$1}'
