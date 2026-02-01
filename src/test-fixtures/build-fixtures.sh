#!/bin/bash
# Build script for aldur test fixtures

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=== Building aldur test fixtures ==="

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

success() { echo -e "${GREEN}✓${NC} $1"; }
info() { echo -e "${YELLOW}→${NC} $1"; }

mkdir -p elf pe

# ELF binaries
info "Building ELF fixtures..."

gcc -o elf/hardened test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=2 2>/dev/null && success "elf/hardened"
gcc -o elf/no_pie test.c -O2 -no-pie -fno-PIE -Wl,-z,relro,-z,now -fstack-protector-strong 2>/dev/null && success "elf/no_pie"
gcc -o elf/exec_stack test.c -O2 -fPIE -pie -Wl,-z,execstack -Wl,-z,relro,-z,now 2>/dev/null && success "elf/exec_stack"
gcc -o elf/no_relro test.c -O2 -fPIE -pie -Wl,-z,norelro 2>/dev/null && success "elf/no_relro"
gcc -o elf/partial_relro test.c -O2 -fPIE -pie -Wl,-z,relro -Wl,-z,lazy 2>/dev/null && success "elf/partial_relro"
gcc -o elf/no_stack_protector test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -fno-stack-protector 2>/dev/null && success "elf/no_stack_protector"
gcc -o elf/with_rpath test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -Wl,-rpath,/tmp/lib 2>/dev/null && success "elf/with_rpath"
gcc -o elf/with_runpath test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -Wl,--enable-new-dtags -Wl,-rpath,/opt/lib 2>/dev/null && success "elf/with_runpath"
gcc -o elf/static_binary test.c -O2 -static -fstack-protector-strong 2>/dev/null && success "elf/static_binary"
gcc -o elf/with_debug test.c -O0 -g -fPIE -pie -Wl,-z,relro,-z,now -fstack-protector-strong 2>/dev/null && success "elf/with_debug"
gcc -o elf/no_optimization test.c -O0 -g -fPIE -pie -Wl,-z,relro,-z,now 2>/dev/null && success "elf/no_optimization"
gcc -o elf/high_optimization test.c -O3 -march=native -fPIE -pie -Wl,-z,relro,-z,now -fstack-protector-strong 2>/dev/null && success "elf/high_optimization"
gcc -o elf/with_lto test.c -O2 -flto -fPIE -pie -Wl,-z,relro,-z,now -fstack-protector-strong 2>/dev/null && success "elf/with_lto"
gcc -o elf/with_cet test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -fcf-protection=full -fstack-protector-strong 2>/dev/null && success "elf/with_cet"
gcc -o elf/stripped test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -s 2>/dev/null && success "elf/stripped"
gcc -o elf/fortified test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -fstack-protector-strong 2>/dev/null && success "elf/fortified"
gcc -o elf/no_fortify test.c -O2 -fPIE -pie -Wl,-z,relro,-z,now -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 2>/dev/null && success "elf/no_fortify"

# PE binaries via MinGW
info "Building PE fixtures..."

cat > /tmp/test_win.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <windows.h>
void vulnerable_function(char *input) { char buffer[64]; strcpy(buffer, input); printf("%s\n", buffer); }
int main(int argc, char *argv[]) { if (argc > 1) vulnerable_function(argv[1]); return 0; }
EOF

MINGW=x86_64-w64-mingw32-gcc

$MINGW -o pe/hardened.exe /tmp/test_win.c -O2 -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat -fstack-protector-strong 2>/dev/null && success "pe/hardened.exe"
$MINGW -o pe/no_aslr.exe /tmp/test_win.c -O2 -Wl,--disable-dynamicbase -Wl,--nxcompat 2>/dev/null && success "pe/no_aslr.exe"
$MINGW -o pe/no_high_entropy.exe /tmp/test_win.c -O2 -Wl,--dynamicbase -Wl,--disable-high-entropy-va -Wl,--nxcompat 2>/dev/null && success "pe/no_high_entropy.exe"
$MINGW -o pe/no_nx.exe /tmp/test_win.c -O2 -Wl,--dynamicbase -Wl,--disable-nxcompat 2>/dev/null && success "pe/no_nx.exe"
$MINGW -o pe/no_stack_protector.exe /tmp/test_win.c -O2 -Wl,--dynamicbase -Wl,--nxcompat -fno-stack-protector 2>/dev/null && success "pe/no_stack_protector.exe"
$MINGW -o pe/console_app.exe /tmp/test_win.c -O2 -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat -fstack-protector-strong 2>/dev/null && success "pe/console_app.exe"
$MINGW -o pe/stripped.exe /tmp/test_win.c -O2 -s -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat 2>/dev/null && success "pe/stripped.exe"
$MINGW -o pe/with_debug.exe /tmp/test_win.c -O0 -g -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat 2>/dev/null && success "pe/with_debug.exe"

cat > /tmp/gui_test.c << 'EOF'
#include <windows.h>
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int s) { MessageBoxA(NULL, "Hi", "Test", MB_OK); return 0; }
EOF
$MINGW -o pe/gui_app.exe /tmp/gui_test.c -O2 -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat -mwindows -fstack-protector-strong 2>/dev/null && success "pe/gui_app.exe"

cat > /tmp/dll_test.c << 'EOF'
#include <windows.h>
__declspec(dllexport) int add(int a, int b) { return a + b; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) { return TRUE; }
EOF
$MINGW -shared -o pe/test_lib.dll /tmp/dll_test.c -O2 -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat -fstack-protector-strong 2>/dev/null && success "pe/test_lib.dll"

rm -f /tmp/test_win.c /tmp/gui_test.c /tmp/dll_test.c

echo ""
echo "=== Validation ==="
echo ""
echo "ELF fixtures:"
printf "%-22s %-6s %-9s %-6s %-8s\n" "Binary" "PIE" "RELRO" "NX" "SSP"
echo "----------------------------------------------------"
for f in elf/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    pie=$(readelf -h "$f" 2>/dev/null | grep -q "DYN" && echo "yes" || echo "NO")
    relro=$(readelf -l "$f" 2>/dev/null | grep -q GNU_RELRO && (readelf -d "$f" 2>/dev/null | grep -q BIND_NOW && echo "full" || echo "partial") || echo "NO")
    nx=$(readelf -l "$f" 2>/dev/null | grep GNU_STACK | grep -q "RWE" && echo "NO" || echo "yes")
    ssp=$(readelf -s "$f" 2>/dev/null | grep -q "__stack_chk" && echo "yes" || echo "NO")
    printf "%-22s %-6s %-9s %-6s %-8s\n" "$name" "$pie" "$relro" "$nx" "$ssp"
done

echo ""
echo "PE fixtures:"
printf "%-22s %-6s %-12s %-8s\n" "Binary" "ASLR" "HIGH_ENTROPY" "NX"
echo "----------------------------------------------------"
for f in pe/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    chars=$(x86_64-w64-mingw32-objdump -p "$f" 2>/dev/null | grep -A5 "DllCharacteristics")
    aslr=$(echo "$chars" | grep -qi "DYNAMIC_BASE" && echo "yes" || echo "NO")
    heva=$(echo "$chars" | grep -qi "HIGH_ENTROPY" && echo "yes" || echo "NO")
    nx=$(echo "$chars" | grep -qi "NX_COMPAT" && echo "yes" || echo "NO")
    printf "%-22s %-6s %-12s %-8s\n" "$name" "$aslr" "$heva" "$nx"
done

echo ""
success "Built $(ls elf | wc -l) ELF and $(ls pe | wc -l) PE fixtures"
