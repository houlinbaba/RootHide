#!/usr/bin/env python3
"""RC7 Phase 6: actual-source guard checks + libzstd EOF-stream behavior tests.

IMPORTANT: this does not compile the Objective-C methods or exercise iOS filesystem APIs.
"""
import ctypes as C
import ctypes.util
from pathlib import Path

root = Path(__file__).resolve().parents[2]
src = (root/'Application/Dopamine/Jailbreak/DOBootstrapper.m').read_text()
update = (root/'BaseBin/launchdhook/src/update.m').read_text()
project = (root/'Application/Dopamine.xcodeproj/project.pbxproj').read_text()

def check(cond, message):
    assert cond, message

method = src.split('- (NSError *)decompressZstd:', 1)[1].split('- (NSError *)extractTar:',1)[0]
check(method.count('ZSTD_decompressStream(dstream, &out, &in)') == 1, 'zstd stream not examined')
check('if (total_bytes_read == 0 || ret != 0)' in method, 'missing truncated EOF guard')
check('if (fclose(output_file) != 0)' in method, 'missing delayed output close error check')
check(method.count('remove(tarPath.fileSystemRepresentation)') >= 9, 'missing partial output cleanup')
check('DOBootstrapper.m in Sources' in project, 'RC7 expected ObjC source absent')
check('DOBootstrapper+zstd.m in Sources' not in project, 'unexpected added decompressor build target')
install = src.split('-(int) InstallBootstrap:',1)[1].split('-(int) ReRandomizeBootstrap:',1)[0]
check('bootstrap-%@.tar' in install and 'NSUUID.UUID.UUIDString' in install, 'not using unique temporary tar path')
check(install.count('removeItemAtPath:bootstrapTarFile error:nil') >= 2, 'temp tar not removed on all extraction paths')
finalize = src.split('- (NSError *)finalizeBootstrap',2)[-1].split('- (NSError *)deleteBootstrap',1)[0]
check('Failed to save Bootstrap installation marker' in finalize, 'install marker failures suppressed')
delete = src.split('- (NSError *)deleteBootstrap',2)[-1].split('@end',1)[0]
check('contentsOfDirectoryAtPath:dirpath error:&error' in delete and 'if (!items)' in delete, 'uninstall enumeration failure ignored')
check('if (!newBasebinContents)' in update and 'return 7;' in update, 'basebin listing failure ignored')
check('![fileManager removeItemAtPath:oldBasebinPath error:&fileError]' in update and 'return 8;' in update, 'basebin removal failure ignored')
check('![fileManager copyItemAtPath:newBasebinPath toPath:oldBasebinPath error:&fileError]' in update and 'return 9;' in update, 'basebin copy failure ignored')
print('PASS: source-level Bootstrap/update contracts')

libname=ctypes_name=ctypes.util.find_library('zstd')
if not libname:
    print('SKIP: dynamic libzstd EOF behavior tests (libzstd not available); source guards passed')
    raise SystemExit(0)
lib=C.CDLL(libname)
Size=C.c_size_t
class InBuffer(C.Structure):
    _fields_=[('src',C.c_void_p),('size',Size),('pos',Size)]
class OutBuffer(C.Structure):
    _fields_=[('dst',C.c_void_p),('size',Size),('pos',Size)]
lib.ZSTD_createDStream.restype=C.c_void_p
lib.ZSTD_initDStream.argtypes=[C.c_void_p];lib.ZSTD_initDStream.restype=Size
lib.ZSTD_freeDStream.argtypes=[C.c_void_p];lib.ZSTD_freeDStream.restype=Size
lib.ZSTD_decompressStream.argtypes=[C.c_void_p,C.POINTER(OutBuffer),C.POINTER(InBuffer)];lib.ZSTD_decompressStream.restype=Size
lib.ZSTD_isError.argtypes=[Size];lib.ZSTD_isError.restype=C.c_uint
lib.ZSTD_compressBound.argtypes=[Size];lib.ZSTD_compressBound.restype=Size
lib.ZSTD_compress.argtypes=[C.c_void_p,Size,C.c_void_p,Size,C.c_int];lib.ZSTD_compress.restype=Size

def compress(payload):
    n=lib.ZSTD_compressBound(len(payload));dest=C.create_string_buffer(n)
    source=C.create_string_buffer(payload)
    got=lib.ZSTD_compress(dest,n,source,len(payload),3)
    assert not lib.ZSTD_isError(got)
    return dest.raw[:got]

def stream_valid(raw,chunk):
    ds=lib.ZSTD_createDStream();assert ds
    ret=lib.ZSTD_initDStream(ds)
    assert not lib.ZSTD_isError(ret)
    total=0
    output=bytearray()
    failed=False
    try:
        for offset in range(0,len(raw),chunk):
            part=raw[offset:offset+chunk]
            total+=len(part)
            inmem=C.create_string_buffer(part)
            ib=InBuffer(C.cast(inmem,C.c_void_p),len(part),0)
            while ib.pos<ib.size:
                outmem=C.create_string_buffer(8192)
                ob=OutBuffer(C.cast(outmem,C.c_void_p),8192,0)
                ret=lib.ZSTD_decompressStream(ds,C.byref(ob),C.byref(ib))
                if lib.ZSTD_isError(ret):
                    failed=True
                    break
                output+=outmem.raw[:ob.pos]
            if failed:break
    finally:
        lib.ZSTD_freeDStream(ds)
    return total>0 and ret==0 and not failed,bytes(output)

payload=(b'RC7 bootstrap frame compatibility check\x00'*5000)
archive=compress(payload)
for chunk in (1,7,59,8192):
    ok,data=stream_valid(archive,chunk)
    check(ok and data==payload,f'valid stream failed chunk={chunk}')
    print('PASS: valid zstd stream chunk',chunk)
for cut in (1,2,5,10):
    ok,_=stream_valid(archive[:-cut],8192)
    check(not ok, f'truncated zstd stream accepted, cut={cut}')
    print('PASS: truncated zstd stream rejected, cut',cut)
ok,_=stream_valid(b'',8192)
check(not ok, 'empty stream accepted')
print('PASS: empty stream rejected')
second=compress(b'frame two')
ok,out=stream_valid(archive+second,8192)
check(ok and out==payload+b'frame two','concatenated frames failed')
print('PASS: concatenated zstd frames')
print('PASS: 10 dynamic zstd stream scenarios')
