#!/usr/bin/env python3

"""
Provide a Python interface to the statfs(1) syscall as defined in
GNU/Linux 5.8.0.

Usage:
  import statfs
  statfs.load_statfs()
  stat_result = statfs.statfs(path)
"""

import argparse
import logging
import os
import sys

import cffi

# pystatfs ffi and lib; populated by load_statfs()
statfs_ffi = None
statfs_lib = None

logging.basicConfig(format="%(module)s:%(lineno)s: %(levelname)s: %(message)s",
                    level=logging.INFO)
logger = logging.getLogger(__name__)

STATFS_FFI = "pystatfs"

STATFS_FFI_CDEF = """
typedef long __fsword_t;
typedef unsigned long __fsblkcnt_t;
typedef unsigned long __fsfilcnt_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long __fsword_t;

struct statfs {
    __fsword_t f_type;
    __fsword_t f_bsize;
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsfilcnt_t f_files;
    __fsfilcnt_t f_ffree;
    __fsid_t f_fsid;
    __fsword_t f_namelen;
    __fsword_t f_frsize;
    __fsword_t f_flags;
    __fsword_t f_spare[4];
};

extern int statfs(const char* path, struct statfs* stat);
"""

STATFS_FFI_CODE = """
struct statfs {
    __fsword_t f_type;
    __fsword_t f_bsize;
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsfilcnt_t f_files;
    __fsfilcnt_t f_ffree;
    __fsid_t f_fsid;
    __fsword_t f_namelen;
    __fsword_t f_frsize;
    __fsword_t f_flags;
    __fsword_t f_spare[4];
};

extern int statfs(const char* path, struct statfs* stat);
"""

ishex = lambda s: all(c in "1234567890abcdef" for c in s.lower().lstrip("0x"))

def _macros_from(path):
  if os.path.exists(path):
    with open(path, "rt") as fobj:
      for line in fobj:
        pieces = line.split()
        if len(pieces) >= 3 and pieces[0] == "#define":
          name, value = pieces[1], pieces[2]
          if ishex(value):
            yield "#define {} {}".format(pieces[1], pieces[2])

def load_statfs(tmpdir=os.getcwd()):
  "Populate statfs_ffi and statfs_lib, generating them if needed"
  global statfs_ffi, statfs_lib
  verbose = logger.getEffectiveLevel() <= logging.DEBUG
  ffibuilder = cffi.FFI()
  cdef = STATFS_FFI_CDEF
  code = STATFS_FFI_CODE
  for mdef in _macros_from("/usr/include/linux/magic.h"):
    cdef += mdef + "\n"
    code += mdef + "\n"
  logger.debug("CDEF: {}".format(cdef))
  logger.debug("Code: {}".format(code))
  ffibuilder.cdef(cdef)
  ffibuilder.set_source(STATFS_FFI, code)
  ffibuilder.compile(verbose=verbose, tmpdir=tmpdir)
  import pystatfs
  statfs_ffi = pystatfs.ffi
  statfs_lib = pystatfs.lib

def statfs(path):
  "Invoke the Linux statfs() syscall; raises OSError on error"
  p = statfs_ffi.new("struct statfs*")
  rc = statfs_lib.statfs(path.encode("UTF-8"), p)
  if rc == -1:
    raise OSError(statfs_ffi.errno, os.strerror(statfs_ffi.errno), path)
  fields = statfs_ffi.typeof(p).item.fields
  return dict((field, getattr(p, field)) for field, fdef in fields)

def statfs_get_type(stats):
  "Get the filesystem type macro from the given statfs value"
  for t in dir(statfs_lib):
    if t.endswith("_MAGIC"):
      if stats["f_type"] == getattr(statfs_lib, t):
        return t

def main():
  global statfs_ffi, statfs_lib
  ap = argparse.ArgumentParser()
  ap.add_argument("path", nargs="+", help="device path(s)")
  ap.add_argument("-t", "--tmpdir", metavar="PATH", default=os.getcwd(), help="temporary directory (default: cwd)")
  ap.add_argument("-v", "--verbose", action="store_true", help="verbose output")
  args = ap.parse_args()
  if args.verbose:
    logger.setLevel(logging.DEBUG)
  load_statfs()
  for path in args.path:
    stats = statfs(path)
    fstype = statfs_get_type(stats)
    print("{!r}: type {}:".format(path, fstype))
    print(stats)

if __name__ == "__main__":
  main()

# vim: set ts=2 sts=2 sw=2:
