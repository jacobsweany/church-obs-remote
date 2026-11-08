#!/usr/bin/env python3
"""Send a single virtual key (CGEvent). Usage: zoom_key.py <keycode>"""
import sys, time
import ctypes
cg = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
cg.CGEventCreateKeyboardEvent.restype = ctypes.c_void_p
cg.CGEventCreateKeyboardEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
cg.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
cg.CFRelease.argtypes = [ctypes.c_void_p]
code = int(sys.argv[1])
down = cg.CGEventCreateKeyboardEvent(None, code, False)
up = cg.CGEventCreateKeyboardEvent(None, code, True)
cg.CGEventPost(0, down)
time.sleep(0.05)
cg.CGEventPost(0, up)
cg.CFRelease(down); cg.CFRelease(up)
print("key", code, "sent")
