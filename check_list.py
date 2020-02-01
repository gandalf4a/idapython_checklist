# -*- coding: utf-8 -*-
"""
@author  : Gandalf4a
@file    : check_list.py 
@time    : 2019/11/20
@site    : www.gandalf.site
@software: ida_check

_ooOoo_
o8888888o
88" . "88
(| -_- |)  
O\  =  /O  $ sudo rm -rf /
/`---'\____
.'  \\|     |//  `.
/  \\|||  :  |||//  \
/  _||||| -:- |||||-  \
|   | \\\  -  /// |   |
| \_|  ''\-/''  |   |
\  .-\__  `-`  ___/-. /
___`. .'  /-.-\  `. . __
."" '<  `.___\_<|>_/___.'  >'"".
| | :  `- \`.;`\ _ /`;.`/ - ` : | |
\  \ `-.   \_ __\ /__ _/   .-` /  /
======`-.____`-.___\_____/___.-`____.-'======
"""
from idautils import *
from idaapi import *
import idc

def danger_func_check():
    print "-----------------------------------------------------------------"
    print "Do danger func check..."
    #danger func from: https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
    danger_func = ["alloca","_alloca","scanf","wscanf","sscanf","swscanf","vscanf","vsscanf","strlen","wcslen","strtok","strtok_r","wcstok","strcat","strncat","wcscat","wcsncat","strcpy","strncpy","wcscpy","wcsncpy","memcpy","wmemcpy","stpcpy","stpncpy","wcpcpy","wcpncpy","memmove","wmemmove","memcmp","wmemcmp","memset","wmemset","gets","sprintf","vsprintf","swprintf","vswprintf","snprintf","vsnprintf","realpath","getwd","wctomb","wcrtomb","wcstombs","wcsrtombs","wcsnrtombs"]
    _danger_func = danger_func
    s = '_'
    for i in xrange(len(danger_func)):
        _danger_func[i] = s + danger_func[i]
    total_danger_func = danger_func + _danger_func
    for func in Functions():
        func_name = GetFunctionName(func)
        if func_name in total_danger_func:
            print "danger_func_define: ".ljust(8),"\t", func_name.ljust(8), "\t", hex(func)[:-1]
            xrefs = CodeRefsTo(func, False)
            i=0
            for xref in xrefs:
                if GetMnem(xref).lower() == "call" or "BL":
                    if func_name in total_danger_func:
                        i=i+1
                        print format(i,'>5.0f')+".","\t","danger_func_call:".ljust(8),"\t", func_name.ljust(8),"\t", hex(xref)[:-1].ljust(8),"\t", GetFuncOffset(xref)
    print "Danger func check over."

def iOS_check():
    print "-----------------------------------------------------------------"
    print "It's iOS file, do iOS check..."
    iOS_NSlog = ["NSLog","_NSLog"]
    iOS_pseudo_random = ["rand","random","_rand","_random",]
    for func in Functions():
        func_name = GetFunctionName(func)
        if func_name in iOS_pseudo_random:
            print "iOS_pseudo_random_define: ".ljust(8),"\t", func_name.ljust(8), "\t", hex(func)[:-1]
            xrefs = CodeRefsTo(func, False)
            i=0
            for xref in xrefs:
                if GetMnem(xref).lower() == "call" or "BL":
                    if func_name in iOS_pseudo_random:
                        i=i+1
                        print  format(i,'>5.0f')+".","\t","iOS_pseudo_random_call:".ljust(8),"\t", func_name.ljust(8),"\t", hex(xref)  [:-1].ljust(8),"\t",GetFuncOffset(xref)
        if func_name in iOS_NSlog:
            print "iOS_NSlog_define: ".ljust(8),"\t", func_name.ljust(8), "\t", hex(func)[:-1]
            xrefs = CodeRefsTo(func, False)
            i=0
            for xref in xrefs:
                if GetMnem(xref).lower() == "call" or "BL":
                    if func_name in iOS_NSlog:
                        i=i+1
                        print  format(i,'>5.0f')+".","\t","iOS_NSlog_call:".ljust(8),"\t", func_name.ljust(8),"\t",hex(xref)[:-1].ljust(8),"\t", GetFuncOffset(xref)
    print "iOS check over."

def CreateProcessAsUserW_check():
    print "-----------------------------------------------------------------"
    print "Do CreateProcessAsUserW check.."
    print "加载路径中含有空格且不带引号的情况下可能导致歧义，如将c:\program files\sub dir\program name.exe解析为c:\program.exe"
    imports_name = ["CreateProcessAsUserW"]
    implist = idaapi.get_import_module_qty()
    for i in range(0, implist):
        name = idaapi.get_import_module_name(i)
        def imp_cb(ea, name, ord):
            if name in imports_name:
                print "danger_func_define:".ljust(8),"\t", "%08x: %s (ord#%d)" %(ea,name,ord)
                xrefs = CodeRefsTo(ea, False)
                i=0
                for xref in xrefs:
                    if GetMnem(xref).lower() == "call" or "BL":
                        i=i+1
                        print format(i,'>5.0f')+".","\t","danger_func_call:".ljust(8),"\t", name.ljust(8),"\t", hex(xref)[:-1].ljust(8),"\t", GetFuncOffset(xref)
            return True
        idaapi.enum_import_names(i, imp_cb)
    print "CreateProcessAsUserW check over."
    
def twos_compl(val, bits=32):
   """compute the 2's complement of int value val"""
   # if sign bit is set e.g., 8bit: 128-255 
   if (val & (1 << (bits - 1))) != 0: 
       val = val - (1 << bits)        # compute negative value
   return val                             # return positive value as is
   
def is_stack_buffer(addr, idx):
   inst = DecodeInstruction(addr)
   # IDA < 7.0
   try:
       ret = get_stkvar(inst[idx], inst[idx].addr) != None
   # IDA >= 7.0
   except:
       from ida_frame import *
       v = twos_compl(inst[idx].addr)
       ret = get_stkvar(inst, inst[idx], v)
   return ret
 
def find_arg(addr, arg_num):
    function_head = GetFunctionAttr(addr, idc.FUNCATTR_START)    # Get the start address of the function that we are in
    steps = 0
    arg_count = 0
    while steps < 100:    # It is unlikely the arguments are 100 instructions away, include this as a safety check
        steps = steps + 1
        addr = idc.PrevHead(addr)    # Get the previous instruction        
        op = GetMnem(addr).lower() # Get the name of the previous instruction
        # Check to ensure that we havent reached anything that breaks sequential code flow
        if op in ("ret", "retn", "jmp", "b") or addr < function_head:    
            return
        if op == "push":
            arg_count = arg_count + 1
            if arg_count == arg_num:
                return GetOpnd(addr, 0) # Return the operand that was pushed to the stack

def strcpy_buffer_check():
    print "-----------------------------------------------------------------"
    print "Do strcpy stack buffer check.."
    for functionAddr in Functions():
        if "strcpy" in GetFunctionName(functionAddr): # Check each function to look for strcpy
            xrefs = CodeRefsTo(functionAddr, False) 
            for xref in xrefs:                                    # Iterate over each cross-reference
                if GetMnem(xref).lower() == "call":  # Check to see if this cross-reference is a function call
                    opnd = find_arg(xref, 1) # Since the dest is the first argument of strcpy
                    function_head = GetFunctionAttr(xref, idc.FUNCATTR_START)
                    addr = xref
                    _addr = xref
                    while True:
                        _addr = idc.PrevHead(_addr)
                        _op = GetMnem(_addr).lower()
                        if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                            break
                        elif _op == "lea" and GetOpnd(_addr, 0) == opnd:
                        # We found the destination buffer, check to see if it is in the stack
                            if is_stack_buffer(_addr, 1):
                                print "STACK BUFFER STRCOPY FOUND at 0x%X" % addr 
                                break
                    # If we detect that the register that we are trying to locate comes from some other register 
                    # then we update our loop to begin looking for the source of the data in that other register
                        elif _op == "mov" and GetOpnd(_addr, 0) == opnd:
                            op_type = GetOpType(_addr, 1)
                            if op_type == o_reg:
                                opnd = GetOpnd(_addr, 1)
                                addr = _addr
                            else:
                                break
    print "Strcpy stack buffer check over.."

#def Android_so_check():

def main():
    idc.Wait()  
    print ["Check begin-----------------------------------------------------------------"]
    file_type = idaapi.get_file_type_name()
    print "It's",[file_type],"file."
    danger_func_check()
    #iOS_file = ["Fat Mach-O file, 1. ARMv7","Fat Mach-O file, 2. ARM64","Mach-O file (EXECUTE). ARM64","Mach-O file (EXECUTE). ARMv7","Mach-O file (EXECUTE). ARM","Mach-O file (EXECUTE). ARMv7s","Mach-O file (EXECUTE). ARMv6"]
    #Android_so_file = []
    if ("Mach-O file" in file_type) and ("ARM" in file_type):
        iOS_check()
    if "PE" in file_type:
        CreateProcessAsUserW_check()
    #if file_type in Android_so_file:
        #Android_so_check()
    strcpy_buffer_check()
    print "-----------------------------------------------------------------"
    print ["Check over-----------------------------------------------------------------"]
    idc.Exit(0)  

if __name__ == "__main__":
    main()
