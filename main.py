# -*- coding: utf-8 -*-
msg = '''
-----------------------------------------------------------------
@author  : Gandalf4a
@file    : main.py 
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
/  \\|||  :  |||//  \\
/  _||||| -:- |||||-  \\
|   | \\\  -  /// |   |
| \_|  ''\-/''  |   |
\  .-\__  `-`  ___/-. /
___`. .'  /-.-\  `. . __
."" '<  `.___\_<|>_/___.'  >'"".
| | :  `- \`.;`\ _ /`;.`/ - ` : | |
\  \ `-.   \_ __\ /__ _/   .-` /  /
======`-.____`-.___\_____/___.-`____.-'======
-----------------------------------------------------------------
'''
import os 
import magic
import subprocess
from zipfile import ZipFile
import sys
#reload(sys)
#sys.setdefaultencoding("utf-8")

#win需要修改路径'/'为'\\'

#idapython脚本路径
script_path = "./check_list.py"
#分析文件路径
_path = "."  
#日志文件路径
f = open ("./_check.log",'a+')
#ida路径
#ida32_path = "/Applications/IDA\ Pro\ 7.0/ida.app/Contents/MacOS//idat"
#ida64_path = "/Applications/IDA\ Pro\ 7.0/ida.app/Contents/MacOS//idat64"
ida32_path = "idat"
ida64_path = "idat64"
system = sys.platform

def unzip_zipfile():
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print ("Unzip file...")
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'/'+file_name
            file_type = magic.from_file(full_file_name)
            if "Zip archive data" in file_type:
                print ("unzip Zip file",full_file_name,"to",full_file_name[:-4],"...")
                zp = ZipFile(full_file_name,"r")
                zp.extractall(full_file_name[:-4])
    #zp.close()
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print('\n')

def win_unzip_zipfile():
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print ("Unzip file...")
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'\\'+file_name
            file_type = magic.from_file(full_file_name)
            if "Zip archive data" in file_type:
                print ("unzip Zip file",full_file_name,"to",full_file_name[:-4],"...")
                zp = ZipFile(full_file_name,"r")
                zp.extractall(full_file_name[:-4])
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print('\n')
    #zp.close()
 
def binary_file_list():
    bin_file = ["PE32","ELF","Mach-O"]
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'/'+file_name
            file_type = magic.from_file(full_file_name)
            for e in bin_file:
                if e in file_type:
                    if "64" in file_type:
                        print ("Analysis",full_file_name,"ing...")
                        #fat Mach-O 优先用64位ida
                        cmd = '{} -L{}_ida.log -c -A -S{} {}'.format(ida64_path,full_file_name.replace("/","_").replace(".","_"),script_path,full_file_name)
                        p = subprocess.Popen([cmd],shell=True)
                        p.wait()
                        print ("out：",full_file_name.replace("/","_").replace(".","_")+'_ida.log')
                        print('\n')
                    else:
                        print ("Analysis",full_file_name,"ing...")
                        cmd = '{} -L{}_ida.log -c -A -S{} {}'.format(ida32_path,full_file_name.replace("/","_").replace(".","_"),script_path,full_file_name)
                        p = subprocess.Popen([cmd],shell=True)
                        p.wait()
                        print ("out：",full_file_name.replace("/","_").replace(".","_")+'_ida.log')
                        print('\n')

def win_binary_file_list():
    bin_file = ["PE32","ELF","Mach-O"]
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'\\'+file_name
            file_type = magic.from_file(full_file_name)
            for e in bin_file:
                if e in file_type:
                    if "64" in file_type:
                        cmd = '{} -L{}_ida.log -c -A -S{} {}'.format(ida64_path,full_file_name.replace("\\","_").replace(".","_"),script_path,full_file_name)
                        print ("Analysis",full_file_name,"ing...")
                        p = subprocess.Popen(cmd,shell=True)
                        p.wait()
                        print( "out：",full_file_name.replace("\\","_").replace(".","_")+'_ida.log')
                        print('\n')
                    else:
                        cmd = '{} -L{}_ida.log -c -A -S{} {}'.format(ida32_path,full_file_name.replace("\\","_").replace(".","_"),script_path,full_file_name)
                        print ("Analysis",full_file_name,"ing...")
                        p = subprocess.Popen(cmd,shell=True)
                        p.wait()
                        print( "out：",full_file_name.replace("\\","_").replace(".","_")+'_ida.log')
                        print('\n')
                        
def iOS_compile_parameters_check():
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print ("iOS file compile parameters check...")
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'/'+file_name
            file_type = magic.from_file(full_file_name)
            if ("Mach-O" in file_type) and ("arm" in file_type):
                cmd_pie = 'otool -hv {} | grep PIE'.format(full_file_name)
                pie = subprocess.Popen([cmd_pie],shell=True,stdout=subprocess.PIPE)
                pie.wait()
                p = pie.stdout.read()
                if "PIE".encode() in p:
                    file_pie = "PIE ON!"
                else:
                    file_pie = "PIE OFF!"
                cmd_ssp = 'otool -Iv {} | grep stack'.format(full_file_name)
                ssp = subprocess.Popen([cmd_ssp],shell=True,stdout=subprocess.PIPE)
                ssp.wait()
                s = ssp.stdout.read()
                if ("stack_chk_guard".encode() in s) or ("stack_chk_fail".encode() in s):
                    file_ssp = "SSP ON!"
                else: 
                    file_ssp = "SSP OFF!"
                cmd_arc = 'otool -Iv {} | grep objc_releas'.format(full_file_name)
                arc = subprocess.Popen([cmd_arc],shell=True,stdout=subprocess.PIPE)
                arc.wait()
                a = arc.stdout.read()
                if "objc_releas".encode() in a:
                    file_arc = "ARC ON!"
                else:
                    file_arc = "ARC OFF!"
                print (file_pie.ljust(8),"\t",file_ssp.ljust(8),"\t",file_arc.ljust(8),"\t",full_file_name)
                print (file_pie.ljust(8),"\t",file_ssp.ljust(8),"\t",file_arc.ljust(8),"\t",full_file_name,file=f)
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print('\n',file=f)
    print('\n')

def win_file_check():
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print ("Win file check... ")
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'\\'+file_name
            file_type = magic.from_file(full_file_name)
            cmd = 'cacls {}'.format(full_file_name)
            p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
            p.wait()
            a = p.stdout.read()
            if "Everyone".encode() in a:
                everyone = "Everyone ON!"
            else:
                everyone = "Everyone OFF!"
            print (everyone.ljust(8),"\t",full_file_name)
            print (everyone.ljust(8),"\t",full_file_name, file=f)
    print ("-----------------------------------------------------------------")
    print ("-----------------------------------------------------------------",file=f)
    print('\n')

def rwrite_log():
    begin = "Check begin-----------------------------------------------------------------"
    over = "Check over-----------------------------------------------------------------"
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'/'+file_name
            file_type = magic.from_file(full_file_name)
            content = []
            recording = False
            if "_ida.log" in full_file_name:
                with open(full_file_name,'rb') as read_file:
                    for line in read_file:
                        line = line.strip()
                        if "File" in line.decode():
                            print(line.decode()[:-48],file=f)
                        if begin in line.decode():
                            recording = True
                        if recording :
                            content.append(line.decode())
                        if over in line.decode() :
                            break
                print('\n'.join(content),file=f)
                print('\n',file=f)
                print('\n',file=f)

def win_rwrite_log():
    begin = "Check begin-----------------------------------------------------------------"
    over = "Check over-----------------------------------------------------------------"
    for path,dir_list,file_list in os.walk(_path):  
        for file_name in file_list:  
            full_file_name = path+'\\'+file_name
            file_type = magic.from_file(full_file_name)
            content = []
            recording = False
            if "_ida.log" in full_file_name:
                with open(full_file_name,'rb') as read_file:
                    for line in read_file:
                        line = line.strip()
                        if "File" in line.decode():
                            print(line.decode()[:-48],file=f)
                        if begin in line.decode():
                            recording = True
                        if recording :
                            content.append(line.decode())
                        if over in line.decode() :
                            break
                print('\n'.join(content),file=f)
                print('\n',file=f)
                print('\n',file=f)
                
def main():
    print (msg)
    print (msg,file=f)
    print('\n')
    print ("-----------------------------------------------------------------",file=f)
    print ("-----------------------------------------------------------------")
    print ("System is:",system)
    print ("System is:",system,file=f)
    print ("-----------------------------------------------------------------",file=f)
    print ("-----------------------------------------------------------------")
    print('\n')
    print('\n',file=f)

    if system == "win32":
        win_unzip_zipfile()
        win_file_check()
        win_binary_file_list()
        win_rwrite_log()
    else:
        unzip_zipfile()
        if system == "darwin":
            iOS_compile_parameters_check()
        binary_file_list()
        rwrite_log()

if __name__ == "__main__":
    main()
