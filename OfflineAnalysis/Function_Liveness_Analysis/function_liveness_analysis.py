#
# ##############################################################################
# file:     function-liveness-analysis.py
# author:   mchen
# desc:     Offline analysis of XTaint log
#        XTaint log contains a series of pair marks of instruction 
#        CALL & RET
#
#        These pair marks could be nested, such that:
#
#           Call
#           Call
#           Call
#           Ret
#           Ret
#           Call
#           Ret
#           Ret
#
#        And need to figure out which marks are paired with each other, 
#        such that
#
#           Call   level 0
#               Call   level 1
#                   Call   level 2
#                   Ret    level 2
#               Ret    level 1
#               Call   level 1
#               Ret    level 1
#           Ret    level 0
#
#        Thus, we know which records in these pair marks belong to 
#        the same function, called function liveness analysis
#
#        Specifically, it need to:
#        1) determines pair marks
#        2) if there is no taint records between same pair marks, delete these
#            marks
#        
#        PS: The implementation algorithm essentially is same to determine
#        valid pairs of parenthesis.
# ##############################################################################
#

import os

DIR_PATH = "/home/user/Workspace-Ubuntu1004/Qemu/XTaint/Offline-Analysis/Function-Liveness-Analysis/"
# IN_FILE = "test6-function-linveness-analysis.txt"
# OUT_FILE = "test6-result-func-liveness-analysis.txt"

##IN_FILE = "DES-CBC-Aval-1Block-heap_gv_sv_stack.txt"
##OUT_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack.txt"

IN_FILE = "DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"
OUT_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"


in_file = open(DIR_PATH + IN_FILE, 'r')

CALL = "14"   # 14 is CALL inst
RET = "18"    # 18 is RET inst

level = 0                # level of nested function calls
simu_func_stack = []     # use stack to simulate the function call & ret
record = []              # use to store temporary record of file

line = in_file.readline()
record.append(line)
line = line.rstrip('\n')

while line != "":
    #################### 
    # case: CALL mark
    #################### 
    if line[:2] == CALL:                       
        # pop original CALL record, append again with level info
        record.pop()        
        record.append(line + "CALL level:" + str(level) + '\n')           

        # push CALL into stack
        simu_func_stack.append([CALL,level])          
        level += 1
        
    #################### 
    # case: RET mark
    ####################
    elif line[:2] == RET:
        # pop original RET record
        level -= 1
        record.pop()    

        # if last reocord is CALL mark
        #   if level is matched
        #       the empty matched pair cancele
        #   else
        #       append RET again with level info
        # else with taints between, append RET again with level info
        if simu_func_stack:
            if record[-1][:2] == CALL:
                if simu_func_stack.pop()[1] == level:
                    record.pop()
                else:
                    record.append("Error: RET is not matched to CALL\n")
                    record.append(line + "RET level:" + str(level) + '\n')
            else:
                record.append(line + "RET level:" + str(level) + '\n')
        else:
            record.append(line + "RET level:" + str(level) + '\n')
    
    line = in_file.readline()
    record.append(line)
    line = line.rstrip('\n')

in_file.close()
print("finish parse, write to file...")
      
out_file = open(DIR_PATH + OUT_FILE, 'w')
for item in record:
##    print(item, end='')
    out_file.write(item)
out_file.close()
print("finish write file...")
