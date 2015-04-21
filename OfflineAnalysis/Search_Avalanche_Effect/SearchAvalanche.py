'''
file:
    SearchAvalanche.py
    
desc:
    Search the avalanche effect in the XTaint log. The main procedure can
    be divided into 3 components:
        * Determine Path - determines if there is a path between any
            given src and dest in a XTaint log
        * Create Sets of Buffers - creates sets of buffers within the 
            same function call (matched CALL & RET instructions)
        * Search Avalanche Effect - searches avalanche effect based on
            the sets of buffers
@author: mchen
'''

XTAINT_LOG_DIR = "/home/mchen/Workspace-Linuxmint/XTaint/Result/"
XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"

CALL = "14"   # 14 is CALL instruction
RET = "18"    # 18 is RET instruction

xtaint_log_list = []

def preprocess():
    """pre-process XTaint log.
    
    input:
        path of XTaint log
    output:
        generate a list that contains all XTaint log records, such as:
            [{}, {}, {},...]
            each sub-dictonary is either normal record or CALL or RET record,
            form as dictionary:
            * normal record:
                {record: {flag: <flag>, addr: <addr>, val: <val>} }
            * CALL or RET instruction record:
                {CALL: {func_addr: <func_addr>, level: <level>} }
                {RET: {level: <level>} }
    """
    with open(XTAINT_LOG_DIR + XTAINT_LOG_FILE, 'r') as xt_log_fp:
        for line in xt_log_fp:
            if line[:2] == CALL:
                words = line.split()
                """
                example:
                    list: ['14', '0', '0', 'CALL', 'level:-215']
                needs to save func_addr ('0') and 'level:-215'
                """
                call = {}
                call['CALL'] = {'func_addr':words[1], 'level':words[4]}
                xtaint_log_list.append(call)
            elif line[:2] == RET:
                words = line.split()
                """
                example: 
                    list: ['18', '0', '0', 'RET', 'level:-1']
                only needs to save "RET" and "level:-1"
                """
                ret = {}
                ret['RET'] = {'level':words[4]}
                xtaint_log_list.append(ret)
            else:
                """normal record"""
                words = line.split()
                """break line into words"""
                pair = {}
                pair['src'] = \
                    {'flag':words[0], 'addr':words[1], 'val':words[2]}
                pair['dest'] = \
                    {'flag':words[3], 'addr':words[4], 'val':words[5]}
                record = {'record':pair}
                xtaint_log_list.append(record);

    xt_log_fp.close()
    
def main():
    preprocess()
    for record in xtaint_log_list:
        print(record)
 
if __name__ == '__main__':
    main()
