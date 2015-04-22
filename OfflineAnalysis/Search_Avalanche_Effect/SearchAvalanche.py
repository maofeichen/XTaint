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
xtaint_buffer_set_list = []

def preprocess():
    """pre-process XTaint log.
    
    Args:
        global constant - path of XTaint log
    Returns:
        save in the list that contains all XTaint log records, such as:
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
            words = line.split()
            if words[0] == CALL:
                """
                example words:
                    list: ['14', '0', '0', 'CALL', 'level:-215']
                needs to save func_addr ('0') and 'level:-215'
                """
                call = {}
                call['CALL'] = {'func_addr':words[1], 'level':words[4]}
                xtaint_log_list.append(call)
            elif words[0] == RET:
                """
                example words: 
                    list: ['18', '0', '0', 'RET', 'level:-1']
                only needs to save "RET" and "level:-1"
                """
                ret = {}
                ret['RET'] = {'level':words[4]}
                xtaint_log_list.append(ret)
            else:
                """normal record"""
                pair = {}
                pair['src'] = \
                    {'flag':words[0], 'addr':words[1], 'val':words[2]}
                pair['dest'] = \
                    {'flag':words[3], 'addr':words[4], 'val':words[5]}
                record = {'record':pair, 'is_in_set': "FALSE"}
                xtaint_log_list.append(record);

    xt_log_fp.close()

def create_buffer_set():
    """create sets of buffers for each function call.
    Args:
        global - xtaint_log_list
    Return:
        save in xtaint_buffer_set_list as:
            [[], [], [],...]
        each nested list contains members of the set
    Algorithm:
        copy xtaint_log_list in to local list
        scan the local list, repeat until end:
            look for "RET" records, if found:
                look for its matched "CALL" record, if found:
                    save all normal records between
                    delete the normal records in between, as well as
                        the paired CALL and RET
                Otherwise, continue look for next "RET"
    """
    local_xt_log_list = list(xtaint_log_list)

    item_index = 0
    for item in local_xt_log_list:
        if "RET" in item:
#             print(item)
            is_match_found = False

            """scan backwards to look for its matched CALL"""
            prev_item_index = item_index - 1
            while prev_item_index >= 0:
                prev_item = local_xt_log_list[prev_item_index]
                if "CALL" in prev_item and \
                        prev_item['CALL']['level'] == item['RET']['level']:
                    is_match_found = True
                    break
                prev_item_index -= 1

            if is_match_found:
                """if found, add records between to set"""
#                 print("found a match")
                buffer_set = [prev_item, prev_item_index, item, item_index]
                for record in local_xt_log_list[prev_item_index:item_index]:
                    if "RET" not in record and\
                            "CALL" not in record and \
                            record['is_in_set'] == "FALSE":
                        record['is_in_set'] = "TRUE"

                        """only save if src or dest is memory addr"""
                        if len(record['record']['src']['addr']) == 8:
                            buffer_set.append(record['record']['src'])
                        elif len(record['record']['dest']['addr']) == 8:
                            buffer_set.append(record['record']['dest'])
                            
                xtaint_buffer_set_list.append(buffer_set)
                
#             else: print("matched CALL not found")
            
        item_index += 1
        
def main():
    preprocess()
#     for record in xtaint_log_list:
#         print(record)
    create_buffer_set()
    for member in xtaint_buffer_set_list:
        for record in member:
            print(record)
 
if __name__ == '__main__':
    main()
