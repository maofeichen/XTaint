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

from operator import itemgetter

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
                """if found, add records of same function to set"""
#                 print("found a match")
                buffers = {}
                
                call_mark = prev_item.copy()
                call_mark['CALL']['line_num'] = prev_item_index
                ret_mark = item.copy()
                ret_mark['RET']['line_num'] = item_index
                buffer_head = [call_mark, ret_mark]
                buffers['head'] = buffer_head
                
                buffers['buffer'] = []
                for record in local_xt_log_list[prev_item_index:item_index]:
                    if "RET" not in record and\
                            "CALL" not in record and \
                            record['is_in_set'] == "FALSE":
                        record['is_in_set'] = "TRUE"

                        """only save if src or dest is memory addr"""
                        if len(record['record']['src']['addr']) == 8:
                            mem_cell = {'flag':record['record']['src']['flag'],\
                                        'addr':int(record['record']['src']['addr'],16),\
                                        'val':record['record']['src']['val']}
                            buffers['buffer'].append(mem_cell)
                            
                        elif len(record['record']['dest']['addr']) == 8:
                            mem_cell = {'flag':record['record']['dest']['flag'],\
                                        'addr':int(record['record']['dest']['addr'],16),\
                                        'val':record['record']['dest']['val']}
                            buffers['buffer'].append(mem_cell)
                            
                xtaint_buffer_set_list.append(buffers)
                
#             else: print("matched CALL not found")
            
        item_index += 1

def sort_buffer_set():    
    """for all memory buffers in the same function call, sort them via 'addr'
    Args:
        global - xtaint_buffer_set_list
    Return:
        save results in xtaint_buffer_set_list
    
    (Needs to be called after create_buffer_set)
    At this time the xtaint_buffer_set_list forms as:
        [{'head':[{'CALL':{} }, {'RET':{} } ], 'buffer':[{}, {}, ...] }, {}, ...]
    each member of the list is a dictionary, with key head and buffer; the 
    value of buffer is a list, which contains all the 
        {'flag':<>, 'addr':<>, 'val':<> }
    in it, needs to sort items in the buffer via the 'addr' value
    """
    for item in xtaint_buffer_set_list:
        item['buffer'] = sorted(item['buffer'], key=itemgetter('addr') )
#         for mem_cell in item['buffer']:
#             print(mem_cell)

def create_contin_buffer_set():
    """create continous buffer sets of buffers in same function call
    Args:
        global - xtaint_buffer_set_list
    Return:
        save results in xtaint_buffer_set_list
        
    for {} of each function call, the value of key 'buffer' is sorted list
    that contains all records (i.e., {'flag':<>, 'addr':<>, 'val':<> })
    of the function call
    
    it needs to break the 'buffer' list into several sub-lists, such that,
    for 'addr' of each record, if their interval smaller than a default
    value, they belong to the same continous buffer set
    """
    default_interval = 4
    for item in xtaint_buffer_set_list:
        buf_set = []
        contin_buf_set = []
        record_index = 0
        for record in item['buffer']:
            if record_index == 0:
                contin_buf_set.append(record)
            else:
                interval = record['addr'] - contin_buf_set[-1]['addr']
                if interval > 0 and interval <= default_interval:
                    """continous buffer (get rid of duplicate buffer)"""
                    contin_buf_set.append(record)
                elif interval > default_interval:
                    buf_set.append(contin_buf_set)
                    contin_buf_set = []
                    contin_buf_set.append(record)
                     
            record_index += 1
        
        """add last contin_buf_set"""    
        buf_set.append(contin_buf_set)
        item['buffer'] = buf_set
     
def main():
    preprocess()
#     for record in xtaint_log_list:
#         print(record)
    create_buffer_set()
    sort_buffer_set()
    create_contin_buffer_set()
    for member in xtaint_buffer_set_list:
        for head in member['head']:
            print(head)
        for sub_list in member['buffer']:
            for record in sub_list:
                print(record)
 
if __name__ == '__main__':
    main()

