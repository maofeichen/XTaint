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
import sys
from operator import itemgetter

# sys.stdout.flush()

XTAINT_LOG_DIR = "/home/mchen/Workspace-Linuxmint/XTaint/Result/"
XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"

CALL = "14"   # 14 is CALL instruction
RET = "18"    # 18 is RET instruction

xtaint_log_list         = []
hash_xtaint_log         = {}
xtaint_buffer_set_list  = []

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

def create_hash_xt_log():
    """create hash table (dictionary) of xtaint_log_list for better
    performance
    @precondition: xtaint_log_list has to be created by preprocess
        before calling this function
    @param global: xtaint_log_list
    @return: global: hash_xtaint_log"""
    for elem in xtaint_log_list:
        if "record" in elem:
#             toint = int(elem['record']['src']['addr'],16)
            src = elem['record']['src']['flag'] + "-" + elem['record']['src']['addr']
#             src = elem['record']['src']['flag'] + "-" + toint
#             print(src)
            hash_xtaint_log[src] = []
    
    i = 0 
    for elem in xtaint_log_list:
        if "record" in elem:
#             toint = int(elem['record']['src']['addr'],16)
            src = elem['record']['src']['flag'] + "-" + elem['record']['src']['addr']
#             src = elem['record']['src']['flag'] + "-" + toint
            dest = {'dest':elem['record']['dest'], 'time':i}
            hash_xtaint_log[src].append(dest)
            i += 1
    
#     for key in hash_xtaint_log:
#         for dest in hash_xtaint_log[key]:
#             print(dest)

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
    
    del local_xt_log_list[:]

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
        buf_sets = []
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
                    buf_sets.append(contin_buf_set)
                    contin_buf_set = []
                    contin_buf_set.append(record)
                      
            record_index += 1
        
        """add last contin_buf_set"""    
        buf_sets.append(contin_buf_set)
        item['buffer'] = buf_sets
    del buf_sets[:]
    del contin_buf_set[:]

def del_val(xtaint_node):
    """ delete val key component of xtaint_node
    a xtaint_node is a dictionary, forms as:
        {'flag':<>, 'addr':<>, 'val':<>}
        
    Args:
        a xtaint_node dictonary
    Return:
        a xtaint_node dictionary without key 'val'
            {'flag':<>, 'addr':<>}
    """
    new_xtaint_node = {'flag':xtaint_node['flag'], 'addr':xtaint_node['addr']}
    return  new_xtaint_node
    

def is_path_exist(src, dest, usehash, time):
    """ determine if a path between the given src and dest
    Args:
        src: {'flag':<>, 'addr':<>, 'val':<>}
        dest: {'flag':<>, 'addr':<>, 'val':<>}
    Return:
        return true if such a path exists; otherwise return false
    """
    if usehash:
#         set_src = [src] # set of dests that src can reach, init with src
#         tohex = hex(src['addr'])[2:]
        key = src['flag'] + "-" + src['addr']
#         key = src['flag'] + "-" + tohex
        if key not in hash_xtaint_log:
            return False
        
        dest_list = hash_xtaint_log[key]
        
        min_time = sys.maxsize
        for elem in dest_list:
            if min_time > elem['time']:
                min_time = elem['time']
        if time > min_time:
            return False
        
        for elem in dest_list:    
            if time <= elem['time']:
                if dest['flag'] == elem['dest']['flag']\
                        and dest['addr'] == elem['dest']['addr']:
                    return True
                else:
                    time = elem['time']
                    new_src = elem['dest']
                    return is_path_exist(new_src, dest, True, time)
            
    else:
        new_src = del_val(src)
        new_dest = del_val(dest) 
        set_src = [new_src] # set of dests that src can reach, init with src

        for item in xtaint_log_list:
            if "record" in item:
                src_of_record = del_val(item['record']['src'])
                dest_of_record = del_val(item['record']['dest'])
                if src_of_record in set_src \
                        and dest_of_record not in set_src:
                    set_src.append(dest_of_record)
    
        if new_dest in set_src: return True
        else: return False

def srch_aval_src_dest_buf(src_buf, dest_buf):
    """search avalanche effect given two continuous buffers
    Args:
        src_buf: source continuous buffer
        dest_buf: destination continuous buffer
        
        both are lists, form as:
            [
                1st mem cell: {'flag'<>, 'addr':<>, 'val':<>}
                2nd mem cell: {'flag'<>, 'addr':<>, 'val':<>}
                3rd mem cell: {'flag'<>, 'addr':<>, 'val':<>}
                ...
            ]
    Return:
        a list of aval_pair input & output buffers if there exists avalanche
        effect between them
        [
            (1st aval_pair input & output buffers):
            {
                'in_buf':
                [
                    {'flag'<>, 'addr':<>, 'val':<>}
                    ...
                ]
                
                'out_buf':
                [
                    {'flag'<>, 'addr':<>, 'val':<>}
                    ...
                ]
            }
            (2nd aval_pair input & output buffers):
            {
                'in_buf':
                [
                    {'flag'<>, 'addr':<>, 'val':<>}
                    ...
                ]
                
                'out_buf':
                [
                    {'flag'<>, 'addr':<>, 'val':<>}
                    ...
                ]
            }
            ...
        ]
    
    """
    aval_src_destbufs_sets  =   []
    aval_in_out_bufs        =   {}
    aval_in_out_bufs_sets   =   []
    
    for nd_src in src_buf:
        aval_src_destbufs = {}
        aval_src_destbufs['src_node'] = nd_src
        aval_src_destbufs['dest_bufs'] = []
        
        nd_src_tostr = {'flag':nd_src['flag'],\
                        'addr':hex(nd_src['addr'])[2:],\
                        'val':nd_src['val']}
        for nd_dest in dest_buf:
#             if is_path_exist(nd_src, nd_dest):
            nd_dest_tostr = {'flag':nd_dest['flag'],\
                        'addr':hex(nd_dest['addr'])[2:],\
                        'val':nd_dest['val']}
            if is_path_exist(nd_src_tostr, nd_dest_tostr, True, 0):               
                aval_src_destbufs['dest_bufs'].append(nd_dest)
        if len(aval_src_destbufs['dest_bufs']) > 0:
            aval_src_destbufs_sets.append(aval_src_destbufs)
            
    for entr in aval_in_out_bufs_sets:
        print("entry source node is:")
        print(entr['src_node'])
        print("dest buf is:")
        for elem in entr['dest_bufs']:
            print(elem)
    
#     counter_continu_dest_buf = 0
# 
#     aval_pair_sets = []
#     aval_pair = {}
#     
#     src_node_i = 0
#     for src_node in src_buf:
#         if src_node_i == 0:
#             aval_pair['in_buf'] = [src_node]
#         else:
#             counter_continu_dest_buf = 0
#             for dest_node in dest_buf:
#                 is_path =  is_path_exist(src_node, dest_node)
#                 if not is_path:
#                     break
#                 
#                 counter_continu_dest_buf += 1
#             
#         src_node_i += 1
#         
#     
#     return aval_pair_sets

def search_avalanche():
    """search avalanche effect between continuous buffer set
    Args:
        global - xtaint_buffer_set_list, which contains continuous buffer
        sets of each function call (ordered by completion time), form as:
        [
            (1st complete function call):
            {
                'head':
                {
                    'CALL':{}
                    'RET':{}
                }
                'buffer':
                {
                    [
                        (1st continuous buffer set):
                        [
                            {'flag'<>, 'addr':<>, 'val':<>}
                            {'flag'<>, 'addr':<>, 'val':<>}
                            ...
                        ]
                        
                        (2nd continuous buffer set):
                        [
                            {'flag'<>, 'addr':<>, 'val':<>}
                            {'flag'<>, 'addr':<>, 'val':<>}
                            ...
                        ]
                        
                        ...
                    ]
                }
                    
            }
            
            (2nd complete function call):
            {
                'head':
                {
                    'CALL':{}
                    'RET':{}
                }
                'buffer':
                {
                    [
                        (1st continuous buffer set):
                        [
                            {'flag'<>, 'addr':<>, 'val':<>}
                            {'flag'<>, 'addr':<>, 'val':<>}
                            ...
                        ]
                        
                        (2nd continuous buffer set):
                        [
                            {'flag'<>, 'addr':<>, 'val':<>}
                            {'flag'<>, 'addr':<>, 'val':<>}
                            ...
                        ]
                        
                        ...
                    ]
                }
                    
            }
            ...
        ]
    
    Return:
        an avalanche effect list, which contains all pair input and output
        buffers that have avalanche effect, forms as:
        [
            (1st pair input & output buffer as dict):
            {
                'head_in_buf':<>(which function call & continuous buffer sets
                    this input buffer comes from)
                'head_out_buf':<>(which function call & continuous buffer sets
                    this output buffer comes from)
                'in_buf':(a continuous buffer)
                [
                    1st mem cell as dict {}
                    2nd mem cell as dict {}
                    ...
                ]
                'out_buf':(a continuous buffer)
                [
                    1st mem cell as dict {}
                    2nd mem cell as dict {}
                    ...
                ]
            }
            (2nd pair input & output buffer as dict):
            {
                'head_in_buf':<>(which function call & continuous buffer sets
                    this input buffer comes from)
                'head_out_buf':<>(which function call & continuous buffer sets
                    this output buffer comes from)
                'in_buf':(a continuous buffer)
                [
                    1st mem cell as dict {}
                    2nd mem cell as dict {}
                    ...
                ]
                'out_buf':(a continuous buffer)
                [
                    1st mem cell as dict {}
                    2nd mem cell as dict {}
                    ...
                ]
            }
            ...
        ]
    Algorithm:
        brute force search, the continuous buffer sets organize as:
            1st func call: [b1, b2, b3, ...]
            2nd func call: [b1, b2, b3, ...]
            3rd func call: [b1, b2, b3, ...]
            ...
        
        each b in any func call is a continuous buffer set, the search is
        as:
            begin with 1st func call continuous buffer sets:
                all b1, b2, ... need to search ALL continuous buffer sets in
                2nd func call, 3rd func call, until end
            after 1st func call finishes, begin with 2nd func call:
                 all b1, b2, ... need to search ALL continuous buffer sets in
                3rd func call, 4th func call, until end
            ...
            repeat until end
            
            essentially it is for continuous buffer sets in same func call,
            NO need to search between them
            for each continuous buffer set, search it between EVERY 
            continuous buffer set after its func call
    """
    i_in_func_compl = 0
    i_out_func_compl = 0
    
    i_in_conti_buf = 0
    i_out_conti_buf = 0
    
    for in_func_compl in xtaint_buffer_set_list:
        i_in_conti_buf = -1
        
        for in_conti_buf in in_func_compl['buffer']:
            i_in_conti_buf += 1
            if len(in_conti_buf) <= 1:
                continue
            i_out_func_compl = i_in_func_compl + 1
            for out_func_compl in xtaint_buffer_set_list[i_in_func_compl+1:]:
                i_out_conti_buf = -1
                
                for out_conti_buf in out_func_compl['buffer']:
                    i_out_conti_buf += 1
                    if len(out_conti_buf) <= 1:
                        continue
                    srch_aval_src_dest_buf(in_conti_buf, out_conti_buf)
                    print("fin searching avalanche:")
                    print("\tindex of input function completion: ", i_in_func_compl)
                    print("\tindex of continuous buffer in the function:", i_in_conti_buf)
                    print("\tindex of output function completion: ", i_out_func_compl)
                    print("\tindex of continuous buffer in the function:", i_out_conti_buf)
                i_out_func_compl += 1
            
        i_in_func_compl += 1
            
    
def main():
    preprocess()
     for record in xtaint_log_list:
         print(record)

#    create_hash_xt_log()
#    create_buffer_set()
#    sort_buffer_set()
#    create_contin_buffer_set()
    
#     is_path_exist(xtaint_log_list[222]['record']['src'], \
#                   xtaint_log_list[222]['record']['dest'], True, 0)

#     assert(\
#            is_path_exist(xtaint_log_list[222]['record']['src'], \
#                   xtaint_log_list[223]['record']['dest'], True, 0)
#            ) == True
           
#     assert(\
#            is_path_exist(xtaint_log_list[222]['record']['dest'], \
#                   xtaint_log_list[222]['record']['src'], True, 0)
#            ) == False
            
#     for member in xtaint_buffer_set_list:
#         for head in member['head']:
#             print(head)
#         for sub_list in member['buffer']:
#             for record in sub_list:
#                 print(record)
#    search_avalanche()
 
if __name__ == '__main__':
    main()

