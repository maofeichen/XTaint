'''Search the avalanche effect given a XTaint log. The main procedure can 
be divided into 3 components:
    * Determine Path - determines if there is a path between any
        given src and dest in a XTaint log
    * Create Sets of Buffers - creates sets of buffers within the 
        same function call (matched CALL & RET instructions)
    * Search Avalanche Effect - searches avalanche effect based on
        the sets of buffers
TODO: explain more clearly'''

import pdb
import sys
from operator import itemgetter

_author_ = "mchen"

XTAINT_LOG_DIR  = "/home/mchen/Workspace-Linuxmint/XTaint/Result/"
# XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack.txt"
XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"

CALL                    = "14"   # 14 is CALL instruction
RET                     = "18"    # 18 is RET instruction

XTAINT_LOG              = []
LOG_FUNC_LIVE           = []
LOG_FUNC_LIVE_DICT      = []

def process_log():
    """process XTaint log.
    :param XTAINT_LOG_DIR + XTAINT_LOG_FILE: path of XTaint log
    :returns XTAINT_LOG: global list that contains all XTaint log records, 
        such as: [{}, {}, {},...].
        Each sub-dictionary is either a normal record dictionary or 
            CALL or RET record dictionary, form as:
            * normal record: {'src':{}, 'dest':{} }, and each src or dest 
                form as {flag: <flag>, addr: <addr>, val: <val>} 
            * CALL or RET instruction record:
                {CALL: {func_addr: <func_addr>, level: <level>} }
                {RET: {level: <level>} }
    """
    with open(XTAINT_LOG_DIR + XTAINT_LOG_FILE, 'r') as xt_log_fp:
        for line in xt_log_fp:
            words = line.split()
            if words[0] == CALL:
                # example word list: ['14', '0', '0', 'CALL', 'level:-215']
                # needs to save func_addr ('0') and 'level:-215'
                call = {}
                call['CALL'] = {'func_addr':words[1], 'level':words[4]}
                XTAINT_LOG.append(call)
            elif words[0] == RET:
                # example words list: ['18', '0', '0', 'RET', 'level:-1']
                # only needs to save "RET" and "level:-1"
                ret = {}
                ret['RET'] = {'level':words[4]}
                XTAINT_LOG.append(ret)
            else:   # normal record
                record = {}
                record['src'] = \
                    {'flag':words[0], 'addr':words[1], 'val':words[2]}
                record['dest'] = \
                    {'flag':words[3], 'addr':words[4], 'val':words[5]}
                record['in_func'] = "FALSE"
                XTAINT_LOG.append(record);

    xt_log_fp.close()
#     for item in XTAINT_LOG:
#         print(item)

def create_func_log():
    """extract records for each function call, based on the RET mark of
    each function.
    :param XTAINT_LOG: after call process_log
    :return LOG_FUNC_LIVE: global and form as [[], [], [],...]
        each nested list contains records of the same function
            LOG_FUNC_LIVE_DICT: global and form as [{}, {},... ]
        each nested dict contains records of the same function
    Algorithm O(n^2):
        scan XTAINT_LOG, repeat until end:
            look for "RET" records, if found:
                look for backwards its matched "CALL" rec, if found:
                    save all normal records between, as well as
                        the paired CALL and RET in the same sub-list
                    mark those records 'in_func' field as TRUE
                Otherwise, continue look for next "RET"
    """
    addr_len = 7    # assume addr len

    for idx, item in enumerate(XTAINT_LOG):
        if "RET" in item:
            match_call_found = False
            
            # scan backwards to look for its matched CALL
            match_call_idx = idx - 1
            while match_call_idx >= 0:
                match_call = XTAINT_LOG[match_call_idx]
                if "CALL" in match_call and \
                        match_call['CALL']['level'] == item['RET']['level']:
                    match_call_found = True
                    break
                match_call_idx -= 1

            if match_call_found:
                # if found, add records between to a sub list 
                records_dict    = {}
                records         = [match_call, item]
                
                for rec in XTAINT_LOG[match_call_idx:idx]:
                    if "RET" not in rec \
                            and "CALL" not in rec \
                            and rec['in_func'] == "FALSE":
                        rec['in_func'] = "TRUE"
                        s = rec['src']
                        d = rec['dest']
                        # only save if it is memory addr 
                        # or their vals are memory addr
                        # TODO: how to distinct with addr with val?
                        if len(s['addr']) >= addr_len \
                                or len(s['val']) >= addr_len:
                            # assume start with "bffff" or "804" (hacked filter)
                            if s['addr'].startswith(('bffff', '804')) \
                                    or s['val'].startswith(('bffff', '804')): 
                                records.append(s)
                            
                                rec_key = (s['flag'],
                                           s['addr'],
                                           s['val'])
                                records_dict[rec_key] = "None"
                             
                        if len(d['addr']) >= addr_len \
                                or len(d['val']) >= addr_len:
                            # assume start with "bffff" or "804"
                            if d['addr'].startswith(('bffff', '804'))\
                                    or d['val'].startswith(('bffff', '804')): 
                                records.append(rec['dest'])
                                
                                rec_key = (d['flag'],
                                           d['addr'],
                                           d['val'])
                                records_dict[rec_key] = "None"
                records = sort_func_records(records)
                LOG_FUNC_LIVE.append(records)
                LOG_FUNC_LIVE_DICT.append(records_dict)
#     for func in LOG_FUNC_LIVE:
#         for rec in func:
#             print(rec)
#     for dic in LOG_FUNC_LIVE_DICT:
#         for key in dic:
#             print(key, dic[key])

def sort_func_records(func_recs):
    """sort logs in the same function call.
        1. convert record addr and val to numbers
        2. sort either by addr or val
        3. convert back to string and save in result list
    :param func_recs: out of order logs in same function, forms as
        [{'CALL':...}, {'RET':...}, {}, {}, ...]
        Begin from 3rd dictionary, it is common record
    :returns func_recs_sorted - a list contains sorted records either by addr
    or val
    """
    func_recs_sorted = [func_recs[0], func_recs[1]]
    func_recs_sorted_addr = []
    func_recs_sorted_val = []
    
    add_len = 7
    
    if len(func_recs) > 3:          # only have more than 1 normal records
        for rec in func_recs[2:]:   # first 2 records are function mark
            if len(rec['addr']) >= add_len:
                rec_int = (rec['flag'],
                           int(rec['addr'], 16),
                           rec['val'])
                func_recs_sorted_addr.append(rec_int)
                
            if len(rec['val']) >= add_len:
                rec_int = ()
                rec_int = (rec['flag'],
                           rec['addr'],
                           int(rec['val'], 16))
                func_recs_sorted_val.append(rec_int)

        func_recs_sorted_addr = sorted(func_recs_sorted_addr, key=lambda x: x[1])
        func_recs_sorted_val = sorted(func_recs_sorted_val, key=lambda x: x[2])
    
        for rec in func_recs_sorted_addr:
            rec_str = {'flag':rec[0],
                       'addr':hex(rec[1])[2:],
                       'val':rec[2]}
            func_recs_sorted.append(rec_str)
        for rec in func_recs_sorted_val:
            rec_str = {'flag':rec[0],
                       'addr':rec[1],
                       'val':hex(rec[2])[2:]}
            func_recs_sorted.append(rec_str)

    return func_recs_sorted

def search_dest(snode):
# def search_dest(snode, dnode):
    """given a source node of any record, search all its propagate_dests 
    destinations
    :param snode: source node of a record
    :returns: destination - a dict contains all destinations that can 
    progate to it
    """
#     XTAINT_LOG      = list(XTAINT_LOG)
#     snode_t         = (snode['flag'], snode['addr'], snode['val'])
#     dests           = [snode_t]
    
#     dests_addr_map  = {}
#     key             = (snode['flag'], snode['addr'])
#     dests_addr_map[key] \
#                     = "None"
                    
    # use only addr as key instead of flag and addr
    dests_addr_map  = {}
    key             = (snode['addr'])
    dests_addr_map[key] \
                    = "None"

    dests_map       = {}
    record_node     = (snode['flag'], snode['addr'], snode['val'])
    dests_map[record_node] \
                    = "None"

    # TODO: more compact implementation
    index = 0
    for record in XTAINT_LOG:
        if "RET" not in record and "CALL" not in record:
            if record['src'] == snode:     
                break
        index += 1

    for record in XTAINT_LOG[index:]:
        if "RET" not in record and "CALL" not in record:
            s = record['src']
            d = record['dest']
               
            dest_key = (d['flag'], d['addr'], d['val']) 
            # use only addr as key instead of flag and addr
#             addr_key = (s['flag'], s['addr'])
            addr_key = (s['addr'])

            if addr_key in dests_addr_map and dest_key not in dests_map:
                # use only addr as key instead of flag and addr
#                 dests_addr_map[(d['flag'], d['addr'])] = "None"
                dests_addr_map[d['addr']] = "None"
                dests_map[dest_key]     = "None"

    return dests_map

#     if dnode in dests_map: return True
#     else: return False

def filter_path(path_func):
    """given a list that contains a path between a source node to any node
    of a function. To filter nodes in the function, such that at least two
    nodes, and either addr or val are continuous (less than 4)
    :param path_func
    :returns a list
    """
    filter_path_func = []
    
    path_func_addr = []
    path_func_val = []
    for nd in path_func:
        if len(nd[1]) >= 7:     # addr containts
            nd_to_int = (nd[0], int(nd[1], 16), nd[2])
            path_func_addr.append(nd_to_int)
        elif len(nd[2]) >= 7:   # val contains
            nd_to_int = (nd[0], nd[0], int(nd[2], 16))
            path_func_val.append(nd_to_int)
                
    # only counts if more than 1 node for each func 
    if len(path_func_addr) > 1:
        path_func_addr = sorted(path_func_addr, key=lambda x: x[1])
        # continue mem addr (<= 4)
        cont_path_func_addr = []
        
        # TODO: more compact implementation
        b_cont_tup = path_func_addr[0]
        l_cont_tup = path_func_addr[0]
        for tup in path_func_addr[1:]:
            if tup[1] - b_cont_tup[1] <= 4 \
                    and tup[1] - b_cont_tup[1] > 0:
                
                begin_tup_hex = (b_cont_tup[0], \
                                 hex(b_cont_tup[1])[2:], \
                                 b_cont_tup[2])
                
                cont_path_func_addr.append(begin_tup_hex)
                
            elif b_cont_tup[1] - l_cont_tup[1] <= 4 \
                    and b_cont_tup[1] - l_cont_tup[1] > 0:
                
                begin_tup_hex = (b_cont_tup[0], \
                                 hex(b_cont_tup[1])[2:], \
                                 b_cont_tup[2])
                
                cont_path_func_addr.append(begin_tup_hex)
            
            l_cont_tup = b_cont_tup
            b_cont_tup = tup

        # add final tup
        if b_cont_tup[1] - l_cont_tup[1] <= 4 \
                and b_cont_tup[1] - l_cont_tup[1] > 0:
                
            begin_tup_hex = (b_cont_tup[0], \
                            hex(b_cont_tup[1])[2:], \
                            b_cont_tup[2])
            cont_path_func_addr.append(begin_tup_hex)
        
        if cont_path_func_addr:
            filter_path_func.append(cont_path_func_addr)
            
    if len(path_func_val) > 1:
        path_func_val = sorted(path_func_val, key=lambda x: x[2])
                # continue mem addr (<= 4)
        cont_path_func_val = []
        
        # TODO: more compact implementation
        b_cont_tup = path_func_val[0]
        l_cont_tup = path_func_val[0]
        for tup in path_func_val[1:]:
            if tup[2] - b_cont_tup[2] <= 4 \
                    and tup[2] - b_cont_tup[2] > 0:
                begin_tup_hex = (b_cont_tup[0], \
                                 b_cont_tup[1], \
                                 hex(b_cont_tup[2])[2:])
                cont_path_func_val.append(begin_tup_hex)
            elif b_cont_tup[2] - l_cont_tup[2] <= 4 \
                    and b_cont_tup[2] - l_cont_tup[2] > 0:
                begin_tup_hex = (b_cont_tup[0], \
                                 b_cont_tup[1], \
                                 hex(b_cont_tup[2])[2:])
                cont_path_func_val.append(begin_tup_hex)
            l_cont_tup = b_cont_tup
            b_cont_tup = tup

        if b_cont_tup[2] - l_cont_tup[2] <= 4 \
                and b_cont_tup[2] - l_cont_tup[2] > 0:
            begin_tup_hex = (b_cont_tup[0], \
                             b_cont_tup[1], \
                             hex(b_cont_tup[2])[2:])
            cont_path_func_val.append(begin_tup_hex)
       
        if cont_path_func_val:
            filter_path_func.append(cont_path_func_val)
    return filter_path_func

# def propagate_dests(srouce):
def propagate_dests(source, idx):
    """Given a source source, forms as {'flag':<>, 'addr':<>, 'val':<>}, 
    determines if it can propagate_dests to any nodes of any function.
    :param source: given source source
    :param idx: ?
    :returns a list that all nodes of any function that the given source 
    can propagate_dests to
    """
    path_funcs  = []
    dest_map    = search_dest(source)
    
    for func_log_dict in LOG_FUNC_LIVE_DICT[idx + 1:]:
        path_func = [nd for nd in dest_map if nd in func_log_dict]
        path_func = filter_path(path_func)
 
        if path_func:  
            path_func_dict = {'fi':idx, 'paths': path_func}
            path_funcs.append(path_func_dict)
         
        idx += 1
                    
#     for idx, func_log_dict in enumerate(LOG_FUNC_LIVE_DICT):
#         # TODO: bug here, even no intersection, last nd still in
#         path_func = [nd for nd in dest_map if nd in func_log_dict]
#         path_func = filter_path(path_func)
#   
#         if path_func:  
#             path_func_dict = {'fi':idx, 'paths': path_func}
#             path_funcs.append(path_func_dict)

#     for idx, func_log_dict in enumerate(LOG_FUNC_LIVE_DICT):
#         path_func = []
#         for nd in func_log_dict:
#             if search_dest(source, nd):
#                 path_func.append(nd)
#         
#         path_func = filter_path(path_func)
#  
#         if path_func:  
#             path_func_dict = {'fi':idx, 'paths': path_func}
#             path_funcs.append(path_func_dict)
            
    return path_funcs

def search_avalanche():
    """search avalanche effect between continuous buffer set
    Args:
        global - LOG_FUNC_LIVE, which contains continuous buffer
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
    for idx, func_log in enumerate(LOG_FUNC_LIVE):
        print("function index: ", idx)
        for node in func_log[2:]:
            if node:
                node_path_funcs = propagate_dests(node, idx)   
                if node_path_funcs:
                    print("node: ", node)
                    for path_func_dict in node_path_funcs:
                        print(path_func_dict)         
    
#     node = {'flag': '2', 'addr': '3', 'val': '804a048'}
#     node_path_funcs = propagate_dests(node)   
#     if node_path_funcs:
#         print("node: ", node)
#         for path_func_dict in node_path_funcs:
#             print(path_func_dict)   
    
def main():
    process_log()
    create_func_log()
    search_avalanche()
 
if __name__ == '__main__':
    main()

