'''Search the avalanche effect given a XTaint log. The main procedure can 
be divided into 3 components:
    * Determine Path - determines if there is a path between any
        given src and dest in a XTaint log
    * Create Sets of Buffers - creates sets of buffers within the 
        same function call (matched CALL & RET instructions)
    * Search Avalanche Effect - searches avalanche effect based on
        the sets of buffers'''

import sys
from operator import itemgetter

_author_ = "mchen"

# sys.stdout.flush()

XTAINT_LOG_DIR  = "/home/mchen/Workspace-Linuxmint/XTaint/Result/"
# XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack.txt"
# XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"
XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block_8position.txt"

CALL                    = "14"   # 14 is CALL instruction
RET                     = "18"    # 18 is RET instruction

XTAINT_LOG              = []
hash_xtaint_log         = {}
XTAINT_FUNC_LOG         = []
XTAINT_FUNC_LOG_DICT    = []

def preprocess():
    """preprocess XTaint log.
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
                record['is_in_set'] = "FALSE"
                XTAINT_LOG.append(record);

    xt_log_fp.close()
#     for item in XTAINT_LOG:
#         print(item)

def create_func_log():
    """extract records for each function call.
    :param XTAINT_LOG: after call preprocess
    :return XTAINT_FUNC_LOG: global and form as [[], [], [],...]
        each nested list contains records of the same function
            XTAINT_FUNC_LOG: global and form as [{}, {},... ]
        each nested dict contains records of the same function
    Algorithm:
        scan XTAINT_LOG, repeat until end:
            look for "RET" records, if found:
                look for its matched "CALL" record, if found:
                    save all normal records between, as well as
                        the paired CALL and RET in the same sub-list
                Otherwise, continue look for next "RET"
    """
    local_xtaint_log = list(XTAINT_LOG)

    index = 0
    for item in local_xtaint_log:
        if "RET" in item:
            is_match_found = False
            
            # scan backwards to look for its matched CALL
            prev_index = index - 1
            while prev_index >= 0:
                prev_item = local_xtaint_log[prev_index]
                if "CALL" in prev_item and \
                        prev_item['CALL']['level'] == item['RET']['level']:
                    is_match_found = True
                    break
                prev_index -= 1

            if is_match_found:
                # if found, add records of same function to set
                records_dict    = {}
                records         = [prev_item, item]
                
                for record in local_xtaint_log[prev_index:index]:
                    if "RET" not in record and\
                            "CALL" not in record and \
                            record['is_in_set'] == "FALSE":
                        record['is_in_set'] = "TRUE"
                        # only save if src or dest is memory addr 
                        # or their vals are memory addr
                        if len(record['src']['addr']) >= 7 or \
                            len(record['src']['val']) >= 7:
                            # assume input start with "bffff" or "804"
                            if record['src']['addr'].startswith(('bffff',
                                                                 '804')) \
                                or record['src']['val'].startswith(('bffff', 
                                                                    '804')): 
                                records.append(record['src'])
                            
                                # add output but with no such restriction
                                rec_key = (
                                           record['src']['flag'],
                                           record['src']['addr'],
                                           record['src']['val']
                                           )
                                records_dict[rec_key] = "None"
                             
                        if len(record['dest']['addr']) >= 7 or \
                            len(record['dest']['val']) >= 7:
                            # assume input start with "bffff" or "804"
                            if record['dest']['addr'].startswith(('bffff',
                                                                 '804')) \
                                or record['dest']['val'].startswith(('bffff', 
                                                                    '804')): 
                                records.append(record['dest'])
                                # add output but with no such restriction
                                rec_key = (
                                    record['dest']['flag'],
                                    record['dest']['addr'],
                                    record['dest']['val']
                                    )
                                records_dict[rec_key] = "None"
                XTAINT_FUNC_LOG.append(records)
                XTAINT_FUNC_LOG_DICT.append(records_dict)
        index += 1
        
    # add those unmatch records
#     records = []
#     for record in local_xtaint_log:
#         if "RET" not in record and\
#             "CALL" not in record and \
#             record['is_in_set'] == "FALSE":
#             record['is_in_set'] = "TRUE"
#                                     
#             records.append(record['src'])
#             rec_key = (
#                         record['src']['flag'],
#                         record['src']['addr'],
#                         record['src']['val']
#                     )
#             records_dict[rec_key] = "None"   
#             
#             records.append(record['dest'])
#             rec_key = (
#                         record['dest']['flag'],
#                         record['dest']['addr'],
#                         record['dest']['val']
#                     )
#             records_dict[rec_key] = "None"      
#     XTAINT_FUNC_LOG.append(records)
    
#     for func in XTAINT_FUNC_LOG:
#         for record in func:
#             print(record)
#     for dic in XTAINT_FUNC_LOG_DICT:
#         for key in dic:
#             print(key, dic[key])
#     del local_xtaint_log[:]

def search_dest(snode):
# def search_dest(snode, dnode):
    """given a source node of any record, search all its propagate 
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

# def propagate(node, idx):
def propagate(node):
    """Given a source node, forms as {'flag':<>, 'addr':<>, 'val':<>}, 
    determines if it can propagate to any nodes of any function.
    :param node: given source node
    :param idx: ?
    :returns a list that all nodes of any function that the given node 
    can propagate to
    """
    path_funcs  = []
    dest_map    = search_dest(node)
    
#     for func_log_dict in XTAINT_FUNC_LOG_DICT[idx + 1:]:
#         path_func = [nd for nd in dest_map if nd in func_log_dict]
#         path_func = filter_path(path_func)
# 
#         if path_func:  
#             path_func_dict = {'fi':idx, 'paths': path_func}
#             path_funcs.append(path_func_dict)
#         
#         idx += 1
                    
    for idx, func_log_dict in enumerate(XTAINT_FUNC_LOG_DICT):
        # TODO: bug here, even no intersection, last nd still in
        path_func = [nd for nd in dest_map if nd in func_log_dict]
        path_func = filter_path(path_func)
  
        if path_func:  
            path_func_dict = {'fi':idx, 'paths': path_func}
            path_funcs.append(path_func_dict)

#     for idx, func_log_dict in enumerate(XTAINT_FUNC_LOG_DICT):
#         path_func = []
#         for nd in func_log_dict:
#             if search_dest(node, nd):
#                 path_func.append(nd)
#         
#         path_func = filter_path(path_func)
#  
#         if path_func:  
#             path_func_dict = {'fi':idx, 'paths': path_func}
#             path_funcs.append(path_func_dict)
            
    return path_funcs
        
def create_hash_xt_log():
    """create hash table (dictionary) of XTAINT_LOG for better
    performance
    @precondition: XTAINT_LOG has to be created by preprocess
        before calling this function
    @param global: XTAINT_LOG
    @return: global: hash_xtaint_log"""
    for elem in XTAINT_LOG:
        if "record" in elem:
#             toint = int(elem['record']['src']['addr'],16)
            src = elem['record']['src']['flag'] + "-" + elem['record']['src']['addr']
#             src = elem['record']['src']['flag'] + "-" + toint
#             print(src)
            hash_xtaint_log[src] = []
    
    i = 0 
    for elem in XTAINT_LOG:
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



def sort_buffer_set():    
    """for all memory buffers in the same function call, sort them via 'addr'
    Args:
        global - XTAINT_FUNC_LOG
    Return:
        save results in XTAINT_FUNC_LOG
    
    (Needs to be called after create_func_log)
    At this time the XTAINT_FUNC_LOG forms as:
        [{'head':[{'CALL':{} }, {'RET':{} } ], 'buffer':[{}, {}, ...] }, {}, ...]
    each member of the list is a dictionary, with key head and buffer; the 
    value of buffer is a list, which contains all the 
        {'flag':<>, 'addr':<>, 'val':<> }
    in it, needs to sort items in the buffer via the 'addr' value
    """
    for item in XTAINT_FUNC_LOG:
        item['buffer'] = sorted(item['buffer'], key=itemgetter('addr') )
#         for mem_cell in item['buffer']:
#             print(mem_cell)

def create_contin_buffer_set():
    """create continous buffer sets of buffers in same function call
    Args:
        global - XTAINT_FUNC_LOG
    Return:
        save results in XTAINT_FUNC_LOG
        
    for {} of each function call, the value of key 'buffer' is sorted list
    that contains all records (i.e., {'flag':<>, 'addr':<>, 'val':<> })
    of the function call
    
    it needs to break the 'buffer' list into several sub-lists, such that,
    for 'addr' of each record, if their interval smaller than a default
    value, they belong to the same continous buffer set
    """
    default_interval = 4
    for item in XTAINT_FUNC_LOG:
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

        for item in XTAINT_LOG:
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
        global - XTAINT_FUNC_LOG, which contains continuous buffer
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
#     i_in_func_compl = 0
#     i_out_func_compl = 0
#     
#     i_in_conti_buf = 0
#     i_out_conti_buf = 0
#     
#     for in_func_compl in XTAINT_FUNC_LOG:
#         i_in_conti_buf = -1
#         
#         for in_conti_buf in in_func_compl['buffer']:
#             i_in_conti_buf += 1
#             if len(in_conti_buf) <= 1:
#                 continue
#             i_out_func_compl = i_in_func_compl + 1
#             for out_func_compl in XTAINT_FUNC_LOG[i_in_func_compl+1:]:
#                 i_out_conti_buf = -1
#                 
#                 for out_conti_buf in out_func_compl['buffer']:
#                     i_out_conti_buf += 1
#                     if len(out_conti_buf) <= 1:
#                         continue
#                     srch_aval_src_dest_buf(in_conti_buf, out_conti_buf)
#                     print("fin searching avalanche:")
#                     print("\tindex of input function completion: ", i_in_func_compl)
#                     print("\tindex of continuous buffer in the function:", i_in_conti_buf)
#                     print("\tindex of output function completion: ", i_out_func_compl)
#                     print("\tindex of continuous buffer in the function:", i_out_conti_buf)
#                 i_out_func_compl += 1
#             
#         i_in_func_compl += 1

    for idx, func_log in enumerate(XTAINT_FUNC_LOG):
        print("function index: ", idx)
        for node in func_log[2:]:
            if node:
                node_path_funcs = propagate(node)   
                if node_path_funcs:
                    print("node: ", node)
                    for path_func_dict in node_path_funcs:
                        print(path_func_dict)         
    
#     node = {'flag': '2', 'addr': '3', 'val': '804a048'}
#     node_path_funcs = propagate(node)   
#     if node_path_funcs:
#         print("node: ", node)
#         for path_func_dict in node_path_funcs:
#             print(path_func_dict)   
    
def main():
    preprocess()
#     create_hash_xt_log()
    create_func_log()
#     sort_buffer_set()
#     create_contin_buffer_set()
    
#     is_path_exist(XTAINT_LOG[222]['record']['src'], \
#                   XTAINT_LOG[222]['record']['dest'], True, 0)

#     assert(\
#            is_path_exist(XTAINT_LOG[222]['record']['src'], \
#                   XTAINT_LOG[223]['record']['dest'], True, 0)
#            ) == True
           
#     assert(\
#            is_path_exist(XTAINT_LOG[222]['record']['dest'], \
#                   XTAINT_LOG[222]['record']['src'], True, 0)
#            ) == False
            
#     for member in XTAINT_FUNC_LOG:
#         for head in member['head']:
#             print(head)
#         for sub_list in member['buffer']:
#             for record in sub_list:
#                 print(record)

    search_avalanche()
 
if __name__ == '__main__':
    main()

