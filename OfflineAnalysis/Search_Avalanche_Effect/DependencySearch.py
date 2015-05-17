'''Given a XTaint log and destination records, searches ALL sources that can
propagate to them. Each destination record should has a separate result, 
in addition with a result of combining all separate results, which shows 
common sources of all destination records.'''

from multiprocessing.connection import address_type

_author_ = "mchen"

XTAINT_LOG_DIR  = "/home/mchen/Workspace-Linuxmint/XTaint/Result/"
XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack.txt"
OUT_DIR         = "/home/mchen/Workspace-Linuxmint/XTaint/Result/" \
                    "DES-CBC-Aval-1Block-heap_gv_sv_stack-gdb/" \
                    "With-Flag_Addr-as-Key/"

SOURCE_RECORDS  = [
            {'flag':'13', 'addr':'3', 'val':'804b008'},
            {'flag':'8f', 'addr':'3', 'val':'804b00c'},
            {'flag':'f', 'addr':'bffff680', 'val':'804b00f'},
            {'flag':'f', 'addr':'bffff680', 'val':'804a044'},
            {'flag':'2', 'addr':'3', 'val':'804a048'},
        ]
DEST_RECORDS    =[
            {'flag':'2', 'addr':'bffff754', 'val':'42d718c3'},
            {'flag':'2', 'addr':'bffff758', 'val':'eac4346'},
            {'flag':'2', 'addr':'bffff75c', 'val':'39d039e8'},
            {'flag':'2', 'addr':'bffff760', 'val':'53aa7e75'},
            {'flag':'2', 'addr':'bffff764', 'val':'9f18ec45'},
            {'flag':'2', 'addr':'bffff768', 'val':'370f0ce9'},
        ]
XTAINT_LOG      = []    # store xtaint log records after pre-process

MARK_CALL       = "14"  # 14 is MARK_CALL instruction
MARK_RET        = "18"  # 18 is MARK_RET instruction

def preprocess():
    """pre-process XTaint log.
    :returns:  
        store in the global XTAINT_LOG list, such as:
            [{}, {}, {},...]
            each dictionary is a normal record, form as sub-dictionaries below:
            {
            'src':{flag: <flag>, addr: <addr>, val: <val>},
            'dest':{flag: <flag>, addr: <addr>, val: <val>} 
            } 
    """
    with open(XTAINT_LOG_DIR + XTAINT_LOG_FILE, 'r') as xtaint_log:
        for line in xtaint_log:
            words = line.split()
            if words[0] != MARK_CALL and words[0] != MARK_RET:  # normal record
                record = {}
                record['src'] = \
                        {'flag':words[0], 'addr':words[1], 'val':words[2]}
                record['dest'] = \
                        {'flag':words[3], 'addr':words[4], 'val':words[5]}
                XTAINT_LOG.append(record);
    xtaint_log.close()

def search_sources(dnode):
    """given a destination node of any record, search all its dependent 
    sources 
    :param dnode: destination node of a record
    :returns: sources - a list contains all sources that can progate to it
    """
    r_xtaint_log        = list(reversed(XTAINT_LOG))
    dnode_t             = (dnode['flag'], dnode['addr'], dnode['val'])
    sources             = [dnode_t]
    
    sources_addr_map    = {}
#    key                 = dnode['addr']
    key                 = (dnode['flag'], dnode['addr'])
    sources_addr_map[key] \
                        = "None"

    sources_map         = {}
    record_node         = (dnode['flag'], dnode['addr'], dnode['val'])
    sources_map[record_node] \
                        = "None"

    # TODO: more compact implementation
    index = 0
    for record in r_xtaint_log:
        if record['dest'] == dnode:     
            break
        index += 1

    for record in r_xtaint_log[index:]:
        s = record['src']
        d = record['dest']
               
        source_key = (s['flag'], s['addr'], s['val']) 
#        addr_key = d['addr']
        addr_key = (d['flag'], d['addr'])
        if addr_key in sources_addr_map and source_key not in sources_map:
#            sources_addr_map[s['addr']] = "None"
            sources_addr_map[(s['flag'], s['addr'])] = "None"
            sources_map[source_key]     = "None"
            sources.append(source_key)
#             print("sources_addr_mam: %s" % str(sources_addr_map))
#             print("source_map: %s" % str(sources_map))
    return sources

def search_dest(snode):
    """given a source node of any record, search all its propagate 
    destinations
    :param snode: source node of a record
    :returns: destination - a list contains all destinations that can 
    progate to it
    """
    xtaint_log      = list(XTAINT_LOG)
    snode_t         = (snode['flag'], snode['addr'], snode['val'])
    dests           = [snode_t]
    
    dests_addr_map  = {}
#    key             = snode['addr']
    key             = (snode['flag'], snode['addr'])
    dests_addr_map[key] \
                    = "None"

    dests_map       = {}
    record_node     = (snode['flag'], snode['addr'], snode['val'])
    dests_map[record_node] \
                    = "None"

    # TODO: more compact implementation
    index = 0
    for record in xtaint_log:
        if record['src'] == snode:     
            break
        index += 1

    for record in xtaint_log[index:]:
        s = record['src']
        d = record['dest']
               
        dest_key = (d['flag'], d['addr'], d['val']) 
#        addr_key = s['addr']
        addr_key = (s['flag'], s['addr'])

        if addr_key in dests_addr_map and dest_key not in dests_map:
#            dests_addr_map[d['addr']] = "None"
            dests_addr_map[(d['flag'], d['addr'])] = "None"
            dests_map[dest_key]     = "None"
            dests.append(dest_key)

    return dests


def output_source_lists():
    """output all result source lists to files, according to the given
    destination records. In addition, output a source list that combining 
    (intersection) all result source lists
    :param DEST_RECORDS: list of destination record
    """
    source_lists = []
     
    for dnode in DEST_RECORDS:
        sources = search_sources(dnode)
        source_lists.append(sources)
   
    # TODO: use list to keep time order instead of set
    source_combine = set(source_lists[0]).intersection(*source_lists)

    for i, source in enumerate(source_lists):
        with open(OUT_DIR + "source_%i.txt" %i, 'w') as fp:
            for node in source:
                fp.write(str(node) + '\n')
            fp.close()
            
    with open(OUT_DIR + "source_combine.txt", 'w') as fp:
        for node in source_combine:
            fp.write(str(node) + '\n')
        fp.close()

def output_dest_lists():
    """output all result dest lists to files, according to the given
    source records. In addition, output a dest list that combining 
    (intersection) all result dest lists
    :param SOURCE_RECORDS: list of source records
    """
    dest_lists = []
     
    for snode in SOURCE_RECORDS:
        dests = search_dest(snode)
        dest_lists.append(dests)
   
    # TODO: use list to keep time order instead of set
    dest_combine = set(dest_lists[0]).intersection(*dest_lists)

    for i, source in enumerate(dest_lists):
        with open(OUT_DIR + "dest_%i.txt" %i, 'w') as fp:
            for node in source:
                fp.write(str(node) + '\n')
            fp.close()
            
    with open(OUT_DIR + "dest_combine.txt", 'w') as fp:
        for node in dest_combine:
            fp.write(str(node) + '\n')
        fp.close()


def main():
    preprocess()
    output_source_lists()
    output_dest_lists()
    
if __name__ == '__main__':
    main()
