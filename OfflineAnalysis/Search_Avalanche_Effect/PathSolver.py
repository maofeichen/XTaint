#
# ##############################################################################
# file: PathSolver.py
# author:   
#       mchen
# desc:     
#       The goal of this PathSolver is to determine if there is path from
#       a given src and dest with a XTaint log.
#
#       A XTaint log contains thousands of records, each record forms as
#       <src des>, each src or dest forms as <flag addr val>, thus the
#       record is as:
#           <flag addr val flag addr val>
#       The first triple is src, whereas latter triple is dest.
#
#       Some src or dest of a record can be a src or dest of another record.
#       Therefore, a XTaint log can be considered as a 
#       directed graph, each record is as a edge of the graph, 
#       the problem is:
#
#           give such a XTaint log, and any pair <src dest>, it determines
#       if there is a path between the src and dest (notice that the src
#       or dest can be in different records)
#
#       Essentially, it the PATH problem in graph, and there is a 
#       polynomial algorithm of it.
#
# Algorithm (reference Intro to Computation Theory 3rd ed.):
#       1. Break each record into separate triple as src and dest
#       2. Init a set with the source, repeat the following until 
#           NO new src or dest added:
#               Scan all records, if a pair <src dest> is found going from 
#               a src is already in the set, add the dest in the set too
#   
#       The running time is polynomial
# ##############################################################################
#

XTAINT_LOG_DIR = "/home/mchen/Workspace-Linuxmint/XTaint/Result/"
XTAINT_LOG_FILE = "result-DES-CBC-Aval-1Block-heap_gv_sv_stack-nogdb.txt"
OUT_FILE = "preprocess-result_DES_CBC_1Block-heap_gv_sv_stack-nogdb.txt"

CALL = "14"   # 14 is CALL instruction
RET = "18"    # 18 is RET instruction

XT_LOG = []    # the list of output of preprocess

# preprocess XTaint log
# input:
#       XTaint log file
# output:
#       a list as:
#           [ [(flag addr), (flag addr)], 
#               [(flag addr), (flag addr)], ...]
#       each inner square parenthesis:
#           [(), ()]
#       is a pair [src, dest] (i.e., an edge)
#       notice that we don't include the val
def preprocess():
    xt_log = open(XTAINT_LOG_DIR + XTAINT_LOG_FILE, 'r')
    line = xt_log.readline().rstrip('\n')
    while line != "":
        # only parse record which is neither CALL nor RET
        if line[:2] != CALL and line[:2] != RET:
            pair = []
            src = []
            dest = []

            word = line.split()
#             src = word[:len(word)/2]
#             dest = word[len(word)/2:]
            for i in range(len(word) ):
                if i < 2:
                    src.append(word[i])
                elif i > 2 and i < 5:
                    dest.append(word[i])

            pair.append(src)
            pair.append(dest)
            XT_LOG.append(pair)

        line = xt_log.readline().rstrip('\n')
    
    xt_log.close()

# determine if a path between the given src and dest
# input:
#        a list of pair src and dest: [[],[]]
#        first triple list is src, latter is dest
# output:
#        return true if such a path exists; otherwise return false
def isPath(src_dest):
    set_src = [src_dest[0]] # set of dests that src can reach, init with src
    
    for pair in XT_LOG:
        # if src is in set, add dest to set too
        if pair[0] in set_src and pair[1] not in set_src:
            set_src.append(pair[1])
        
    if src_dest[1] in set_src: return True
    else: return False

preprocess()
isPath(XT_LOG[0])

# out_file = open(XTAINT_LOG_DIR + OUT_FILE, 'w')
for pair in XT_LOG:
    print(pair)
#     out_file.write(' '.join(pair) )
# out_file.close
