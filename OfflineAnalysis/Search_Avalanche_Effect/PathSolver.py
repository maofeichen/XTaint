#
# ##############################################################################
# file:     PathSolver.py
# author:   mchen
# desc:     The goal of this PathSolver is to determine if there is path from
#           src to dest given a XTaint log.
#
#           A XTaint log contains thousands of records, each record forms as
#           <src des>, each src or dest fomrs as <flag addr val>, thus the
#           record is as:
#               <flag addr val flag addr val>
#           The first triple is src, whereas latter triple is dest.
#
#           Considers a XTaint log contains thousands fo records, some
#           src or dest of a record can be a src or dest of another record.
#           Therefore, essentially a XTaint log can be considered as a 
#           directed graph, the problem is:
#
#               give such a XTaint log, and any pair <src dest>, it determines
#           if there is a path between the src and dest (notice that the src
#           or dest can be in different records)
#
# algorithm:
#           1. Break each record into seperate triple as src and dest
#           2. Init a set with the source, repeat the following until 
#              NO new src or dest added:
#               Scan all records, if a pair <src dest> is found going from 
#               a src is already in the set, add the dest in the set too
#   
#           The running time is polynomial
# ##############################################################################
#
