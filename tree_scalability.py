#!/usr/bin/python

# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2022

import networkx as nx
import time
import sys
import getopt

# Global variables
verbose1 = False
verbose2 = False
verbosePeriod = 10
fanout = 10

# Functions
def _tree_edges(n,r):
    # helper function for trees
    # yields edges in rooted tree at 0 with n nodes and branching ratio r
    nodes=iter(range(n))
    parents=[next(nodes)] # stack of max length r
    while parents:
        source=parents.pop(0)
        for i in range(r):
            try:
                target=next(nodes)
                parents.append(target)
                yield source,target
            except StopIteration:
                break

def usage():
	print("This script will create a tree topology and calculate all the possible paths for multicasting between leaf nodes. The tree is composed of a root node and two levels, each one with a given fanout (same value for simplicity).")
	print("Usage:   %s [-h] [-v] [-p <verbose period>] -f <fanout>" % (sys.argv[0]))
	print("Example: %s -p 10 -f 10")

# Main function

# Getting parameters
try:
    opts, args = getopt.getopt(sys.argv[1:], "hf:p:v", ["help", "output="])
except getopt.GetoptError as err:
    # print help information and exit:
    print(err)
    usage()
    sys.exit(2)

f, r, R = 0, 0, 0
for o, a in opts:
    if o == "-v":
        verbose1 = True
        #print("Verbose: %s" % (verbose1))
    elif o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o == "-p":
        verbosePeriod = int(a)
        #print("Verbose period: %d" % (verbosePeriod))
    elif o in ("-f", "--fanout"):
        fanout = int(a)
        #print("Fanout: %d" % (fanout))
    else:
        assert False, "unhandled option"


# Creating a tree topology
nodes = 1 + fanout + fanout*fanout
print("Tree topology with fanout=%d => %d nodes, %d in the last level..." % (fanout, nodes, fanout*fanout))
#print("fanout: " + str(fanout))
#print("nodes:  " + str(nodes))
if verbose1: print (list(_tree_edges(nodes,fanout)))
  #[(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (1, 6), (2, 7), (2, 8), (2, 9), (3, 10), (3, 11), (3, 12)]

G = nx.Graph(_tree_edges(nodes,fanout))
#print(G)

# Generate all possible paths on leaf nodes
starttime=time.time()
k = 0
for i in range(1+fanout+1, 1+fanout+fanout*fanout):
  for j in range(1+fanout+1, 1+fanout+fanout*fanout):
    k = k + 1
    if verbose2 and k % verbosePeriod == 0:
      print("Calculated path no. " + str(k))
    if i != j:
      path = nx.shortest_path(G, i, j)
      if verbose1: print("path from " + str(i) + " to " + str(j) + ": " + str(path))

endtime=time.time()
totaltime=round((endtime - starttime), 3)

print("Calculated paths: " + str(k))

if verbose1: print("Start time: " + str(starttime))
if verbose1: print("End time  : " + str(endtime))
print("Total time: " + str(totaltime))
