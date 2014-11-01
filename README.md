== Attack Robustness and Centrality of Complex Networks

This file describes our Python based software for evaluating the robustness 
of complex networks under different kinds of targeted attacks as described 
in [our paper](http://dx.doi.org/10.1371/journal.pone.0059613).

`robustness.py`: This script performs robustness analysis on the given 
network, which involves removing nodes from the network at random, or in 
reverse order of centrality measures (degree, betweenness, closeness, and 
eigenvector), and comparing the size of the largest component in the 
network to the fraction of nodes removed. The script is run as 

```bash
python robustness.py <infile> <outfile> <recalculate>
```

where `infile` is the name of the network file in gml format, `outfile` is the 
name of the output (pdf) file in which the results of the analysis is 
saved, and `recalculate` (True of False) specifies if the targeted attack is 
simultaneous (False), or sequential (True).

== Software Dependencies

* [igraph](http://igraph.org/)
* [NetworkX](https://networkx.github.io/)
* [NumPy](http://www.numpy.org/)
* [Matplotlib](http://matplotlib.org/)

== Contact

If you have any questions about the software, please email 
swami.iyer@gmail.com.
