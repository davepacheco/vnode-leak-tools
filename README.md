Here's a D script and a perl post-processor that I used to debug a vnode
refcount leak on illumos.  I had added SDT probes for vnode hold and rele by
inserting them into the macros that are used in most (but not all) places.
