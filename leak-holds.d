#!/usr/sbin/dtrace -Cs

/*
 * leak.d: help track down a per-zone vnode leak by:
 *
 *    o identifying the per-zone vnode_t that's subject to the leak, recording
 *      these in an associative array keyed by zonename.
 *
 *    o tracing operations that may bump the refcount of such vnodes and
 *      dumping the corresponding zone's vnode's refcount both before and
 *      after the function is called.
 *
 *    o tracing a marlin-specific event that indicates that the zone is halted
 *      and dumping out the refcount.  If it increases, we expect that we've
 *      hit the problem.
 */

#pragma D option quiet
#pragma D option dynvarsize=4m
#pragma D option cleanrate=202hz

int lastcount[string];
vnode_t *zonevnodes[string];

BEGIN
{
	printf("tracing. timestamp %d => %Y.%09d\n",
	    timestamp, walltimestamp, walltimestamp % 1000000000);
}

/*
 * Identify the per-zone vnode_t that we should look at.  We can trigger on any
 * operation that will happen during the zone's lifetime.  We expect that the
 * vnode_t will never go away because it will always be referenced at least by
 * the ARC and we never try to unmount the filesystem (which would purge the ARC).
 */
fbt::zfs_lookup:entry
/self->pnp == NULL/
{
	self->pnp = args[2];
	self->depth = stackdepth;
}

fbt::zfs_lookup:return
/arg1 == 0 &&
 self->pnp != NULL && stackdepth == self->depth &&
 (this->vp = *(self->pnp)) != NULL &&
 this->vp->v_path != NULL &&
 strstr(this->vp->v_path, "/zones") != NULL &&
 strstr(this->vp->v_path, "/root") != NULL &&
 strlen(this->vp->v_path) == 
 sizeof ("/zones/1531ca95-3939-4824-98a0-add14a5677ed/root") - 1/
{
	this->zname = substr(this->vp->v_path, sizeof ("/zones/") - 1,
	    sizeof ("1531ca95-3939-4824-98a0-add14a5677ed") - 1);
}

fbt::zfs_lookup:return
/this->zname != NULL &&
 (zonevnodes[this->zname] == 0 || zonevnodes[this->zname] != *self->pnp)/
{
	interested[zonevnodes[this->zname]] = 0;
	interested[*self->pnp] = 1;
	zonevnodes[this->zname] = *self->pnp;
	printf("%d zone \"%s\" => vnode %p (%s)\n",
	    timestamp, this->zname, zonevnodes[this->zname],
	    stringof(zonevnodes[this->zname]->v_path));
}

fbt::zfs_lookup:return
{
	self->pnp = NULL;
	self->depth = 0;
	this->zname = NULL;
	this->vp = 0;
}

/*
 * Trace a bunch of operations that we expect may bump the refcounts in
 * question.  We'll start with fop operations and assume that whatever's
 * causing this is happening in the context of the zone in question.
 */
sdt:::vn-hold,
sdt:::vn-rele
/execname != "dtrace" && interested[(vnode_t *)arg0]/
{
	this->vnp = (vnode_t *)arg0;
	printf("%d %s %3d %p (%s) %s\n", timestamp, probename,
	    this->vnp->v_count, this->vnp, stringof(this->vnp->v_path),
	    curpsinfo->pr_psargs);
	stack();
	jstack(80, 8192);
	this->vnp = 0;
}

/*
 * When we do the "zfs rollback" for a zone, we know that zone is halted.
 */
proc:::exec-success
/strstr(curpsinfo->pr_psargs, "zfs rollback zones/") != 0/
{
	this->zname = strtok(curpsinfo->pr_psargs, "/");
	this->zname = strtok(NULL, "@") + 1;
	printf("%d rollback %s\n", timestamp, this->zname);
}

proc:::exec-success
/this->zname != NULL && zonevnodes[this->zname] &&
 lastcount[this->zname] != 0 &&
 zonevnodes[this->zname]->v_count != lastcount[this->zname]/
{
	printf("%d zone %s: leak!\n", timestamp, this->zname);
}

proc:::exec-success
/this->zname != NULL && zonevnodes[this->zname]/
{
	printf("%d zone %s down: count = %d\n", timestamp, this->zname, 
	    zonevnodes[this->zname]->v_count);
	lastcount[this->zname] = zonevnodes[this->zname]->v_count;
}

proc:::exec-success
{
	this->zname = 0;
}
