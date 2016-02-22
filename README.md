## check_couchbase

There are three checks implemented in this script:
1. Node status: node is active and healthy
2. Cluster overall status: memory, disk usage and make sure each node is active and healthy
3. XDCR health: this check looks at replication checkpoints and checkpoint failures. The pools/default/tasks endpoint is also checked for xdcr errors.

For details see ./check_couchbase -h 

