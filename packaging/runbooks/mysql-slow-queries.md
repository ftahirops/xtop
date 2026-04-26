---
name: MySQL slow-query / IO pressure
bottleneck: io, cpu
app: mysql, mariadb
culprit: mysqld, mariadbd
---

## Diagnosis

MySQL/MariaDB is the culprit. Typical causes:

1. A slow query is scanning a large table.
2. `innodb_buffer_pool_size` is too small — you're hitting disk for working-set reads.
3. A long-running transaction holding locks.

Collect evidence:

```bash
mysql -e "SHOW PROCESSLIST;" | head -20
mysql -e "SHOW ENGINE INNODB STATUS\G" | grep -E "Buffer pool|read requests|reads/s"
mysql -e "SELECT * FROM performance_schema.events_statements_summary_by_digest \
          ORDER BY sum_timer_wait DESC LIMIT 5\G"
# Slow-query log (if enabled)
tail -100 /var/log/mysql/slow.log
```

## Fix

- Kill the offender from `SHOW PROCESSLIST` if safe: `KILL <thread_id>;`.
- If buffer pool misses are high: increase `innodb_buffer_pool_size` to ~70 % of RAM.
- Add missing indexes — check `EXPLAIN <query>` for the slow statements from the digest table above.
- Make sure long transactions commit: `SELECT * FROM information_schema.innodb_trx ORDER BY trx_started LIMIT 5;`.

If this is a recurring pattern, enable the slow query log (`long_query_time=1`) and route it
to `pt-query-digest` for a weekly review.
