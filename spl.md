<details><summary>Bro Query</summary>
  
```plaintext
index=bro sourcetype=corelight_conn earliest= latest=now()
```
</details>

# Summary Index

index=central_summary source=summary_conn_dest earliest= latest=now()

# List all indexes.

| eventcount summarize=false index=* | dedup index | fields index
