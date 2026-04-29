# Testing Procedure

After setup has been completed, the following sequences have been used to verify the setup.

## Log Storage

The `jalop_rec.py` script will create a local directory `jalop_records`. Subdirectories will be created to seperate Log and Audit files.

Each log creates the associated Metadata file, and labels that and the Payload with the unique JalEntryID.

## Syslog Message Testing

```
logger -ip {facility}.{level} "{message}"
```

## Auditd Message Testing

```
sudo auditctl -m "{message}"
```