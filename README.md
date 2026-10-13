# Microsoft Product Key Checker

A small command-line tool for Windows, Office, SQL Server, Exchange, Visual Studio, and other
supported Microsoft products. It checks whether a product key is valid and shows what it is:
edition, license type and channel, Product ID, Extended PID, Activation ID and, optionally, the
remaining activation count reported by Microsoft's activation service.

Created by [salnaggar](https://github.com/salnaggar).

## Requirements

- Windows (the script calls the `PidGenX` function in Windows' own `pidgenx.dll`)
- Python 3.10 or newer, no extra packages

## Usage

```
python check.py
```

1. Enter the product key (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`).
2. Pick the software package, or choose **0. Auto-detect / I don't know** (also the default when you
   press Enter). Auto-detection checks each unique available configuration file locally and shows
   the matching packages, descriptions, and licence channels.
3. If several configurations match, pick a match to see its details. Products can share key families,
   so multiple matches do not necessarily identify one exact software version.
4. Optionally enter `y` when asked to check the MAK count online. Press Enter to skip it.

If auto-detection finds no match, the key may belong to a product whose configuration is not included.
You can run the script again and select **Load Custom PkeyConfig** with the appropriate file.

Example output:

```
Product Key:     XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
Package:         Windows 11
Key Status:      Valid for selected configuration
Product ID:      00330-81493-87404-AA570
Extended PID:    XXXXX-03308-149-387404-00-1033-19045.0000-2842026
Activation ID:   4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c
Edition Type:    Professional
Description:     Win 10 RTM Professional Retail
Edition ID:      [TH]res-v3308
License Type:    Retail
License Channel: Retail
Crypto ID:       3308
MAK Count:       -1 (ErrorCode 0x86)
```

## How it works

- **Validation is offline.** The key is decoded by `PidGenX` against a `pkeyconfig.xrm-ms` file, the
  database Microsoft ships with each product that describes its key ranges.
- **The optional MAK count is online.** If you opt in, the Extended PID (not the key itself) is sent to
  `activation.sls.microsoft.com`, which answers with the number of activations left. Keys that are
  not volume (MAK) keys return `-1` with an error code.

## Supported packages

Windows Vista through Windows 11, Windows Server, Windows Embedded, Office 2010-2016, Exchange,
SQL Server, Visual Studio and the Office KMS hosts. Extra menu entries:

- **Load Custom PkeyConfig** - use any `.xrm-ms` file you have.
- **This PC's pkeyconfig** - use the files of the Windows installation running the script.

Windows 11 keys of the common editions are described as "Win 10" because Windows 11 reuses the
Windows 10 key families; that text comes from Microsoft's file.

## Notes

- The files in `pkeyconfig/` are Microsoft's and are included unmodified. The Windows 11 files are
  the 22H2 (build 22621) versions.
- The package list and request format follow the behaviour of the "Microsoft PID Checker 1.49"
  utility.
- A valid key is not proof of a genuine licence: the check only confirms the key fits the product.
