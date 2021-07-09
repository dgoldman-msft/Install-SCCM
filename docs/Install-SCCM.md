---
external help file:
Module Name:
online version:
schema: 2.0.0
---

# Install-SCCM

## SYNOPSIS
Automated install of SCCM

## SYNTAX

```
Install-SCCM [[-DomainContoller] <String>] [[-SCCMServer] <String>] [[-LoggingPath] <String>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This is a script to kick off an automated installation of SCCM

## EXAMPLES

### EXAMPLE 1
```
Install-SCCM -DomainController DC1 -SCCMServer SCCM
```

## PARAMETERS

### -DomainContoller
Domain Controller where accounts will be created

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: DC1
Accept pipeline input: False
Accept wildcard characters: False
```

### -SCCMServer
Name of your SCCM server if not on the same machine

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: SCCM
Accept pipeline input: False
Accept wildcard characters: False
```

### -LoggingPath
Path to PowerShell transcript logging

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: C:\Logs\SCCMInstall.Log
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Installation notes: https://systemcenterdudes.com/complete-sccm-installation-guide-and-configuration/
As of right now you need to manually install SQL Server and SCCM so you can define your SQL instance as well as Primary Site and transport options

## RELATED LINKS
