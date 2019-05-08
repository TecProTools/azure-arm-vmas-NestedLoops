# 13Apr19 vol21


### Initialize empty disks after empty disk is added to nominated vm.
## https://docs.microsoft.com/en-us/azure/virtual-machines/windows/attach-disk-ps#initialize-the-disk 


  ## Track message.
  $logNameToInstall = "algoRigsLog"
  $logNameSrc = $logNameToInstall + "Src"
  #$logNameToInstall = $logName
  #$logNameSrc = $logSrc
  $dateTime = Get-Date -Format g 

    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
    -Message "$dateTime : Script initialize emptyDisk on nominated vm, started."


$disks = Get-Disk | Where-Object partitionstyle -eq 'raw' | Sort-Object number
    $letters = 70..89 | ForEach-Object { [char]$_ }
    $count = 0
    $labels = "data1","data2"

    foreach ($disk in $disks) {
        $driveLetter = $letters[$count].ToString()
        $disk | 
        Initialize-Disk -PartitionStyle MBR -PassThru |
        New-Partition -UseMaximumSize -DriveLetter $driveLetter |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel $labels[$count] -Confirm:$false -Force
	      $count++
    }

    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
    -Message "$dateTime : Script initialize emptyDisk on nominated vm, ended."