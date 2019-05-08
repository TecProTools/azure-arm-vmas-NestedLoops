#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                           #
#################################################################################################################################

param
(
    [Parameter(Mandatory = $true)]
    [string] $HostName
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    try
    {
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Attempt to delete winRM listener."
        $config = Winrm enumerate winrm/config/listener
        foreach($conf in $config)
        {
            if($conf.Contains("HTTPS"))
            {
                #Write-Verbose "HTTPS is already configured. Deleting the exisiting configuration."
                Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
                -Message "HTTPS is already configured. Deleting the exisiting configuration."
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
                break
            }
        }
    }
    catch
    {
        #Write-Verbose -Verbose "Exception while deleting the listener: " + $_.Exception.Message
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Exception while deleting the listener: " + $_.Exception.Message
    }
}

function Create-Certificate
{
    param(
        [string]$hostname
    ) 
    
    
    ## MakeCert at this path work 26Mar19 see vol20. Note required certificate parameters.
    # https://github.com/Azure/azure-quickstart-templates/blob/master/201-vm-winrm-windows/ConfigureWinRM.ps1
    # note: makecert ocassionally produces negative serial numbers which golang tls/crypto <1.6.1 cannot handle.
	# https://github.com/golang/go/issues/8265
    # $serial = Get-Random
    #    .\makecert -r -pe -n CN=$hostname -b 01/01/2012 -e 01/01/2022 -eku 1.3.6.1.5.5.7.3.1 -ss my -sr localmachine -sky exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -# $serial 2>&1 | Out-Null
    

    ## Self Signed certificate.
    # https://www.techdiction.com/2016/02/12/create-a-custom-script-extension-for-an-azure-resource-manager-vm-using-powershell/ 
    #$thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My).Thumbprint
    $thumbprint = (New-SelfSignedCertificate -DnsName $hostname -CertStoreLocation Cert:\LocalMachine\My).Thumbprint
    #$thumbprint=(Get-ChildItem cert:\Localmachine\my | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint
    if(-not $thumbprint)
    {
        #throw "Failed to create the test certificate."
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
            -Message "Failed to assemble test certificate."
    }
    else 
    { 
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Assembled test certificate hostname, $hostname, thumbprint, $thumbprint."
    }
    return $thumbprint
}

function Configure-WinRMHttpsListener
{
    param([string] $HostName,
          [string] $port)


    ## Delete the WinRM Https listener if already configured.
    Delete-WinRMListener
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Deleted WinRMListener." 
    
    
    ## Verify test certificate existence.
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1)
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
        # Install test certificate.
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
            -Message "Certificate did not exist, create test cert."
        $thumbprint = Create-Certificate -hostname $HostName   
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped
        # Delete the certificate
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force
        $thumbprint = Create-Certificate -hostname $HostName
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
            -Message "Cert exists but private key is missing. Deleted cert and installed new cert, $thumbprint."
    }


    ## Install winRM HTTPS listener.
    $WinrmCreate= "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$hostName`";CertificateThumbprint=`"$thumbPrint`"}"
    invoke-expression $WinrmCreate
    winrm set winrm/config/service/auth '@{Basic="true"}'  | Out-Null
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Create winrm https listener for $hostName . "
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message  "Ended, add new firewall rule. "
}


#################################################################################################################################
#                                              Configure WinRM With Log                                                                #
#################################################################################################################################



### Install algoRigs event log. 
  ## This script runs on vm, loaded as vm extension.
    # https://www.petri.com/use-powershell-to-create-custom-log-events
  ## Track message.
    $logNameToInstall = "algoRigsLog"
    $logNameSrc = $logNameToInstall + "Src"
    $dateTime = Get-Date -Format g 
    try {
      get-eventlog  $logNameToInstall -ErrorAction Stop | Out-Null
      Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "$dateTime : Found previously installed $logNameToInstall solution automation event log." 

      Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
      -Message "$dateTime : Script ConfigureWinRmAndLog.ps1 started."
    }
    catch {
      Write-Output "Sa event log not installed, create."
      try {
        New-EventLog -LogName  $logNameToInstall -Source $logNameSrc
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
          -Message "Installed $logNameToInstall solution automation event log."   
        write-verbose 'Sa event log installed.'   
        Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "$dateTime : Script ConfigureWinRmAndLog.ps1 started."
      }
      catch {
        Write-Error "Failed, sa event log install, $logNameToInstall."
      }
    }
#endRegion



### Install winRM
    ## Adjust envelope size. 
    # The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb. The small envelop size if not changed
    # results in WS-Management service responding with error that the request size exceeded the configured MaxEnvelopeSize quota.
    winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'  | Out-Null
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Completed winrm/config resize." 


    ## Configure https listener
    $winrmHttpsPort=5986
    Configure-WinRMHttpsListener $HostName $winrmHttpsPort
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Completed winRMHttpsListener HostName, $HostName, Port, $winrmHttpsPort." 


    ## Add firewall exception
    Add-FirewallException -port $winrmHttpsPort
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
        -Message "Added firewall exception port, $winrmHttpsPort. " 


    ## Initialize empty disks
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
    -Message "Verify, next message confirms extension, initialize-emptyDisk-onNomVm.ps1, ran."
    . ./compute/vmExtensions/vmExtScripts/winRM/initialize-emptyDisk-onNomVm.ps1 


    ## Trace.
    Write-EventLog -LogName  $logNameToInstall -Source $logNameSrc -EventId 1000 `
    -Message "$dateTime : Script ConfigureWinRmAndLog.ps1 ended."
# endregion
#################################################################################################################################
#################################################################################################################################
