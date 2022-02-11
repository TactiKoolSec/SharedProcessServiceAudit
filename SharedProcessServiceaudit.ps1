function Get-SharedProcessServices
{
    $AllHostedSvcs = @()
    $AllRegHostedSvcs = @()
    $hostedsvcskey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\'
    $hostedsvcs = $hostedsvcskey.PSObject.Properties
    foreach($hostedsvc in $hostedsvcs)
    {
        if(($hostedsvc.Name -notlike "PSPath") -and  ($hostedsvc.Name -notlike "PSParentPath") -and ($hostedsvc.Name -notlike "PSChildName") -and ($hostedsvc.Name -notlike "PSDrive") -and ($hostedsvc.Name -notlike "PSProvider"))
        {
            #List of all hosted service groups
            $hostedsvcname = $hostedsvc.Name
            $hostedsvcvalues = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\' -Name $hostedsvcname).$hostedsvcname
            #Write-Host $hostedsvcname
            #List of all services for each service group
            foreach ($svc in $hostedsvcvalues)
            {
                #Output $hostedsvcname and $svc to a CSV for all hosted service listing
                $AllHostedServicesObject = New-Object PSObject
                $AllHostedServicesObject | Add-Member -MemberType NoteProperty -Name "Endpoint" -Value $env:COMPUTERNAME
                $AllHostedServicesObject | Add-Member -MemberType NoteProperty -Name "HostedServiceGroup" -Value $hostedsvcname
                $AllHostedServicesObject | Add-Member -MemberType NoteProperty -Name "HostedService" -Value $svc
                $AllHostedSvcs += $AllHostedServicesObject

                $scmsvcpath = "HKLM:\SYSTEM\CurrentControlSet\Services\"+$svc+"\Parameters"
                #All hosted services registered with SCM
                if(Test-Path $scmsvcpath)
                {

                   $SvcDll = (Get-ItemProperty -Path $scmsvcpath -Name ServiceDll).ServiceDll
                   #output below to csv for listing of all registered hosted services w/ their loaded Dlls 
                   #Write-Host "ServiceName: "$svc " ServiceDll: " $SvcDll " ControlSetPath: " $scmsvcpath " ServiceGroupName: " $hostedsvcname
                   $SvcDllSig = Get-AuthenticodeSignature -FilePath $SvcDll
                   $SvcDllHash = Get-FileHash -Algorithm MD5 $SvcDll
                   $SvcDllNTFS = Get-Item -Path $SvcDll 
                   #write-host $signed.Status " " $hash.hash " " $SvcDll " " $Svc " " "netsvc"
                   $AllRegHostedSvcsObject = New-Object PSObject
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "Endpoint" -Value $env:COMPUTERNAME
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "ServiceName" -Value $svc
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "ServiceDll" -Value $SvcDll
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "ServiceDllSigStatus" -Value $SvcDllSig.Status
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "ServiceDllMD5" -Value $SvcDllHash.Hash
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "ServiceGroup" -Value $hostedsvcname
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "CreationTimeUTC" -Value $SvcDllNTFS.CreationTimeUtc
                   $AllRegHostedSvcsObject | Add-Member -MemberType NoteProperty -Name "LastWriteTimeUTC" -Value $SvcDllNTFS.LastWriteTimeUtc
                   $AllRegHostedSvcs += $AllRegHostedSvcsObject
                    
                    
                }

            }
    

        }
        
    }
    $AllHostedSvcs | Export-Csv -NoTypeInformation $.\SharedProcessServices.csv
    $AllRegHostedSvcs | Export-Csv -NoTypeInformation $.\ActiveSharedProcessServices.csv
}

Get-SharedProcessServices