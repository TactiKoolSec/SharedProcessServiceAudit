function FindSharedServiceTargets
{
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
                $scmsvcpath = "HKLM:\SYSTEM\CurrentControlSet\Services\"+$svc+"\Parameters"
                
                #All hosted services registered with SCM
                if(Test-Path $scmsvcpath)
                {

                   $SvcDll = (Get-ItemProperty -Path $scmsvcpath -Name ServiceDll).ServiceDll
                   If(((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start).Start -eq 4) -and (!(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name DependOnService -ErrorAction SilentlyContinue)))
                   {
                    write-host "Disabled Shared Process Service: " $svc $hostedsvc.Name $SvcDll
                 
                   }
                   
                   if(!(Test-Path $SvcDll))
                   {
                   write-host "ServiceDLL not found on disk: " $svc $hostedsvc.Name $SvcDll
                   }
                  
                }
                
            }
    

        }
        
    }

}

FindSharedServiceTargets