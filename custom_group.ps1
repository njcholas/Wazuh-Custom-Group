if (!(Test-Path "C:\Program Files (x86)\ossec-agent")) {

    $ip = (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True').IPAddress[0]
    $thirdOctet = $ip.Split('.')[2]
    
    $group = "CustomGroup-$thirdOctet"
    
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.8-1.msi -OutFile ${env:tmp}\wazuh-agent-4.3.8.msi; msiexec.exe /i ${env:tmp}\wazuh-agent-4.3.8.msi /q WAZUH_MANAGER='manager_ip' WAZUH_REGISTRATION_SERVER='server_ip' WAZUH_AGENT_GROUP=$group  
    
    Start-Sleep -Seconds 5
    
    Copy-Item "C:\Util\Wazuh\ossec.conf" -Destination "C:\Program Files (x86)\ossec-agent" -Force
    
    $content = Get-Content C:\Util\Wazuh\ossec.conf 
    $content -Replace '<groups>Windows</groups>',"<groups>$group</groups>" | Set-Content C:\'Program Files (x86)'\ossec-agent\ossec.conf
    
    start-service WazuhSvc
    } else {
        Write-Output "Wazuh agent is already installed"
    }