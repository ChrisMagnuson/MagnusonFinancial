function Install-MagnusonFinancial {
    Install-Module -Name GoogleDynamicDNSTools
    Install-Module -Name CredentialManager
}

function Get-OfficeComputers {
    Import-Clixml -Path "$env:USERPROFILE\OfficeComputers.xml"
}

Function Enable-AbilityToRemoteToOfficeComputers {

    $OfficeComputers = Get-OfficeComputers

    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($OfficeComputers -join ",") -Force
    Get-Item WSMan:\localhost\Client\TrustedHosts
}

Function New-OfficeComputerCredential {
    param (
        [ValidateScript({$_ -in (Get-OfficeComputers)})]$ComputerName
    )
    Get-Credential | Export-Clixml "$env:USERPROFILE\$($ComputerName)Credential.txt"
}

Function New-OfficeComputerPSSession {
    param (
        [ValidateScript({$_ -in (Get-OfficeComputers)})]$ComputerName
    )
    $Credential = Import-Clixml "$env:USERPROFILE\$($ComputerName)Credential.txt"
    New-PSSession -ComputerName $ComputerName -Credential $Credential
}

Function Enter-OfficeComputerPSSession {
    param (
        [ValidateScript({$_ -in (Get-OfficeComputers)})]$ComputerName
    )
    $Credential = Import-Clixml "$env:USERPROFILE\$($ComputerName)Credential.txt"
    Enter-PSSession -ComputerName $ComputerName -Credential $Credential

}

Function Invoke-OfficeComputerCommand {
    param (
        [ValidateScript({$_ -in (Get-OfficeComputers)})]$ComputerName,
        $ScriptBlock
    )
    $Credential = Import-Clixml "$env:USERPROFILE\$($ComputerName)Credential.txt"
    Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $ScriptBlock
}


Function Get-StatusOfRoboCopyBackup {
    param (
        [ValidateScript({$_ -in (Get-OfficeComputers)})]$ComputerName
    )
    
    $ScheduledTaskInfo = Invoke-OfficeComputerCommand -ComputerName $ComputerName -ScriptBlock {
        Get-ScheduledTask -TaskPath \ | 
        where TaskName -eq Robocopy | 
        Get-ScheduledTaskInfo 
    }

    [PSCustomObject][Ordered]@{
        ComputerName = $ComputerName
        LastRunTime = $ScheduledTaskInfo.LastRunTime
        Succeeded = $ScheduledTaskInfo.LastTaskResult -eq 0
    }
}

function Set-GoogleDomainsCredential {
    param (
        $APIUserID,
        $APIPassword
    )    
    New-StoredCredential -UserName $APIUserID -Password $APIPassword -Target GoogleDomains
}

function Get-GoogleDomainsCredential {
    Get-StoredCredential -Target GoogleDomains
}

function Update-GoogleDynamicDNS {
    #http://port1433.com/2017/02/20/updating-google-domains-dynamic-dns-with-powershell/#prettyPhoto
    Import-Module GoogleDynamicDNSTools

    $LogDate = Get-Date
    $LogFileName = "GoogleDNSUpdateLog_" + $LogDate.Month + $LogDate.Day + $LogDate.Year + "_" + $LogDate.Hour + $LogDate.Minute + $LogDate.Second + ".txt"

    $Credential = Get-GoogleDomainsCredential

    Start-Transcript -Path ("$Home\DNSLogs\" + $LogFileName)

    Update-GoogleDynamicDNS -credential $Credential -domainName "elkbanking.com" -subdomainName "magnusonfinancial" -Verbose

    #Clean up old log files
    Get-ChildItem -Path "$Home\DNSLogs" | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} | Remove-Item -Verbose

    Stop-Transcript
}

function Set-GuacamoleMYSQLCredential {
    param (
        $UserName,
        $Password
    )
    New-StoredCredential -Target GuacamoleMYSQL -UserName $UserName -Password $Password
}

function Get-GuacamoleMYSQLCredential {
    Get-StoredCredential -Target GuacamoleMYSQL
}

function New-PersistObject {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Object,
        [Parameter(Mandatory)]$Name,
        $Shard = "Default"
    )
    $Object | Export-Clixml -Path "$env:USERPROFILE\Persist\$Shard\$Name.xml"
}

function Get-PersistObject {
    param (
        [Parameter(Mandatory)]$Name,
        $Shard = "Default"
    )
    Import-Clixml -Path "$env:USERPROFILE\Persist\$Shard\$Name.xml"
}

function New-PersistShard {
    param (
        $Shard = "Default"
    )
    New-Item -ItemType Directory -Path $env:USERPROFILE\Persist\$Shard\
}

function Get-GuacamoleContainerAttributes {
    Get-PersistObject -Name GuacamoleContainerAttributes
}

function Invoke-ProvisionGuacamoleStack {
    $MYSQLCredential = Get-GuacamoleMYSQLCredential
    $GuacamoleContainerAttributes = Get-GuacamoleContainerAttributes

    docker run --name guacamole --link some-guacd:guacd `
        --link mysql:mysql `
        -e MYSQL_DATABASE=guacamole_db `
        -e MYSQL_USER=$($MYSQLCredential.UserName)    `
        -e MYSQL_PASSWORD=$($MYSQLCredential.GetNetworkCredential().password) `
        -e VIRTUAL_HOST=$($GuacamoleContainerAttributes.Host) `
        -e LETSENCRYPT_HOST=$($GuacamoleContainerAttributes.Host) `
        -e LETSENCRYPT_EMAIL=$($GuacamoleContainerAttributes.LETSENCRYPT_EMAIL) `
        -d -p 8080:8080 guacamole/guacamole

    #docker run --name guacamole3 --link guacd:guacd --link mysql:mysql -e MYSQL_DATABASE=guacamole_db -e MYSQL_USER=$($MYSQLCredential.UserName) -e MYSQL_PASSWORD=$($MYSQLCredential.GetNetworkCredential().password) -d -p 8081:8080 guacamole/guacamole
}

function Invoke-ProvisionNginXReverseProxyWithSSLManagedByLetsEncrypt {
docker run -d -p 8080:80 -p 8090:443 `
    --name nginx-proxy `
    -v /path/to/certs:/etc/nginx/certs:ro `
    -v /etc/nginx/vhost.d `
    -v /usr/share/nginx/html `
    -v /var/run/docker.sock:/tmp/docker.sock:ro `
    --label com.github.jrcs.letsencrypt_nginx_proxy_companion.nginx_proxy=true `
    jwilder/nginx-proxy

docker run -d `
    -v /path/to/certs:/etc/nginx/certs:rw `
    -v /var/run/docker.sock:/var/run/docker.sock:ro `
    --volumes-from nginx-proxy `
    jrcs/letsencrypt-nginx-proxy-companion
}

function Remove-NginXReverseProxyWithSSLManagedByLetsEncryptContainers {
    docker rm /nginx-proxy -f
    docker rm trusting_turing
}

function Start-BrowserPointedToGuacamoleClient {
    $GuacamoleContainerAttributes = Get-GuacamoleContainerAttributes

    start http://$($GuacamoleContainerAttributes.Host):8080/guacamole/#/
}

function New-GuacamoleStackFirewallRules {
    New-NetFirewallRule -Name Guacamole_HTTP -DisplayName "Guacamole HTTP" -Group Guacamole -Direction Inbound -Protocol TCP -Action Allow -Enabled True -RemotePort Any -LocalPort 8080 
    New-NetFirewallRule -Name Guacamole_HTTPS -DisplayName "Guacamole HTTPS" -Group Guacamole -Direction Inbound -Protocol TCP -Action Allow -Enabled True -RemotePort Any -LocalPort 8090
}