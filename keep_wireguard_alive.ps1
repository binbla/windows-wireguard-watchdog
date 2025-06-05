# wireguard 配置文件
$WireguardConfigFilePath = "C:\Users\admin\Documents\Wireguard\Home.conf" 
# 检查IP变更时间间隔
$IntervalSeconds = 10
# DNS服务器地址,不设置会从 wireguard 配置文件中读取
$DNS = "dns9.hichina.com"
# 是否优先使用IPv6（true/false）
$PreferIPv6 = $true

function getFilenameByPath {
    param (
        [string]$path
    )
    Write-Host "[INFO] 获取文件名: $path"
    $tempArr = $path.Split("\")
    $filename = $tempArr[$tempArr.Length - 1].Split(".")[0] + "temp"
    Write-Host "[INFO] 文件名为: $filename"
    return $filename
}

function getEndpointByFile {
    param (
        [string]$path
    )
    Write-Host "[INFO] 读取配置文件获取 Endpoint: $path"
    Get-Content -Path $path | ForEach-Object { 
        if ($_ -like "*Endpoint*") {
            $endpoint = $_.Split('=')[1].Split(':')[0].Trim()
            Write-Host "[INFO] Endpoint 行: $_"
            Write-Host "[INFO] Endpoint 域名: $endpoint"
            return $endpoint
        }
    }
}

function getDNSByFile {
    param (
        [string]$path
    )
    Write-Host "[INFO] 获取 DNS 配置"
    $ipv6Pattern = '^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$'
    if ($DNS) {
        $domainPattern = '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
        $ipv4Pattern = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        Write-Host "[INFO] DNS 配置为: $DNS"
        if ($DNS -match $domainPattern) {
            Write-Host "[INFO] DNS 是域名，尝试解析"
            $DnsIPAddress = getDnsIp -domain $DNS -DnsServer "114.114.114.114" -PreferIPv6:$PreferIPv6
            Write-Host "[INFO] 域名解析结果: $DnsIPAddress"
            if ($DnsIPAddress -ne "failed") {
                return $DnsIPAddress
            }
        }
        elseif ($DNS -match $ipv4Pattern) {
            Write-Host "[INFO] DNS 是 IPv4 地址: $DNS"
            return $DNS
        }
        elseif ($DNS -match $ipv6Pattern) {
            Write-Host "[INFO] DNS 是 IPv6 地址: $DNS"
            return $DNS
        }
        Write-Host "[WARN] DNS 配置无效，使用默认 114.114.114.114"
        return "114.114.114.114"
    }
    Write-Host "[INFO] 从配置文件读取 DNS"
    Get-Content -Path $path | ForEach-Object { 
        if ($_ -like "*DNS*") {
            $dnsFromFile = $_.Split('=')[1].Trim()
            Write-Host "[INFO] 配置文件 DNS: $dnsFromFile"
            return $dnsFromFile
        }
    }
}

function getDnsIp() {
    param (
        [string]$domain,
        [string]$DnsServer,
        [bool]$PreferIPv6 = $false
    )
    Write-Host "[INFO] 解析域名 $domain 使用 DNS 服务器 $DnsServer, PreferIPv6: $PreferIPv6"
    $ip = "failed"
    if ($PreferIPv6) {
        $result = Resolve-DnsName $domain -Server $DnsServer -Type AAAA -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
        if ($result) {
            $ip = $result[0].IPAddress
            Write-Host "[INFO] 域名 $domain 解析到 IPv6: $ip"
        } else {
            Write-Host "[WARN] 域名 $domain IPv6 解析失败，尝试 IPv4"
            $result = Resolve-DnsName $domain -Server $DnsServer -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
            if ($result) {
                $ip = $result[0].IPAddress
                Write-Host "[INFO] 域名 $domain 解析到 IPv4: $ip"
            } else {
                Write-Host "[WARN] 域名 $domain 解析失败，尝试备用 DNS 114.114.114.114"
                $result = Resolve-DnsName $domain -Server "114.114.114.114" -Type AAAA -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
                if ($result) {
                    $ip = $result[0].IPAddress
                    Write-Host "[INFO] 备用 DNS 解析到 IPv6: $ip"
                } else {
                    $result = Resolve-DnsName $domain -Server "114.114.114.114" -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
                    if ($result) {
                        $ip = $result[0].IPAddress
                        Write-Host "[INFO] 备用 DNS 解析到 IPv4: $ip"
                    } else {
                        Write-Host "[ERROR] 域名 $domain 解析失败"
                    }
                }
            }
        }
    } else {
        $result = Resolve-DnsName $domain -Server $DnsServer -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
        if ($result) {
            $ip = $result[0].IPAddress
            Write-Host "[INFO] 域名 $domain 解析到 IPv4: $ip"
        } else {
            Write-Host "[WARN] 域名 $domain IPv4 解析失败，尝试 IPv6"
            $result = Resolve-DnsName $domain -Server $DnsServer -Type AAAA -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
            if ($result) {
                $ip = $result[0].IPAddress
                Write-Host "[INFO] 域名 $domain 解析到 IPv6: $ip"
            } else {
                Write-Host "[WARN] 域名 $domain 解析失败，尝试备用 DNS 114.114.114.114"
                $result = Resolve-DnsName $domain -Server "114.114.114.114" -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
                if ($result) {
                    $ip = $result[0].IPAddress
                    Write-Host "[INFO] 备用 DNS 解析到 IPv4: $ip"
                } else {
                    $result = Resolve-DnsName $domain -Server "114.114.114.114" -Type AAAA -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
                    if ($result) {
                        $ip = $result[0].IPAddress
                        Write-Host "[INFO] 备用 DNS 解析到 IPv6: $ip"
                    } else {
                        Write-Host "[ERROR] 域名 $domain 解析失败"
                    }
                }
            }
        }
    }
    return $ip
}

function Start-WireguardTunnel {
    param (
        [string]$TunnelName,
        [string]$EndpointIp
    )
    $serviceName = "WireGuard Tunnel: $TunnelName";
    Write-Host "[INFO] 检查 WireGuard 服务: $serviceName"
    $ExistsService = Get-Service $serviceName -ErrorAction SilentlyContinue;
    if ($ExistsService) {
        Write-Host "[INFO] 停止 WireGuard 服务"
        Invoke-Expression "wireguard /uninstalltunnelservice $TunnelName"
    }
    Write-Host "[INFO] 启动 WireGuard 服务"
    Start-Sleep -Seconds 3
    $WireguardConfigFilePathTemp = $WireguardConfigFilePath.Substring(0, $WireguardConfigFilePath.Length - $TunnelName.Length - 1) + "\" + "$TunnelName" + ".conf"
    Write-Host "[INFO] 临时配置文件路径: $WireguardConfigFilePathTemp"
    if (-not(Test-Path $WireguardConfigFilePathTemp -PathType Leaf)) {
        Write-Host "[INFO] 创建临时配置文件"
        New-Item -ItemType File -Path $WireguardConfigFilePathTemp 
        Set-ItemProperty -Path $WireguardConfigFilePathTemp -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
    }
    $Endpoint = getEndpointByFile -path $WireguardConfigFilePath
    $Content = Get-Content -Path $WireguardConfigFilePath

    # 检查是否为IPv6地址，如果是则加上方括号
    $ipv6Pattern = '^(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}$'
    if ($EndpointIp -match $ipv6Pattern -and $EndpointIp -notmatch '^\[.*\]$') {
        Write-Host "[INFO] Endpoint IP 为IPv6，添加方括号"
        $EndpointIp = "[$EndpointIp]"
    }

    $NewContent = $Content.Replace($Endpoint, $EndpointIp)
    Set-Content -Path $WireguardConfigFilePathTemp -Value $NewContent
    Write-Host "[INFO] 安装 WireGuard 隧道服务"
    Invoke-Expression "wireguard /installtunnelservice $WireguardConfigFilePathTemp"
}

function Stop-WireGuardServic {
    param (
        [string]$TunnelName
    )
    Write-Host "[INFO] 停止 WireGuard 服务: $TunnelName"
    Invoke-Expression "wireguard /uninstalltunnelservice $TunnelName"
}

Write-Host "[INFO] 脚本启动"
Write-Host "[INFO] IPv6 优先级配置: $PreferIPv6"
$TunnelName = getFilenameByPath -path $WireguardConfigFilePath
Write-Host "[INFO] 隧道名称: $TunnelName"
$Endpoint = getEndpointByFile -path $WireguardConfigFilePath
Write-Host "[INFO] 服务端连接域名: $Endpoint"
$DnsServer = getDNSByFile -path $WireguardConfigFilePath
Write-Host "[INFO] DNS 服务器: $DnsServer"
$EndpointIPAddress = getDnsIp -domain $Endpoint -DnsServer $DnsServer -PreferIPv6:$PreferIPv6
Write-Host "[INFO] Endpoint 解析到 IP: $EndpointIPAddress"
$DnsIPAddress = $EndpointIPAddress
$DnsFailedCount = 0
Start-WireguardTunnel -TunnelName $TunnelName -EndpointIp $DnsIPAddress

while ($true) {
    $DnsIPAddress = getDnsIp -domain $Endpoint -DnsServer $DnsServer -PreferIPv6:$PreferIPv6
    Write-Host "[INFO] 当前 DnsIPAddress: $DnsIPAddress, EndpointIPAddress: $EndpointIPAddress, DnsServer: $DnsServer"
    if ($DnsIPAddress -eq "failed") {
        $DnsFailedCount = $DnsFailedCount + 1
        Write-Host "[WARN] DNS 解析失败次数: $DnsFailedCount"
        if ($DnsFailedCount -eq 3) {
            Write-Host "[ERROR] 连续 3 次 DNS 解析失败，重启 WireGuard 服务"
            Stop-WireGuardServic -TunnelName $TunnelName
            $DnsServer = getDNSByFile -path $WireguardConfigFilePath
            Write-Host "[INFO] 重新获取 DNS 服务器: $DnsServer"
            $DnsFailedCount = 1
        }
    }
    else {
        $DnsFailedCount = 1
        if ($EndpointIPAddress -ne $DnsIPAddress) {
            Write-Host "[INFO] 解析 IP 发生变化，重启 WireGuard 服务"
            Start-WireguardTunnel -TunnelName $TunnelName -EndpointIp $DnsIPAddress
            $EndpointIPAddress = $DnsIPAddress
        }
        else {
            $serviceName = "WireGuard Tunnel: $TunnelName";
            $ExistsService = Get-Service $serviceName -ErrorAction SilentlyContinue;
            if (!$ExistsService) {
                Write-Host "[WARN] WireGuard 服务未运行，尝试启动"
                Start-WireguardTunnel -TunnelName $TunnelName -EndpointIp $DnsIPAddress
            }
        }
    }
    Start-Sleep -Seconds $IntervalSeconds
}
