# Разработчик:             Воюш Артем Алексеевич
#################################################################################
#                                    Параметры                                  #
#################################################################################
#Region Parameters
$Global:SystemInfo = New-Object -TypeName PSObject -Property $([ordered] @{
		UID	     = '';
		CompName = $env:COMPUTERNAME; # Имя ПК
		Domain   = (Get-WmiObject -Query "Select * from Win32_ComputerSystem").domain;
		FQDN	 = "$env:COMPUTERNAME.$((Get-WmiObject -Query "Select * from Win32_ComputerSystem").domain)"
		UserName = (Get-WmiObject -Query "Select * from Win32_ComputerSystem").username;
		BIOSSerial = '';
		OS	     = ''; # Версия ОС
		InstallDate = ''; # Дата установки ОС
		LastBootUpTime = ''; # Дата включения
		ServerOS = $false; # Серверная ОС
		PSVersion = ($PSVersionTable.PSVersion.ToString()).split('.')[0, 1] -join "."; # Версия PowerShell
		Gateway  = "0.0.0.0";
		IPAddress = "0.0.0.0";
		NetMask  = "0.0.0.0";
		Subnet   = "0.0.0.0";
		MACAddress = '';
		DC_Name  = 'No';
	});
#region Add-Service
$Services = @()
$SystemService = @()
$Services += ('winmgmt,Инструментарий управления Windows,Running,Automatic')
$Services += ('mpssvc,Брандмауэр Защитника Windows,Running,Automatic')
$Services += ('EventLog,Журнал событий Windows,Running,Automatic')
$Services += ('Schedule,Планировщик заданий,Running,Automatic')
$Services += ('wuauserv,Центр обновления Windows,Running,Automatic')
$Services += ('CryptSvc,Службы криптографии,Running,Automatic')
$Services += ('BITS,Фоновая интеллектуальная служба передачи (BITS),Running,Automatic')
$Services += ('CcmExec,Узел агента SMS,Running,Automatic')
FOREACH ($Service IN $Services)
{
	$Service = $Service -split ','
	$add = New-Object -TypeName PSObject -Property $([ordered] @{
			Name			 = $Service[0];
			DisplayName	     = $Service[1];
			DefaultStatus    = $Service[2];
			DefaultStartMode = $Service[3];
			Status		     = $true;
		});
	$SystemService += $add
}
$Global:SystemInfo | Add-Member -MemberType NoteProperty -Name Service -Value $SystemService -Force
#endregion
$Global:ScriptParam = New-Object -TypeName PSObject -Property $([ordered] @{
		Version  = '4.0.7.2'
		#Определяется во время работы скрипта
		FullName = $Global:MyInvocation.MyCommand.Path; #"C:\Users\Acer\Desktop\Scripts\SCCM2012.ps1"; #
		Folder   = $Global:MyInvocation.MyCommand.Path | Split-Path -Parent; #"C:\Users\Acer\Desktop\Scripts\SCCM2012"; #
		Name	 = $Global:MyInvocation.MyCommand.Path | Split-Path -Leaf; #"SCCM2012.ps1"; #
		#
		TaskName = "SCCM_Install_Repair"; # Имя задачи в планировщике на запуск скрипта
		LocalPath = $env:Windir + "\CCM_Install_Script"; # Локальная папка со скриптом
		RemotePath = ""; # Сделать хранение в реестре пути на DC с политикой скрипта !!!
		FirstWriteToLog = $true; # Первая запись в лог в WriteToLog
		Log	     = $env:Windir + "\TEMP\$($Global:SystemInfo.CompName)_ConfigMgrDiag.Log"; # Лог выполнения скрипта
		ScriptCopy = $False;
		ClientHealth = 0; #Общее состояние клиента: 0 - None (Нет клиента),
		AllCheck = 'OK';
	})
$Global:SCCMClientParam = New-Object -TypeName PSObject -Property $([ordered] @{
		DesiredVersion = "5.0.7958.1000" # Минимальная версия Configuration Manager Client.
		SharePath	   = "SCCM_CLIENT_2012"; # Имя папки на DP, где находятся установочные файлы клиента
		LocalPath	   = $env:Windir + "\CCMClient2012"; # Локальная папка с дистрибутивом клиента
		InstallPath    = ""; # Путь установки клиента
		CCMSetup	   = $env:Windir + "\ccmsetup"; # SCCM 2012
		SetupLog	   = $env:Windir + "\ccmsetup\logs\ccmsetup.log"; # Лог установки ccmsetup
		Folders	       = [array]@(
			$env:Windir + "\System32\CCM"; # SCCM 2007
			$env:Windir + "\System32\ccmsetup"; # SCCM 2007
			$env:Windir + "\CCM"; # SCCM 2012
			$env:Windir + "\ccmcache" # SCCM 2012
		);
		Bad		       = $false; # Нахождение ПК в БД BadClients
		Location	   = 0; # 0 - Клиент не определен,100 - Клиент во внутренней сети (omega),101 - Клиент во внешней сети (sigma),102 - Клиент в открытой сети (mobile),103 - Клиент в сети CIB
		LocalMP	       = ''; # Локальная точка управления
		SiteCode	   = '';
		DP			   = '';
		GUID		   = '';
		ExecLog	       = '';
		PolicyLog	   = '';
		InventoryLog   = '';
		lasthwscan	   = '';
		lastswscan	   = '';
		RestSWLog	   = $Global:ScriptParam.LocalPath + "\RestSW.log"; # Лог с датой последнего перезапуска SW инвентаризации
		RestHWLog	   = $Global:ScriptParam.LocalPath + "\RestHW.log"; # Лог с датой последнего перезапуска HW инвентаризации
		RestHWTrig	   = $False; # Триггер запуска HW инвентаризаций
		RestSWTrig	   = $False; # Триггер запуска SW инвентаризаций
		HTTPHash	   = '';
		DistribHASH    = $True; # Hash и кол-во файлов в дистрибутиве
		ccmsetupHASH   = $False; # Hash ccmsetup.exe
		Universal	   = $false; # Необходимость установки универсального клиента при определении локации
		RegKeys	       = [array]@(
			"HKLM:\SOFTWARE\Microsoft\CCM",
			"HKLM:\Software\Microsoft\SMS",
			"HKLM:\Software\Microsoft\ccmsetup",
			"HKLM:\SOFTWARE\Classes\Installer\Features\8D58A6EC9B6DA974F99E0AE66588E116",
			"HKLM:\SOFTWARE\Classes\Installer\Products\8D58A6EC9B6DA974F99E0AE66588E116",
			"HKLM:\SOFTWARE\Classes\Installer\Features\1FDE90624C4330B46B43553F3BCB9413",
			"HKLM:\SOFTWARE\Classes\Installer\Products\1FDE90624C4330B46B43553F3BCB9413",
			"HKLM:\SOFTWARE\Classes\Installer\Features\F9735EACD3C5D0D4AA75CD114321B55A",
			"HKLM:\SOFTWARE\Classes\Installer\Products\F9735EACD3C5D0D4AA75CD114321B55A",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CE6A85D8-D6B9-479A-9FE9-A06E56881E61}",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2609EDF1-34C4-4B03-B634-55F3B3BC4931}",
			"HKLM:\Classes\Installer\Products\8D58A6EC9B6DA974F99E0AE66588E116",
			"HKLM:\Classes\Installer\Products\1FDE90624C4330B46B43553F3BCB9413",
			"HKLM:\Classes\Installer\Products\F9735EACD3C5D0D4AA75CD114321B55A",
			"HKLM:\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\8D58A6EC9B6DA974F99E0AE66588E116",
			"HKLM:\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\1FDE90624C4330B46B43553F3BCB9413",
			"HKLM:\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\F9735EACD3C5D0D4AA75CD114321B55A",
			"HKLM:\SOFTWARE\Classes\Installer\Products\D8DEB17D34B18144D97A5A7C94F8A24C",
			"HKLM:\Software\Microsoft\SMS\Mobile Client\GPRequestedSiteAssignmentCode",
			"HKLM:\Software\Microsoft\SMS\Mobile Client\GPSiteAssignmentRetryInterval(Min)",
			"HKLM:\Software\Microsoft\SMS\Mobile Client\GPSiteAssignmentRetryDuration(Hour)",
			"HKLM:\SOFTWARE\Classes\Installer\Products\D7314F9862C648A4DB8BE2A5B47BE100" #Silverlight
			"HKCR:\Installer\Products\8D58A6EC9B6DA974F99E0AE66588E116",
			"HKCR:\Installer\Features\8D58A6EC9B6DA974F99E0AE66588E116",
			"HKCR:\Installer\Products\1FDE90624C4330B46B43553F3BCB9413",
			"HKCR:\Installer\Features\1FDE90624C4330B46B43553F3BCB9413",
			"HKCR:\Installer\Products\F9735EACD3C5D0D4AA75CD114321B55A",
			"HKCR:\Installer\Features\F9735EACD3C5D0D4AA75CD114321B55A",
			"HKCR:\Installer\Products\D8DEB17D34B18144D97A5A7C94F8A24C"
		);
	})
$Global:ConfigParam = New-Object -TypeName PSObject -Property $([ordered] @{
		ServiceTimeout = 6; # Количество тайм-аутов (по 5 секунд) для запуска/остановки службы, восстановления WMI
		InstallTimeout = 30; # Тайм-аут (в минутах) для установки клиента. "0" - установка без мониторинга.
		MaxPolicyAge   = 7; # Максимальной количество дней с даты последней оценки политики
		MaxExecAge	   = 7; # Максимальной количество дней с даты последнего выполнения программы, "-1" - отключение проверки выполнения программы
		MinFreeSpace   = 100; # Минимальное свободное место (в мегабайтах) на системном диске необходимое для установки клиента
		MinTotalSize   = 80 # Минимальное свободное место (в гигабайтах) на системном диске
	})
[array]$Global:QCodeArray = @() # Массив кодов выхода для записи в БД
# URL альтернативного SLP сервиса
$Global:SlpUrl = New-Object -TypeName PSObject -Property $(@{
		Omega = [array]@(
			"http://Management_Point_1.Omega.ru",
			"http://Management_Point_2.Omega.ru",
			#
			"http://Management_Point_n.Omega.ru"
		);
		Sigma = [array]@(
			"http://Management_Point_1.Sigma.ru",
			"http://Management_Point_2.Sigma.ru",
			#								  
			"http://Management_Point_n.Sigma.ru"
		);
		Mobile = [array]@(
			"https://Management_Point_1.internet_domain.ru"
		);
		CIB   = [array]@(
			"http://Management_Point_1.CIB.ru"
		)
	})
# Подключение разделов реестра
IF (!(Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue)) { New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null }
#endregion

#################################################################################
#                                     ФУНКЦИИ                                   #
#################################################################################
#region Function
FUNCTION WriteToLog($Severity, $Message) #
{
	IF ($Global:ScriptParam.FirstWriteToLog)
	{
		$Global:ScriptParam.FirstWriteToLog = $FALSE
		[array]$LogText = "============================================================================================================================="
		$LogText += "<" + $(Get-Date -Format "G") + "> BEGIN SCCM Client Health Check Script (Version $($Global:ScriptParam.Version))"
		$LogText += "============================================================================================================================="
		$LogText += "<" + $(Get-Date -Format "G") + "> `t[" + $Severity + "] " + "`t" + $Message
	}
	ELSE
	{
		[string]$LogText = "<" + $(Get-Date -Format "G") + "> `t[" + $Severity + "] " + "`t" + $Message
	}
	IF ($Severity -like "END")
	{
		[array]$LogText = "============================================================================================================================="
		$LogText += "<" + $(Get-Date -Format "G") + "> END SCCM Client Health Check Script (Version $($Global:ScriptParam.Version))"
		$LogText += "============================================================================================================================="
	}
	IF ($LogText.Length -gt 0)
	{
		#Add-Content -Path $($Global:ScriptParam.Log) -Value $LogText -Force #Ошибки при частой записи в файл
		$LogText | Out-File -FilePath $($Global:ScriptParam.Log) -Append -Force -Encoding default
	}
	IF ($Severity -like "FAILURE") { Finish }
}
<#
FUNCTION Get-StringHash
{
       PARAM (
             [string]$Content,
            
             [ValidateSet("MD5", "SHA1")]
             [string]$Algorithm,
            
             [string]$Delimiter
       )
       SWITCH ($Algorithm)
       {
             'MD5'{ $cryptoServiceProvider = [System.Security.Cryptography.MD5CryptoServiceProvider]; }
             'SHA1'{ $cryptoServiceProvider = [System.Security.Cryptography.SHA1CryptoServiceProvider]; }
       }
       $hashAlgorithm = new-object $cryptoServiceProvider
       $bytes = [System.Text.Encoding]::Unicode.GetBytes($Content)
       $hashByteArray = $hashAlgorithm.ComputeHash($bytes);
       $formattedHash = [string]::join($Delimiter, ($hashByteArray | ForEach-Object { $_.tostring("X2") }))
       #$formattedHash = [string]::join($Delimiter, $hashByteArray)
       RETURN $formattedHash;
}
#>
FUNCTION CheckService #
{
	PARAM (
		[string]$ServiceName,
		[ValidateSet("Running", "Stopped")]
		[string]$Status,
		[ValidateSet("Automatic", "Disabled", "Manual")]
		[string]$StartMode,
		[switch]$Dependent,
		[switch]$Check,
		[switch]$Delete
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "Service: $($Error[0].Exception.Message)"
		IF ([string]::IsNullOrEmpty($Service))
		{
			IF ($Check) { ($Global:SystemInfo.Service | Where-Object { $_.Name -eq $ServiceName }).Status = $false }
			RETURN
		}
		ELSE { CONTINUE }
	}
	$Service = $Null
	$Service = Get-Service $ServiceName -ErrorAction Stop
	
	IF ($StartMode)
	{
		IF (!($Service.StartType -eq $StartMode))
		{
			Set-Service -Name $($Service.name) -StartupType $StartMode
			$Service = Get-Service $ServiceName
			IF ($Service.StartType -eq $StartMode)
			{
				WriteToLog -Severity "INFORMATION" -Message "Service: Тип запуска $StartMode для службы $($Service.DisplayName) установлен."
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Service: Не удалось установить тип запуска $StartMode для службы $($Service.DisplayName)."
				IF ($Check) { ($Global:SystemInfo.Service | Where-Object { $_.Name -eq $ServiceName }).Status = $false }
			}
		}
	}
	IF ($Dependent)
	{
		$DepServices = ''
		$DepServices = $Service.DependentServices
		IF ($DepServices -ne '')
		{
			FOREACH ($DepService IN $DepServices)
			{
				SWITCH ($Status)
				{
					'Running'{
						Start-Service -name $DepService.name
						WriteToLog -Severity "INFORMATION" -Message "Service: Запуск зависимой службы: $($DepService.Name)."
					}
					'Stopped'{
						Stop-Service -name $DepService.name -Force
						WriteToLog -Severity "INFORMATION" -Message "Service: Остановка зависимой службы: $($DepService.Name)."
					}
				}
				FOR ($i = 1; $i -le $Global:ConfigParam.ServiceTimeout; $i++)
				{
					IF ((Get-Service $DepService.name -ErrorAction Continue).Status -eq $Status) { BREAK }
					Start-Sleep -Seconds 5
				}
			}
		}
	}
	IF ($Service.Status -eq $Status)
	{
		WriteToLog -Severity "INFORMATION" -Message "Service: Cлужба $($Service.DisplayName) - $Status"
	}
	ELSE
	{
		FOR ($i = 1; $i -le $Global:ConfigParam.ServiceTimeout; $i++)
		{
			SWITCH ($Status)
			{
				'Running'{
					Start-Service -name $ServiceName -ErrorAction SilentlyContinue
				}
				'Stopped'{
					Stop-Service -name $ServiceName -ErrorAction SilentlyContinue -Force
				}
			}
			Start-Sleep -Seconds 5
			IF ((Get-Service $ServiceName).Status -eq $Status)
			{
				WriteToLog -Severity "INFORMATION" -Message "Service: Cлужба $($Service.DisplayName) успешно $Status"
				BREAK
			}
		}
		IF ((Get-Service $ServiceName).Status -ne $Status)
		{
			WriteToLog -Severity "WARNING" -Message "Service: Не удалось выполнить $Status службы $($Service.DisplayName). Error: $($Error[0].Exception.Message)"
			IF ($Check) { ($Global:SystemInfo.Service | Where-Object { $_.Name -eq $ServiceName }).Status = $false }
		}
	}
	IF ($Delete)
	{
		$(Get-WmiObject -class Win32_service -Filter $("Name='" + $ServiceName + "'")).delete() | Out-Null
		IF ([string]::IsNullOrEmpty($(Get-Service $ServiceName -ErrorAction SilentlyContinue)))
		{
			WriteToLog -Severity "INFORMATION" -Message "Service: Cлужба $($Service.DisplayName) успешно удалена."
		}
		ELSE
		{
			WriteToLog -Severity "INFORMATION" WARNING "Service: Не удалось выполнить удаление службы $($Service.DisplayName)."
		}
	}
}
FUNCTION RebuildWMI #
{
	$WMIService = ($Global:SystemInfo.Service | Where-Object { $_.Name -eq 'winmgmt' })
	WriteToLog -Severity "WARNING" -Message "WMI: START Rebuild"
	CheckService -ServiceName $WMIService.Name -Status Stopped -StartMode Disabled -Dependent
	$WMIPath = @("$env:WinDir\system32\wbem", "$env:WinDir\SysWOW64\wbem")
	FOREACH ($Path IN $WMIPath)
	{
		IF (Test-Path $Path)
		{
			TRY
			{
				Remove-Item "$Path\repository\" -Recurse -Force -ErrorAction Stop
				WriteToLog -Severity "INFORMATION" -Message "WMI: Удаление репозитория WMI $Path\repository\ выполнено успешно."
			}
			CATCH
			{
				WriteToLog -Severity "ERROR" -Message "WMI: Не удалось выполнить удаление репозитория WMI $Path\repository\. Error: $($Error[0].Exception.Message)"
			}
		}
	}
	$ACL = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)'
	$CmdLine = 'sc.exe sdset "{0}" "{1}" ' -f $WMIService.Name, $ACL
	$Result = Invoke-Expression -Command $CmdLine
	WriteToLog -Severity "INFORMATION" -Message "WMI: Установка прав на службу winmgmt: $Result."
	CheckService -ServiceName $WMIService.Name -Status Running -StartMode Automatic -Dependent
	FOREACH ($Path IN $WMIPath)
	{
		IF (Test-Path $Path)
		{
			WriteToLog -Severity "INFORMATION" -Message "WMI: Регистрируем библиотеки: $Path\*.dll."
			Get-ChildItem $Path -filter *.dll | ForEach-Object{ & regsvr32.exe /s $_.FullName } | Out-Null
			WriteToLog -Severity "INFORMATION" -Message "WMI: Анализируем  $Path\*.mof."
			Get-ChildItem $Path -filter *.mof | ForEach-Object{ & mofcomp.exe $_.FullName } | Out-Null
			WriteToLog -Severity "INFORMATION" -Message "WMI: Анализируем $Path\*.mfl."
			Get-ChildItem $Path -filter *.mfl | ForEach-Object{ & mofcomp.exe $_.FullName } | Out-Null
		}
	}
	& mofcomp.exe 'C:\Program Files\Microsoft Policy Platform\ExtendedStatus.mof' | Out-Null
	$Error.Clear()
	WriteToLog -Severity "INFORMATION" -Message "WMI: Ожидание пространства имен CIMv2."
	FOR ($i = 1; $i -le $Global:ConfigParam.ServiceTimeout; $i++)
	{
		$WMI = Get-WmiObject -Namespace Root\cimv2 -list
		IF ($Error.count -eq 0) { BREAK }
		$Error.Clear()
		Start-Sleep -Seconds 5
	}
	IF ($Error.count -ne 0)
	{
		WriteToLog -Severity "ERROR" -Message "WMI: Не удалось восстановить WMI."
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "WMI: Восстановление WMI завершено успешно."
	}
	WriteToLog -Severity "WARNING" -Message "WMI: STOP Rebuild"
}
FUNCTION ScrCopyPsocCheck #
{
	WriteToLog -Severity "INFORMATION" -Message "=== Поиск запущенных экземпляров скрипта ==="
	$ScriptDouble = $false #Флаг копии скрипта
	TRY
	{
		$PSProcess = Get-WmiObject -Query "Select * from Win32_Process where name = 'powershell.exe'" -ErrorAction Stop
	}
	CATCH
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось получить из WMI список запущенных процессов powershell.exe"
		RETURN
	}
	FOREACH ($Process IN $PSProcess)
	{
		[string]$CommandLine = $Process.Commandline
		IF ($CommandLine -match ([regex]::Escape($Global:ScriptParam.Name)))
		{
			IF (!($CommandLine -match ([regex]::Escape($Global:ScriptParam.FullName)) -or $CommandLine -match ([regex]::Escape('.\'))))
			{
				WriteToLog -Severity "WARNING" -Message "Завершен текущий скрипт, т.к. обнаружен дубликат скрипта - $CommandLine"
				WriteToLog -Severity "INFORMATION" -Message "Параметр сравнения ScriptName - $($Global:ScriptParam.Name)"
				WriteToLog -Severity "INFORMATION" -Message "Параметр сравнения ScriptFullName - $($Global:ScriptParam.FullName)"
				Finish
			}
			IF ($ScriptDouble)
			{
				WriteToLog -Severity "WARNING" -Message "Завершен текущий скрипт, т.к. обнаружена копия скрипта - $CommandLine"
				WriteToLog -Severity "INFORMATION" -Message "Параметр сравнения ScriptName - $($Global:ScriptParam.Name)"
				WriteToLog -Severity "INFORMATION" -Message "Параметр сравнения ScriptFullName - $($Global:ScriptParam.FullName)"
				Finish
			}
			WriteToLog -Severity "INFORMATION" -Message "Найден запущенный скрипт $($Global:ScriptParam.FullName)"
			$ScriptDouble = $true
		}
	}
	#WriteToLog -Severity "INFORMATION" -Message "Не найдено других запущенных экземпляров скрипта."
}
FUNCTION CheckLocation #
{
	TRAP # Обработчик ошибок
	{
		IF ($Error[0].Exception.Message -notmatch "Невозможно разрешить удаленное имя")
		{
			WriteToLog -Severity "WARNING" -Message "CheckLocation: $($Error[0].Exception.Message)"
		}
		CONTINUE
	}
	WriteToLog -Severity "INFORMATION" -Message "=== Определение локации клиента ==="
	
	IF ($Global:SystemInfo.Domain -eq "cib.ru") { $Global:SCCMClientParam.Location = 103 }
	IF ($Global:SCCMClientParam.Location -eq 0) { IF (PingHost -DP "omega.ru") { $Global:SCCMClientParam.Location = 100 } }
	IF ($Global:SCCMClientParam.Location -eq 0)
	{
		$Socket = New-Object net.Sockets.TcpClient
		$Socket.Connect("Management_Point_1.omega.ru", 80)
		IF ($Socket.Connected)
		{
			$Global:SCCMClientParam.Location = 101
		}
		ELSE
		{
			$Socket = New-Object net.Sockets.TcpClient
			$Socket.Connect("Management_Point_1.sigma.ru", 80)
			IF ($Socket.Connected) { $Global:SCCMClientParam.Location = 101 }
		}
	}
	IF ($Global:SCCMClientParam.Location -eq 0)
	{
		$Socket = New-Object net.Sockets.TcpClient
		$Socket.Connect("Management_Point_1.internet_domain.ru", 443)
		IF ($Socket.Connected) { $Global:SCCMClientParam.Location = 102 }
	}
}
FUNCTION PingHost #
{
	PARAM
	(
		[parameter(Mandatory = $true)]
		$DP,
		[parameter(Mandatory = $false)]
		[switch]$PingTracert = $false
	)
	TRAP # Обработчик ошибок
	{
		CONTINUE
	}
	$ping = $false
	IF (!($DP -eq $null) -and !($DP -eq '') -and !($DP -eq ' '))
	{
		FOR ($i = 1; $i -le 4; $i++)
		{
			$objPing = new-object System.Net.NetworkInformation.Ping
			IF ($objPing.send($DP).Status -eq "Success")
			{
				$ping = $True
			}
			IF ($ping)
			{
				BREAK
			}
		}
	}
	IF (!$ping -and $PingTracert)
	{
		WriteToLog -Severity "WARNING" -Message "Нет связи с $DP. Будет произведена диагностика."
		PingTracert($DP)
	}
	RETURN $ping
}
FUNCTION PingTracert($address)
{
	IF ($Global:SCCMClientParam.LocalMP -eq '') { LocalSiteServer -RequestType DefaultMP }
	[int]$Timeout = 1000
	$Ping = New-Object System.Net.NetworkInformation.Ping
	$maxttl = 30
	$message = [System.Text.Encoding]::Default.GetBytes("MESSAGE")
	$dontfragment = "false"
	$success = [System.Net.NetworkInformation.IPStatus]::Success
	$HostUnreachable = [System.Net.NetworkInformation.IPStatus]::DestinationHostUnreachable
	$NetworkUnreachable = [System.Net.NetworkInformation.IPStatus]::DestinationNetworkUnreachable
	$TimedOut = [System.Net.NetworkInformation.IPStatus]::TimedOut
	# IPConfig
	[string]$Result = "IPConfig || "
	[string]$Proverka = "ipconfig"
	$IPConfig = Invoke-Expression -Command "ipconfig /all"
	WriteToLog -Severity "INFORMATION" -Message "Результат ipconfig /all:"
	$IPConfig | ForEach-Object {
		IF (!([string]::IsNullOrWhiteSpace($_)))
		{
			$Result += "$($_.replace('. ', '')) || "
			WriteToLog -Severity "INFORMATION" -Message "$($_.replace('. ', ''))"
		}
	}
	$URLBD = "http://$($Global:SCCMClientParam.LocalMP)/$AppPool_2/ClientCheck2012.asp?request=writeping&compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)&command=$Proverka&result=$Result"
	TRY
	{
		Invoke-WebRequest -Uri $URLBD -Method Get -ErrorAction Stop -UseBasicParsing | Out-Null
	}
	CATCH
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось сделать запись в БД"
	}
	# Ping
	[string]$Result = "Ping $address || "
	[string]$Proverka = "ping"
	WriteToLog -Severity "INFORMATION" -Message "Результат пинга до $address :"
	FOR ($h = 1; $h -le 4; $h++)
	{
		$Reply = $ping.Send($address)
		$addr = $Reply.Address
		IF ($Reply.Status -eq "Success") { $Status = $Reply.Status }
		$Result += "$addr ($($Reply.Status)) Time=$($Reply.RoundtripTime)мс || "
		WriteToLog -Severity "INFORMATION" -Message "$addr ($($Reply.Status)) Time=$($Reply.RoundtripTime)мс"
	}
	$URLBD = "http://$($Global:SCCMClientParam.LocalMP)/$AppPool_2/ClientCheck2012.asp?request=writeping&compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)&command=$Proverka&result=$Result"
	TRY
	{
		Invoke-WebRequest -Uri $URLBD -Method Get -ErrorAction Stop -UseBasicParsing | Out-Null
	}
	CATCH
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось сделать запись в БД"
	}
	# Tracert
	[string]$Result = "Tracert $address || "
	[string]$Proverka = "tracert"
	WriteToLog -Severity "INFORMATION" -Message "Результат трасировки до DP $address :"
	FOR ($ttl = 1; $ttl -le $maxttl; $ttl++)
	{
		$popt = new-object System.Net.NetworkInformation.PingOptions($ttl, $dontfragment)
		$reply = $ping.Send($address, $timeout, $message, $popt)
		$addr = $reply.Address
		$status = $reply.Status
		IF (($addr -eq $null) -or ($addr -eq '')) { $addr = "Узел не определен" }
		IF ($status -eq 'TtlExpired') { $Status = "OK" }
		$Result += "Hop: $ttl`t= $addr ($($Status)) || "
		WriteToLog -Severity "INFORMATION" -Message "Hop: $ttl`t= $addr ($($Status))"
		IF (($reply.Status -eq $success) -or ($reply.Status -eq $HostUnreachable) -or ($reply.Status -eq $NetworkUnreachable)) { BREAK }
	}
	$URLBD = "http://$($Global:SCCMClientParam.LocalMP)/$AppPool_2/ClientCheck2012.asp?request=writeping&compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)&command=$Proverka&result=$Result"
	TRY
	{
		Invoke-WebRequest -Uri $URLBD -Method Get -ErrorAction Stop -UseBasicParsing | Out-Null
	}
	CATCH
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось сделать запись в БД"
	}
}
FUNCTION Finish #
{
	IF ($Global:SCCMClientParam.LocalMP -ne '')
	{
		# Описание параметров запроса
		[string]$URL = "request=inventory&"
		$URL += "a=$($Global:SystemInfo.UID)&" #ID = Request("a")  - (255 символов)
		$URL += "b=$($Global:SystemInfo.CompName)&" #CompName = Request("b") - (50 символов)
		$URL += "c=$($Global:SystemInfo.Domain)&" #PCDomain = Request("c")  - (50 символов)
		$URL += "d=$($Global:SystemInfo.Username)&" #Username = Request("d")  - (50 символов)
		$URL += "e=$($Global:SystemInfo.BIOSSerial)&" #BIOSSerial = Request("e")  - (50 символов)
		$URL += "f=$($Global:SystemInfo.OS.Caption)&" #OS = Request("f")  - (50 символов)
		$URL += "g=$($Global:SystemInfo.OS.OSBuild)&" #OsBuild = Request("g")  - (50 символов)
		$URL += "h=$($Global:SystemInfo.OS.OSArchitecture)&" #OSarch = Request("h")  - (50 символов)
		$URL += "i=$($Global:SystemInfo.OS.InstallDate)&" #OSInstalldate = Request("i") - Дата+время
		$URL += "j=$($Global:SystemInfo.OS.LastBootUpTime)&" #PCOnDate = Request("j")  - Дата+время
		$URL += "k=$($Global:SystemInfo.IPAddress)&" #IP = Request("k")  - (50 символов)
		$URL += "l=$($Global:SystemInfo.Gateway)&" #Gateway = Request("l")  - (50 символов)
		$URL += "m=$(@($Global:SystemInfo.NetMask)[0])&" #NetworkMask = Request("m")  - (50 символов)
		$URL += "n=$($Global:SystemInfo.MACAddress)&" #MAC = Request("n")  - (50 символов)
		$URL += "o=$($Global:ScriptParam.Version)&" #ScriptVersion = Request("o") - (50 символов)
		$URL += "p={alwint$([int](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\Security -Name ClientAlwaysOnInternet -ErrorAction Continue).ClientAlwaysOnInternet)}"
		$URL = $URL.Replace("Майкрософт", "Microsoft")
		$URL = $URL.Replace("Корпоративная", "Corp")
		$URL = [System.Text.Encoding]::Default.GetString([System.Text.Encoding]::GetEncoding('windows-1251').GetBytes($URL))
		WriteBD -URL $URL
	}
	
	#region Запись данных в реестр для скрипта Check_Update
	IF (!(Test-Path -Path HKLM:\SOFTWARE\SCCM))
	{
		New-Item -Path HKLM:\SOFTWARE -Name SCCM
	}
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name IPAddress -Value $Global:SystemInfo.IPAddress -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Subnet -Value $Global:SystemInfo.Subnet -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name OS -Value $Global:SystemInfo.OS.OS -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name OSLanguage -Value $Global:SystemInfo.OS.OSLanguage -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Location -Value $Global:SCCMClientParam.Location -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name LocalMP -Value $Global:SCCMClientParam.LocalMP -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name DC_Name -Value $Global:SystemInfo.DC_Name -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name ClientHealth -Value $Global:ScriptParam.ClientHealth -ErrorAction Stop
	
	#endregion
	
	WriteToLog -Severity "INFORMATION" -Message "=== END ==="
	IF ($Global:SCCMClientParam.LocalMP -ne '') { WriteBD -QuitCode 50 }
	WriteToLog -Severity "END"
	
	#IF (![string]::IsNullOrEmpty($(Get-ScheduledTask -TaskName SCCM_Check_Update)))
	#{
	#      Start-ScheduledTask SCCM_Check_Update -ErrorAction Stop
	#}
	#ELSE
	#{
	$cmd = "powershell.exe -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File $($Global:ScriptParam.Folder)\Check_Update.ps1"
	Invoke-WmiMethod -Class Win32_process -Name Create -ArgumentList $cmd
	#}
	
	EXIT
}
FUNCTION WriteBD #
{
	PARAM (
		[Parameter(ParameterSetName = 'QuitCode', Mandatory = $false)]
		[string]$QuitCode = '',
		[Parameter(ParameterSetName = 'URL', Mandatory = $False)]
		[string]$URL = ''
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "WriteBD Error: HTTPRequest= $($Error[0].Exception.Message) URL=$URLBD"
		CONTINUE
	}
	IF (![string]::IsNullOrEmpty($QuitCode) -and
		($QuitCode -notin @(0, 49, 50)) -and
		($QuitCode -notlike "10*") -and
		($QuitCode -notlike "820*"))
	{ $Global:ScriptParam.AllCheck = 'Errors' }
	IF ($Global:SCCMClientParam.LocalMP -eq '') { LocalSiteServer -RequestType DefaultMP }
	IF ($Global:SCCMClientParam.Location -eq 102)
	{
		$ASP_Url = "https://Management_Point_1.internet_domain.ru"
		$cert = (Get-ChildItem -Path cert:\LocalMachine\My\ | Where-Object{ $_.Subject -Like "*CN=$env:COMPUTERNAME*" })[-1]
		IF ([string]::IsNullOrEmpty($cert))
		{
			WriteToLog -Severity "WARNING" -Message "Не удалось получить PKI сертификат. Запись в БД невозможна"
			Return
		}
	}
	ELSE
	{
		$ASP_Url = "http://$($Global:SCCMClientParam.LocalMP)"
	}
	IF ([string]::IsNullOrEmpty($QuitCode))
	{
		$URLBD = "$ASP_Url/$AppPool_2/ClientCheck2012.asp?$URL"
		WriteToLog -Severity "INFORMATION" -Message "URLBD: $URLBD"
	}
	ELSE
	{
		$URLBD = "$ASP_Url/$AppPool_2/ClientCheck2012.asp?request=writelog&Subnet=$($Global:SystemInfo.Subnet)&IP=$($Global:SystemInfo.IPAddress)&CompName=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)&ScriptVersion=$($Global:ScriptParam.Version)&DC_Name=$($Global:SystemInfo.DC_Name)&QuitCode=$QuitCode"
		WriteToLog -Severity "INFORMATION" -Message "QuitCode: $QuitCode"
	}
	IF ($Global:SCCMClientParam.Location -eq 102)
	{
		Invoke-WebRequest -Uri $URLBD -Method Get -ErrorAction Stop -ContentType "text/html; charset=utf-8" -Certificate $cert -UseBasicParsing | Out-Null
	}
	ELSE
	{
		Invoke-WebRequest -Uri $URLBD -Method Get -ErrorAction Stop -UseBasicParsing | Out-Null
	}
}
FUNCTION LocalSiteServer
{
	[CmdletBinding(DefaultParameterSetName = 'Request')]
	PARAM (
		[Parameter(ParameterSetName = 'Request', Mandatory = $true)]
		[ValidateSet("DP", "SiteCode", "DefaultMP", "LastHWScan", "LastSWScan", "GUID", "BadClientsCheck", "BadClientsRemove", "GetHash")]
		[string]$RequestType,
		[Parameter(ParameterSetName = 'Request', Mandatory = $False)]
		[switch]$Check,
		[Parameter(ParameterSetName = 'Speed', Mandatory = $true)]
		[switch]$Speed,
		[Parameter(ParameterSetName = 'Speed', Mandatory = $true)]
		[string]$DP
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "LocalSiteServer Error: HTTPRequest= $($Error[0].Exception.Message) URL=$URL Result=$Result"
		CONTINUE
	}
	
	FOREACH ($ASP_Url IN $Global:ASP_Urls)
	{
		IF ([string]::IsNullOrEmpty($Global:SCCMClientParam.LocalMP))
		{
			$ASP_Url = $ASP_Url
		}
		ELSE
		{
			IF ($Global:SCCMClientParam.Location -eq 102)
			{
				$ASP_Url = "https://Management_Point_1.internet_domain.ru"
			}
			ELSE
			{
				$ASP_Url = "http://$($Global:SCCMClientParam.LocalMP)"
			}
		}
		SWITCH ($RequestType)
		{
			"DP" {
				$URL = "$ASP_Url/$AppPool_1/mcs_slp.asp?request=dp&ip=$($Global:SystemInfo.Subnet)&ir=$($Global:SystemInfo.IPAddress)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос обслуживающих DP: $URL"
			}
			"SiteCode" {
				$URL = "$ASP_Url/$AppPool_1/mcs_slp.asp?request=SiteCode&ip=$($Global:SystemInfo.Subnet)&ir=$($Global:SystemInfo.IPAddress)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос сайта управления: $URL"
			}
			"DefaultMP"
			{
				$URL = "$ASP_Url/$AppPool_1/mcs_slp.asp?request=defaultmp&ip=$($Global:SystemInfo.Subnet)&ir=$($Global:SystemInfo.IPAddress)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос точки управления: $URL"
			}
			"BadClientsCheck"
			{
				$URL = "$ASP_Url/$AppPool_2/ClientCheck2012.asp?request=BCcheck&Compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Проверка ПК в BadClients: $URL"
			}
			"BadClientsRemove"
			{
				$URL = "$ASP_Url/$AppPool_2/ClientCheck2012.asp?request=BCremove&Compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Удаление ПК из BadClients: $URL"
			}
			"GetHash"
			{
				$URL = "$ASP_Url/$AppPool_2/clientcheck2012.asp?request=checksum"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос списка файлов и хэша дистрибутива: $URL"
			}
		} #end switch url
		IF ($Speed)
		{
			$URL = "$ASP_Url/$AppPool_1/mcs_slp.asp?request=speed&ir=$($Global:SystemInfo.IPAddress)&strDP=$DP"
			WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос скорости подключения к DP: $URL"
		}
		IF ($Global:SCCMClientParam.Location -eq 102)
		{
			$cert = (Get-ChildItem -Path cert:\LocalMachine\My\ | Where-Object{ $_.Subject -Like "*CN=$env:COMPUTERNAME*" })[-1]
			IF ([string]::IsNullOrEmpty($cert))
			{
				WriteToLog -Severity "WARNING" -Message "Не удалось получить PKI сертификат."
				Finish
			}
			$HTTPResult = (Invoke-WebRequest -Uri $URL -Method Get -ErrorAction Stop -UseBasicParsing -Certificate $cert).Content
		}
		ELSE
		{
			$HTTPResult = (Invoke-WebRequest -Uri $URL -Method Get -ErrorAction Stop -UseBasicParsing).Content
		}
		IF (![string]::IsNullOrWhiteSpace($HTTPResult) -and $HTTPResult -notmatch "Error" -and $HTTPResult -notmatch "not found" -and $HTTPResult -notmatch "No Group Boundary") { BREAK } #exit to foreach $ASP_Url
		IF ($RequestType -in @("LastHWScan", "LastSWScan") -and ($HTTPResult -match "No LastHWDate" -or $HTTPResult -match "No LastScanDate")) { BREAK } #exit to foreach $ASP_Url
	} #end foreach $ASP_Url
	
	# Проверка корректности ответа на запрос
	IF ($HTTPResult -notmatch "No LastHWDate" -and $HTTPResult -notmatch "No LastScanDate" -and ([string]::IsNullOrWhiteSpace($HTTPResult) -or $HTTPResult -match "Error")) #-or $HTTPResult -match "not found" -or $HTTPResult -match "No Group Boundary"
	{
		#Определение МР из http запроса
		WriteToLog -Severity "WARNING" -Message "HTTP: Получен некорректный ответ на HTTP-запрос: $HTTPResult"
		$Global:SCCMClientParam.LocalMP = $URL.split("/")[2]
		IF (PingHost -DP $Global:SCCMClientParam.LocalMP -PingTracert)
		{
			WriteToLog -Severity "WARNING" -Message "HTTP: Не заведена граница обслуживания"
			WriteBD -QuitCode 15
		}
		ELSE
		{
			WriteToLog -Severity "WARNING" -Message "HTTP: Точка управления (MP) недоступна"
		}
		CreateScheduler
		Finish
	}
	
	# Костыль для "безграничных" клиентов
	IF (($HTTPResult -match "not found" -or $HTTPResult -match "No Group Boundary") -and $Global:SCCMClientParam.Location -eq 101)
	{
		WriteToLog -Severity "INFORMATION" -Message "HTTP: Получен ответ: $HTTPResult"
		RETURN 'no'
	}
	
	# Нормальная работа функции
	ELSE
	{
		# Обработка ответа на запрос
		IF ($Speed)
		{
			IF ([int]$HTTPResult -eq 1)
			{
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Получен ответ: Slow"
				RETURN 'Slow'
			}
			ELSEIF ([int]$HTTPResult -eq 0)
			{
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Получен ответ: Fast"
				RETURN 'Fast'
			}
			ELSE
			{
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Получен ответ: Null: $HTTPResult"
				RETURN 'null'
			}
		}
		IF ($RequestType -ne "BadClientsRemove") { WriteToLog -Severity "INFORMATION" -Message "HTTP: Получен ответ: $HTTPResult" }
		SWITCH ($RequestType)
		{
			"DP" {
				$DPList = @($HTTPResult.Split(' ').trim())
				$add = @()
				FOREACH ($dp IN $DPList)
				{
					IF (![string]::IsNullOrEmpty($DP))
					{
						$el = New-Object -TypeName PSObject -Property @{
							DPName = $dp;
							Speed  = LocalSiteServer -Speed -DP $dp
						}
						$add += $el
					}
				}
				$Global:SCCMClientParam | Add-Member NoteProperty -Name DP -Value $add -Force
			}
			"DefaultMP"{
				$Global:SCCMClientParam.LocalMP = $HTTPResult.trim()
				IF ($Check) { RETURN $True }
			}
			"BadClientsCheck"{
				IF ($HTTPResult -eq 1) { $Global:SCCMClientParam.Bad = $True }
			}
			"GetHash"{
				$Global:SCCMClientParam.HTTPHash = $HTTPResult
			}
			"SiteCode"
			{
				$Global:SCCMClientParam.SiteCode = $HTTPResult
			}
		} #end switch result
	}
}
FUNCTION Invoke #
{
	[CmdletBinding()]
	[OutputType([boolean])]
	PARAM
	(
		[string]$ArgumentList,
		[ValidateNotNullOrEmpty()]
		[string]$FilePatch
	)
	WriteToLog -Severity "INFORMATION" -Message "Запуск процесса $FilePatch $ArgumentList"
	$Process = $null
	$Process = Invoke-WmiMethod -Class Win32_process -Name Create -ArgumentList "$FilePatch $ArgumentList"
	IF ($Process.ReturnValue -eq 0)
	{
		WriteToLog -Severity "INFORMATION" -Message "Процесс $($Process.ProcessId) успешно запущен"
		Wait-Process -ProcessId $Process.ProcessId
		RETURN $true
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "Ошибка запуска процесса: $($Process.ReturnValue) $($Error[0].Exception.Message)"
		RETURN $false
	}
}
FUNCTION CheckHash
{
	PARAM (
		[switch]$ccmsetup = $false
	)
	WriteToLog -Severity "INFORMATION" -Message "Проверка хэша локального дистрибутива"
	# Получение списка файлов и хэша
	LocalSiteServer -RequestType GetHash
	$Global:SCCMClientParam.DistribHASH = $true
	$Global:SCCMClientParam.ccmsetupHASH = $false
	IF (![string]::IsNullOrEmpty($Global:SCCMClientParam.HTTPHash))
	{
		$Content = $Global:SCCMClientParam.HTTPHash.split(';') | Where-Object { ![string]::IsNullOrEmpty($_) }
		if ($ccmsetup) { $Content = $Content | Where-Object { $_ -match ("ccmsetup.exe") } }
		FOREACH ($Line IN $Content)
		{
			TRAP # Обработчик ошибок
			{
				WriteToLog -Severity "WARNING" -Message "CheckHash Error: $($Error[0].Exception.Message)"
				IF (!($File[0] -like "*ccmclean.exe*")) # отсутствие и хэш этих файлов игнорируется
				{
					$Global:SCCMClientParam.DistribHASH = $false
				}
				CONTINUE
			}
			$File = $Line.split(',')
			IF ((Get-FileHash -Path "$($Global:SCCMClientParam.LocalPath)\$($File[0])" -Algorithm MD5 -ErrorAction Stop).hash -eq $File[1])
			{
				IF ($File[0].Contains("ccmsetup.exe")) { $Global:SCCMClientParam.ccmsetupHASH = $TRUE }
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Не совпал хэш у файла $($File[0])"
				$Global:SCCMClientParam.DistribHASH = $false
			}
		}
	}
	ELSE
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось получить спискок файлов и хэш"
		$Global:SCCMClientParam.DistribHASH = $false
	}
	#$Global:SCCMClientParam.ccmsetupHASH = $true #for test
	
}

FUNCTION MobileDownload
{
	WriteToLog -Severity "INFORMATION" -Message "Проверяется возможность копирования дистрибутива через защищенный канал SSL\TLS."
	# Получение машинного сертификата для ПК. [-1] - если их несколько, то берется последний (свежий)
	$cert = (Get-ChildItem -Path cert:\LocalMachine\My\ | Where-Object{ $_.Subject -Like "*CN=$env:COMPUTERNAME*" })[-1]
	IF ([string]::IsNullOrEmpty($cert))
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось получить PKI сертификат."
		RETURN $false
	}
	# В $ASPContent результат выполнения команды (Get-ChildItem -Path "C:\TEMP\Client_ASP\CLIENT" -Recurse -file).FullName
	# Путь C:\TEMP\Client_ASP\CLIENT\ обрезан, разделитель ";"
	# Через ASP возвращается по аналогии с хэшем (возможно потом его и будем использовать)
	IF ([string]::IsNullOrEmpty($Global:SCCMClientParam.HTTPHash)) { LocalSiteServer -RequestType GetHash }
	IF (![string]::IsNullOrEmpty($Global:SCCMClientParam.HTTPHash))
	{
		$DistribFiles = $($Global:SCCMClientParam.HTTPHash).split(';') | ForEach-Object{ $_.split(',')[0] } | Where-Object { ![string]::IsNullOrEmpty($_) }
	}
	ELSE
	{
		ELSE
		{
			WriteToLog -Severity "WARNING" -Message "Не удалось получить спискок файлов."
			RETURN $false
		}
	}
	#$ASPContent = [string]('ccmsetup.cab;ccmsetup.exe;ep_defaultpolicy.xml;scepinstall.exe;wimgapi.msi;i386\client.msi;i386\microsoftpolicyplatformsetup.msi;i386\msrdcoob_x86.exe;i386\msxml6.msi;i386\ndp452-kb2901907-x86-x64-allos-enu.exe;i386\silverlight.exe;i386\vc50727_x86.exe;i386\vcredist_x86.exe;i386\wic_x86_enu.exe;i386\windowsfirewallconfigurationprovider.msi;i386\windowsupdateagent30-x86.exe;i386\ClientUpdate\configmgr1606-client-kb3186654-i386.msp;i386\LanguagePack\CLP1049.msp;i386\LanguagePack\CLP1049.mst;x64\client.msi;x64\microsoftpolicyplatformsetup.msi;x64\msrdcoob_amd64.exe;x64\msxml6_x64.msi;x64\vc50727_x64.exe;x64\vcredist_x64.exe;x64\wic_x64_enu.exe;x64\windowsfirewallconfigurationprovider.msi;x64\windowsupdateagent30-x64.exe;x64\ClientUpdate\configmgr1606-client-kb3186654-x64.msp;x64\LanguagePack\CLP1049.msp;x64\LanguagePack\CLP1049.mst;')
	# Результат ASP разбивается на файлы, пустые строки отсекаются
	#$DistribFiles = $ASPContent.split(';') | Where-Object { ![string]::IsNullOrEmpty($_) }
	# Начинаем перебирать файлы
	FOREACH ($File IN $DistribFiles)
	{
		TRAP
		{
			IF ($($Error[0].Exception.Message) -match "404")
			{
				WriteToLog -Severity "WARNING" -Message "Файл $File не найден на сервере."
				CONTINUE
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Error: $($Error[0].Exception.Message)"
				WriteToLog -Severity "WARNING" -Message "Копирование завершено с ошибками."
				RETURN $false
			}
		}
		# Получаем путь до файла
		$Path = $File | Split-Path -Parent
		# Если папка не существует, то создаем ее
		IF (!(Test-Path "$($Global:SCCMClientParam.LocalPath)\$Path")) { New-Item -Path "$($Global:SCCMClientParam.LocalPath)\$Path" -ItemType Directory -Force | Out-Null }
		WriteToLog -Severity "INFORMATION" -Message "Копируем файл $($Global:SCCMClientParam.LocalPath)\$File."
		Invoke-WebRequest -Uri "https://irida3-m12.sberbank.ru/mcs_slp_cert/client/$($File.Replace('\', '/'))" -UseBasicParsing -Certificate $cert -OutFile "$($Global:SCCMClientParam.LocalPath)\$File" -ErrorAction Stop
	}
	RETURN $true
}

FUNCTION DPDownload
{
	WriteToLog -Severity "INFORMATION" -Message "Проверяется возможность копирования дистрибутива с DP."
	IF (Test-Path -Path "$env:windir\system32\robocopy.exe")
	{
		WriteToLog -Severity "INFORMATION" -Message "Robocopy запущен с аргументами: \\$DP\$($Global:SCCMClientParam.SharePath) $($Global:SCCMClientParam.LocalPath) /DCOPY:DA /COPY:DA /MIR /IPG:1200 /eta /ns /np /tee /log:C:\temp\robocopy.log"
		Invoke-Expression -Command "robocopy \\$DP\$($Global:SCCMClientParam.SharePath) $($Global:SCCMClientParam.LocalPath) /DCOPY:DA /COPY:DA /MIR /IPG:1200 /eta /ns /np /tee /log:C:\temp\robocopy.log"
		$Result = $Global:LastExitCode
		IF (($Result -ge 0) -AND ($Result -lt 8) -AND ![string]::IsNullOrEmpty($Result))
		{
			WriteToLog -Severity "INFORMATION" -Message "Копирование успешно завершено с кодом: $Result."
			#RETURN $true
		}
		ELSE
		{
			WriteToLog -Severity "WARNING" -Message "Копирование завершено с ошибкой: $Result"
			RETURN $false
		}
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "Robocopy.exe не найдено, будет произведена попытка копирования стандартными методами."
		(Get-ChildItem -Path "\\$DP\$($Global:SCCMClientParam.SharePath)" -Recurse -file).FullName
		$DistribFiles = ((Get-ChildItem -Path "\\$DP\$($Global:SCCMClientParam.SharePath)" -Recurse -file -ea Stop).FullName).replace("\\$DP\$($Global:SCCMClientParam.SharePath)\", "")
		FOREACH ($File IN $DistribFiles)
		{
			TRAP
			{
				WriteToLog -Severity "WARNING" -Message "Error: $($Error[0].Exception.Message)"
				WriteToLog -Severity "WARNING" -Message "Копирование завершено с ошибками."
				RETURN $false
			}
			# Получаем путь до файла
			$Path = $File | Split-Path -Parent
			# Если папка не существует, то создаем ее
			IF (!(Test-Path "$($Global:SCCMClientParam.LocalPath)\$Path")) { New-Item -Path "$($Global:SCCMClientParam.LocalPath)\$Path" -ItemType Directory -Force | Out-Null }
			# WriteToLog -Severity "INFORMATION" -Message "Копируем файл $($Global:SCCMClientParam.LocalPath)\$File."
			Copy-Item -Path "\\$DP\$($Global:SCCMClientParam.SharePath)\$File" -Destination "$($Global:SCCMClientParam.LocalPath)\$Path" -Force -ea Stop
		}
		#RETURN $True
	}
	WriteToLog -Severity "INFORMATION" -Message "Дистрибутив скопирован в папку $($Global:SCCMClientParam.LocalPath). Выполняется проверка версии и хэша дистрибутива."
	CheckHash # Проверка хэша локального дистрибутива
	IF ($Global:SCCMClientParam.DistribHASH)
	{
		WriteToLog -Severity "INFORMATION" -Message "Хэш совпадает. Установка будет производиться из локального дистрибутива."
		$Global:SCCMClientParam.InstallPath = $Global:SCCMClientParam.LocalPath
		RETURN $true
	}
	ELSE
	{
		WriteToLog -Severity "WARNING" -Message "Хэш не совпадает после скачивания."
		RETURN $false
	}
}

FUNCTION BitsDownload
{
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "Bits Error: $($Error[0].Exception.Message)"
		CONTINUE
	}
	WriteToLog -Severity "INFORMATION" -Message "Проверяется возможность копирования ccmsetup.exe с помощью BITS."
	IF (!(Test-Path $Global:SCCMClientParam.LocalPath)) { New-Item -Path $Global:SCCMClientParam.LocalPath -ItemType Directory -Force | Out-Null }
	$BitsTransfer = Start-BitsTransfer -DisplayName ccmsetup -Source http://http://Management_Point_1.Sigma.ru/SCCM_CLIENT_2012/ccmsetup.exe -Destination $($Global:SCCMClientParam.LocalPath) -Asynchronous
	
	IF (![string]::IsNullOrEmpty($BitsTransfer))
	{
		WriteToLog -Severity "INFORMATION" -Message "Ожидание завершения задачи Bits $($BitsTransfer.JobId)"
		DO
		{
			Start-Sleep -Seconds 2
			$BitsTransfer = Get-BitsTransfer -JobId $BitsTransfer.JobId -ErrorAction Stop
			IF ($BitsTransfer.JobState -eq "Error" -or $BitsTransfer.JobState -eq "TransientError")
			{
				WriteToLog -Severity "WARNING" -Message "Error: $($BitsTransfer.ErrorDescription | Where-Object { ![string]::IsNullOrEmpty($_) })"
				BREAK
			}
			IF ((New-TimeSpan -Start (get-date($BitsTransfer.CreationTime)) -End (get-date)).Minutes -gt 30)
			{
				WriteToLog -Severity "WARNING" -Message "Скачивание длится более 30 минут"
				BREAK
			}
		}
		WHILE ($BitsTransfer.JobState -ne "Transferred")
		IF ($BitsTransfer.JobState -eq "Transferred")
		{
			WriteToLog -Severity "INFORMATION" -Message "Скачивание завершено успешно."
			Get-BitsTransfer -JobId $BitsTransfer.JobId | Complete-BitsTransfer | Remove-BitsTransfer
			RETURN $true
		}
		ELSE
		{
			WriteToLog -Severity "WARNING" -Message "Скачивание завершено с ошибками."
			Get-BitsTransfer -JobId $BitsTransfer.JobId | Remove-BitsTransfer
			RETURN $false
		}
	}
	ELSE
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось создать задачу в BITS."
		RETURN $false
	}
}

FUNCTION CCMClean
{
	WriteToLog -Severity "INFORMATION" -Message "Запуск CCMCleaner"
	IF (!(Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue)) { New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null }
	$Query1 = @()
	$Query1 = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.InstallSource -match ([regex]::Escape('C:\Windows\ccmsetup\')) } | Select-Object -Property DisplayName, PSChildName, PSPath
	$Query1 | Format-List
	$Query1 | ForEach-Object{ $_.PSPath | Remove-Item -Recurse -Force }
	$MassPatch = @(
		'HKLM:\SOFTWARE\Classes\Installer\Features\*',
		'HKLM:\SOFTWARE\Classes\Installer\Products\*',
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*',
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\*',
		'HKCR:\Installer\Products\*',
		'HKCR:\Installer\Patches\*',
		'HKCR:\Installer\Features\*'
	)
	FOREACH ($Patch IN $MassPatch)
	{
		$Query2 = @()
		FOREACH ($Name IN $($Query1.DisplayName))
		{
			$Query2 += Get-ItemProperty $Patch | Where-Object { $_.ProductName -match $Name } | Select-Object -Property ProductName, PSChildName, PSPath
		}
		
		
		$Query2 | Format-List
		$Query2 | ForEach-Object{ $_.PSPath | Remove-Item -Recurse -Force }
	}
}


FUNCTION Install
{
	PARAM
	(
		[switch]$Repeat = $false
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "Install Error: $($Error[0].Exception.Message)"
		CONTINUE
	}
	#region Отправка накопленных QC
	FOREACH ($Code IN $Global:QCodeArray)
	{
		WriteBD -QuitCode $Code
	}
	#endregion
	#region Проверка всего и вся, что может помешать установке.
	# Исключение переустановки для мигрировавших менее 2 дней назад ПК
	$InstallAge = (New-TimeSpan -Start $($global:SystemInfo.OS.InstallDate) -End (get-date -Format D)).days
	SWITCH ((get-date).DayOfWeek)
	{
		"Monday" { $InstallAge = $InstallAge + 2 }
		"Tuesday" { $InstallAge = $InstallAge + 1 }
	}
	IF ((Test-Path "$Env:SystemDrive\Migration" -ErrorAction Stop) -and $InstallAge -lt 2 -and !($Global:SCCMClientParam.Bad))
	{
		WriteToLog -Severity "INFORMATION" -Message "INSTALL: Обнаружена папка C:\Migration, Установка системы выполнена $($global:SystemInfo.OS.InstallDate), менее 2 рабочих дней назад. Переустановка отменена."
		WriteBD -QuitCode 351
		Finish
	}
	$Drive = Get-WmiObject -Class win32_logicaldisk | Where-Object { $_.DeviceID -like $env:SystemDrive }
	IF ($($Drive.FreeSpace)/1073741824 -lt $Global:ConfigParam.MinTotalSize)
	{
		WriteToLog -Severity "INFORMATION" -Message "Размер системного диска меньше 80Gb"
	}
	IF ($($Drive.FreeSpace)/1048576 -lt $Global:ConfigParam.MinFreeSpace)
	{
		WriteBD -QuitCode 21
		WriteToLog -Severity "FAILURE" -Message "На системном диске недостаточно свободного места для установки."
	}
	#endregion
	#region Проверяем наличие дистрибутива и хэш
	IF (Test-Path "$($Global:SCCMClientParam.LocalPath)\ccmsetup.exe" -ErrorAction Stop)
	{
		WriteToLog -Severity "INFORMATION" -Message "ccmsetup.exe обнаружен в папке $($Global:SCCMClientParam.LocalPath). Выполняется проверка версии и хэша дистрибутива."
		CheckHash # Проверка хэша локального дистрибутива
		IF ($Global:SCCMClientParam.DistribHASH)
		{
			WriteToLog -Severity "INFORMATION" -Message "Хэш совпадает. Установка будет производиться из локального дистрибутива."
			$Global:SCCMClientParam.InstallPath = $Global:SCCMClientParam.LocalPath
		}
		ELSE
		{
			WriteToLog -Severity "INFORMATION" -Message "Установка с локального дистрибутива невозможна."
		}
	}
	IF ([string]::IsNullOrEmpty($Global:SCCMClientParam.InstallPath))
	{
		WriteToLog -Severity "INFORMATION" -Message "Дистрибутив локально не обнаружен. Определение типа запуска установки."
		IF ($Global:SCCMClientParam.Location -eq 102)
		{
			IF (MobileDownload)
			{
				WriteToLog -Severity "INFORMATION" -Message "Дистрибутив скопирован в папку $($Global:SCCMClientParam.LocalPath). Выполняется проверка версии и хэша дистрибутива."
				CheckHash # Проверка хэша локального дистрибутива
				IF ($Global:SCCMClientParam.DistribHASH)
				{
					WriteToLog -Severity "INFORMATION" -Message "Хэш совпадает. Установка будет производиться из локального дистрибутива."
					$Global:SCCMClientParam.InstallPath = $Global:SCCMClientParam.LocalPath
				}
				ELSE
				{
					WriteToLog -Severity "WARNING" -Message "Хэш не совпадает после скачивания. Установка отменена."
					Finish
				}
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Не удалось выполнить копирование дистрибутива. Установка отменена."
				Finish
			}
		}
		ELSEIF ($Global:SCCMClientParam.Location -eq 101 -and $Global:SystemInfo.domain -ne "sigma.ru")
		{
			# скачиваем ccmsetup через BITS, установка с ключом MP    
			IF (BitsDownload)
			{
				WriteToLog -Severity "INFORMATION" -Message "Файл ccmsetup.exe скопирован в папку $($Global:SCCMClientParam.LocalPath). Выполняется проверка версии и хэша файла."
				CheckHash -ccmsetup # Проверка хэша локального дистрибутива
				IF ($Global:SCCMClientParam.ccmsetupHASH)
				{
					WriteToLog -Severity "INFORMATION" -Message "Хэш совпадает. Установка будет производиться с ключом /MP."
					$Global:SCCMClientParam.InstallPath = $Global:SCCMClientParam.LocalPath
					$KeyMP = $true
				}
				ELSE
				{
					WriteToLog -Severity "WARNING" -Message "Хэш не совпадает после скачивания. Установка отменена."
					Finish
				}
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Не удалось выполнить копирование дистрибутива. Установка отменена."
				Finish
			}
		}
		ELSE
		{
			WriteToLog -Severity "INFORMATION" -Message "Проверяется возможность установки с DP."
			LocalSiteServer -RequestType DP
			#$Global:SCCMClientParam.DP
			$FastDP = $Global:SCCMClientParam.DP | Where-Object{ $_.Speed -eq "Fast" }
			$SlowDP = $Global:SCCMClientParam.DP | Where-Object{ $_.Speed -eq "Slow" }
			IF (![string]::IsNullOrEmpty($FastDP))
			{
				FOREACH ($DP IN $FastDP.DPName)
				{
					TRAP # Обработчик ошибок
					{
						WriteToLog -Severity "WARNING" -Message "DP $DP Error: $($Error[0].Exception.Message)"
						CONTINUE
					}
					IF (PingHost -DP $DP)
					{
						IF (Test-Path -Path "\\$DP\$($Global:SCCMClientParam.SharePath)" -ErrorAction Stop)
						{
							$Global:SCCMClientParam.InstallPath = "\\$DP\$($Global:SCCMClientParam.SharePath)"
							WriteToLog -Severity "INFORMATION" -Message "Установка будет производиться c DP $($Global:SCCMClientParam.InstallPath)"
							BREAK
						}
					}
				}
			}
			IF ([string]::IsNullOrEmpty($Global:SCCMClientParam.InstallPath))
			{
				FOREACH ($DP IN $SlowDP.DPName)
				{
					TRAP # Обработчик ошибок
					{
						WriteToLog -Severity "WARNING" -Message "DP $DP Error: $($Error[0].Exception.Message)"
						CONTINUE
					}
					IF (PingHost -DP $DP)
					{
						WriteToLog -Severity "INFORMATION" -Message "Дистрибутив будет закачан с DP $DP"
						IF (DPDownload)
						{
							WriteToLog -Severity "INFORMATION" -Message "Дистрибутив скопирован в папку $($Global:SCCMClientParam.LocalPath). Выполняется проверка версии и хэша дистрибутива."
							CheckHash # Проверка хэша локального дистрибутива
							IF ($Global:SCCMClientParam.DistribHASH)
							{
								WriteToLog -Severity "INFORMATION" -Message "Хэш совпадает. Установка будет производиться из локального дистрибутива."
								$Global:SCCMClientParam.InstallPath = $Global:SCCMClientParam.LocalPath
								BREAK
							}
							ELSE
							{
								WriteToLog -Severity "WARNING" -Message "Хэш не совпадает после скачивания."
							}
						}
						ELSE
						{
							WriteToLog -Severity "WARNING" -Message "Не удалось выполнить копирование дистрибутива c DP $DP."
						}
					}
				}
			}
		}
	}
	IF ([string]::IsNullOrEmpty($Global:SCCMClientParam.InstallPath))
	{
		WriteToLog -Severity "WARNING" -Message "Не удалось определить способ установки. Установка отменена."
		Finish
	}
	#endregion
	
	# Счетчик установок клиента для блокировки
	$NeedInstallDate = ""
	$NeedInstallCount = 0
	$NeedInstallDate = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallDate -ErrorAction Stop).NeedInstallDate
	$NeedInstallCount = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallCount -ErrorAction Stop).NeedInstallCount
	IF ((New-TimeSpan -Start $NeedInstallDate -End (get-date -Format D)).days -gt 0 -or [string]::IsNullOrEmpty($NeedInstallDate))
	{
		Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallDate -Value $(get-date -Format D) -ErrorAction Stop
		Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallCount -Value $([int]$NeedInstallCount + 1) -ErrorAction Stop
		WriteBD -QuitCode "90$([int]$NeedInstallCount + 1)"
	}
	
	
	# Удаление клиента
	IF ($Global:ScriptParam.ClientHealth -ne 0 -or $Global:SCCMClientParam.Bad)
	{
		WriteToLog -Severity "INFORMATION" -Message "Обнаружен установленный клиент SCCM. Будет выполнено удаление."
		$result = Invoke -FilePatch "$($Global:SCCMClientParam.InstallPath)\ccmsetup.exe" -ArgumentList "/uninstall"
		CheckLog -LogName "$($Global:SCCMClientParam.SetupLog)" -SearchLine '<![LOG[CcmSetup' -QuitCode 0 -ScriptBlock {
			IF ($TextLastLine -match 'failed with error code')
			{
				WriteToLog -Severity "INFORMATION" -Message "Удаление завершено с ошибками: $TextLastLine"
				$Global:SCCMClientParam.Bad = $true
			}
			ELSEIF ($TextLastLine -match 'is exiting with return code 0')
			{
				WriteToLog -Severity "INFORMATION" -Message "Удаление завершено успешно."
			}
			ELSE
			{
				#WriteToLog -Severity "INFORMATION" -Message "Удаление завершено с ошибками: $TextLastLine"
				#$Global:SCCMClientParam.Bad = $true
				WriteToLog -Severity "INFORMATION" -Message "$LastLine"
				#WriteToLog -Severity "INFORMATION" -Message "$DateLastLine"
			}
		}
		CheckService -ServiceName 'CCMExec' -Status Stopped -StartMode Disabled -Delete
		CheckService -ServiceName 'ccmsetup' -Status Stopped -StartMode Disabled -Delete
	}
	# Пресоздаем WMI, если ПК находится BadClients
	IF ($Global:SCCMClientParam.Bad)
	{
		RebuildWMI
		#CCMClean
	}
	# Очистка реестра после удаления
	FOREACH ($RegKey IN $Global:SCCMClientParam.RegKeys)
	{
		TRAP # Обработчик ошибок
		{
			WriteToLog -Severity "WARNING" -Message "Reg Error: $($Error[0].Exception.Message)"
			CONTINUE
		}
		IF (Test-Path -Path $RegKey)
		{
			WriteToLog -Severity "INFORMATION" -Message "Reg: Удаляем ветку реестра $RegKey"
			Remove-Item -Path $RegKey -Recurse -Force -ea Stop
		}
	}
	# Удаление файлов и папок
	FOREACH ($Folder IN $Global:SCCMClientParam.Folders)
	{
		IF (Test-Path $Folder -ErrorAction SilentlyContinue)
		{
			WriteToLog -Severity "INFORMATION" -Message "INSTALL: На ПК найдена папка $Folder - удаляем"
			Remove-Item -Path $Folder -Recurse -Force -ErrorAction Stop
		}
	}
	
	# Установка клиента
	#region Определение параметров установки
	$Parameters = ""
	
	# Отключение службы
	$Parameters += "/noservice" + [char]32
	
	# Использование PKI сертификата
	IF ($Global:SCCMClientParam.Location -eq 102)
	{
		$Parameters += "/UsePKICert" + [char]32
	}
	
	# Код сайта управления
	LocalSiteServer -RequestType SiteCode
	$Parameters += "SMSSITECODE=$($Global:SCCMClientParam.SiteCode)"
	
	# Добавление SMSMP=Management_Point_1.Sigma.ru
	
	IF ($Global:SCCMClientParam.Location -eq 102 -and ![string]::IsNullOrEmpty($((nltest /dsgetdc:sigma.ru | Where-Object { $_ -match '\\\\([a-zA-Z0-9]+)' }).Split('\')[2])))
	{
		$Parameters += "Management_Point_1.internet_domain.ru" + [char]32
	}
	ELSE
	{
		$Parameters += "SMSMP=Management_Point_1.Sigma.ru" + [char]32
	}
	
	# Добавление CCMHOSTNAME=Management_Point_1.internet_domain.ru
	IF ($Global:SCCMClientParam.Location -ne 100)
	{
		$Parameters += "CCMHOSTNAME=Management_Point_1.internet_domain.ru" + [char]32
	}
	
	# Добавление DNSSUFFIX=sigma.ru
	IF ($Global:SCCMClientParam.Location -ne 100)
	{
		$Parameters += "DNSSUFFIX=sigma.ru" + [char]32
	}
	
	# Для корректного выбора сертификата из хранилища
	$Parameters += "CCMFIRSTCERT=1" + [char]32
	
	# Добавление ключа "Всегда интернет" для мобильных клиентов
	IF ($Global:SCCMClientParam.Location -eq 102)
	{
		$Parameters += "CCMALWAYSINF=1" + [char]32
	}
	
	# Отключение CRL проверки
	IF ($NOCRLCheck)
	{
		$Parameters += "/NOCRLCheck" + [char]32
	}
	
	# Либо Source(локальный или с DP), либо с ключом /MP
	IF (!([string]::IsNullOrEmpty($KeyMP)) -and $KeyMP)
	{
		$Parameters += "/MP:$($Global:SCCMClientParam.LocalMP)" # Пробел добавляется в ASP-запросе
	}
	ELSE { $Parameters += "/Source:$($Global:SCCMClientParam.InstallPath)\" + [char]32 }
	
	#endregion
	
	$result = Invoke -FilePatch "$($Global:SCCMClientParam.InstallPath)\ccmsetup.exe" -ArgumentList $Parameters
	IF ($result) { WriteToLog -Severity "INFORMATION" -Message "Установка завершена." }
	CheckLog -LogName "$($Global:SCCMClientParam.SetupLog)" -SearchLine '<![LOG[CcmSetup' -QuitCode 0 -ScriptBlock {
		IF ($TextLastLine -match 'failed with error code')
		{
			WriteToLog -Severity "INFORMATION" -Message "Установка завершена с ошибками: $TextLastLine"
			IF (!$Repeat)
			{
				$Global:SCCMClientParam.Bad = $true
				CCMClean
				Install -Repeat
			}
		}
		ELSEIF ($TextLastLine -match 'is exiting with return code 0')
		{
			WriteToLog -Severity "INFORMATION" -Message "Установка завершена успешно."
			$Global:ScriptParam.ClientHealth = 2
		}
		ELSE
		{
			#WriteToLog -Severity "INFORMATION" -Message "Установка завершена с ошибками: $TextLastLine"
			#$Global:SCCMClientParam.Bad = $true
			WriteToLog -Severity "INFORMATION" -Message "$LastLine"
			#WriteToLog -Severity "INFORMATION" -Message "$DateLastLine"
		}
	}
}

FUNCTION Wait-Process #
{
	[CmdletBinding()]
	PARAM
	(
		[ValidateNotNullOrEmpty()]
		[string]$ProcessId
	)
	$Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
	
	IF (![string]::IsNullOrEmpty($Process))
	{
		WriteToLog -Severity "INFORMATION" -Message "Ожидание завершения процесса $($Process.Product)..."
		DO
		{
			Start-Sleep -Seconds 2
			$Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
		}
		WHILE (![string]::IsNullOrEmpty($Process))
		WriteToLog -Severity "INFORMATION" -Message "Процесс $($Process.Product) завершен."
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "Процесс завершен."
	}
}
FUNCTION CheckIP #
{
	SWITCH ($Global:SCCMClientParam.Location)
	{
		102 {
			# Для мобильных задаем IP-адрес, который есть в границах
			$Global:SystemInfo.IPAddress = "10.20.30.40"
		}
		default
		{
			# Получение IP-адреса из WMI
			$NICs = Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"
			IF (![string]::IsNullOrEmpty($NICs))
			{
				$IP_correct = $False
				FOREACH ($Adapter IN $NICs)
				{
					$arrAdapterIPAddress = $Adapter.IPAddress
					FOREACH ($AdapterIPAddress IN $arrAdapterIPAddress)
					{
						IF (!($Adapter.DefaultIPGateway -eq $Null) -AND (($Adapter.DefaultIPGateway).trim() -ne "") -AND ($Adapter.DefaultIPGateway -ne "0.0.0.0") -and !($AdapterIPAddress.contains(":")))
						{
							$IPOctet = $AdapterIPAddress.split(".")
							IF (($IpOctet[0] -ne "127") -AND ($IpOctet[0] -ne "192") -AND ($IpOctet[0] -ne "169"))
							{
								$IPAddressGet = $AdapterIPAddress
								$SubnetMaskGet = $Adapter.IPSubnet
							}
							ELSE
							{
								$IPAddressNotGet = $AdapterIPAddress
								$SubnetMaskNotGet = $Adapter.IPSubnet
							}
							
							IF ([string]::IsNullOrEmpty($IPAddressGet))
							{
								$Global:SystemInfo.IPAddress = $IPAddressNotGet
								$SubnetMask = $SubnetMaskNotGet
							}
							ELSE
							{
								$Global:SystemInfo.IPAddress = $IPAddressGet
								$SubnetMask = $SubnetMaskGet
							}
							$Global:SystemInfo.Gateway = $Adapter.DefaultIPGateway[0]
							$Global:SystemInfo.NetMask = $SubnetMask
							$IP = $Global:SystemInfo.IPAddress.split(".")
							$SN = $SubnetMask.split(".")
							$Global:SystemInfo.Subnet = ($IP[0] -band $SN[0]).tostring() + "." + ($IP[1] -band $SN[1]).tostring() + "." + ($IP[2] -band $SN[2]).tostring() + "." + ($IP[3] -band $SN[3]).tostring()
							$CheckMP = LocalSiteServer -RequestType DefaultMP -Check
							IF ($CheckMP -eq $true)
							{
								WriteToLog -Severity "INFORMATION" -Message "Определен корректный IP-адрес сетевого адаптера: $($Global:SystemInfo.IPAddress), подсеть: $($Global:SystemInfo.Subnet)"
								$IP_correct = $True
							}
							elseif ($CheckMP -eq 'no')
							{
								# Для "безграничных" задаем IP-адрес, который есть в границах
								$Global:SystemInfo.IPAddress = "1.0.0.1"
								WriteToLog -Severity "INFORMATION" -Message "Граница не найдена, назначен универсальный IP-адрес сетевого адаптера: $($Global:SystemInfo.IPAddress)"
								$IP_correct = $True
							}
							ELSE
							{
								WriteToLog -Severity "INFORMATION" -Message "Найден некорректный IP-адрес сетевого адаптера: $($Global:SystemInfo.IPAddress), подсеть: $($Global:SystemInfo.Subnet)"
							}
						}
						IF ($IP_correct) { BREAK }
					}
				}
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Error: Не найдено включенных сетевых адаптеров"
				Finish
			}
		}
	}
}
FUNCTION CheckLog #
{
	PARAM (
		[Parameter(Mandatory = $true)]
		[string]$LogName,
		[string]$SearchLine,
		[int]$QuitCode = -1,
		[scriptblock]$ScriptBlock
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "CheckLog Error: $($Error[0].Exception.Message)"
		CONTINUE
	}
	IF (Test-Path -Path $LogName)
	{
		$CheckLog = ''
		$CheckLog = Get-Content -Path $LogName
		IF ($CheckLog -ne '')
		{
			$LastLine = ''
			FOREACH ($Line IN $CheckLog)
			{
				IF ($Line -match ([regex]::Escape($SearchLine)))
				{
					$LastLine = $Line
				}
			}
			IF ($LastLine -ne '')
			{
				$DateLastLine = "$(Get-Date([datetime]$($LastLine.Substring($LastLine.IndexOf('date=') + 6, 10))) -Format 'MM.dd.yyyy') $($LastLine.Substring($LastLine.IndexOf('time=') + 6, 8))"
				$TextLastLine = $($LastLine.Substring(0, $LastLine.IndexOf('time=') - 1))
				WriteToLog -Severity "WARNING" -Message "CheckLog: В логе $LogName обнаружена строка <$DateLastLine> $TextLastLine"
				IF ($QuitCode -gt 0) { WriteBD -QuitCode $QuitCode }
				Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $DateLastLine
			}
			ELSE
			{
				WriteToLog -Severity "INFORMATION" -Message "CheckLog: Лог $LogName успешно проверен, ошибок не обнаружено"
			}
		}
		ELSE
		{
			WriteToLog -Severity "WARNING" -Message "CheckLog: Не удалось загрузить $LogName"
		}
	}
	ELSE
	{
		WriteToLog -Severity "WARNING" -Message "CheckLog: Лог $LogName не найден"
	}
}
FUNCTION RunCCMAction ($ActionID) #
{
	TRY
	{
		$Action = (New-Object -ComObject CPApplet.cpAppletmgr).GetClientActions() | Where-Object { $_.ActionID -eq $ActionID }
		$Action.PerformAction()
		WriteToLog -Severity "INFORMATION" -Message "RunCCMAction: Выполнен запуск $($Action.Name)"
	}
	CATCH
	{
		WriteToLog -Severity "INFORMATION" -Message "RunCCMAction: Не удалось выполнить запуск $($Action.Name). $($Error[0].Exception.Message)"
	}
}
FUNCTION CreateScheduler #
{
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "Scheduler Error: $($Error[0].Exception.Message)"
		CONTINUE
	}
	WriteToLog -Severity "INFORMATION" -Message "Полный путь к запущенному скрипту: $($Global:ScriptParam.FullName)"
	#region CopyScript
	IF ($($Global:ScriptParam.Folder) -ne $($Global:ScriptParam.LocalPath))
	{
		WriteToLog -Severity "INFORMATION" -Message "Копируем скрипт в локальную папку."
		IF (Test-Path -Path "$env:windir\system32\robocopy.exe")
		{
			$Result = $null
			Invoke-Expression -Command "robocopy $($Global:ScriptParam.Folder) $($Global:ScriptParam.LocalPath) $($Global:ScriptParam.Name)"
			$Result = $Global:LastExitCode
			WriteToLog -Severity "INFORMATION" -Message "Robocopy запущен с аргументами: $($Global:ScriptParam.Folder) $($Global:ScriptParam.LocalPath) $($Global:ScriptParam.Name)."
			IF (($Result -ge 0) -AND ($Result -lt 8) -AND ($Result -ne $null))
			{
				WriteToLog -Severity "INFORMATION" -Message "Копирование успешно завершено с кодом: $Result."
				$Global:ScriptParam.ScriptCopy = $True
				#Invoke-Expression -Command "robocopy $($Global:ScriptParam.Folder)\$($Global:SystemInfo.OS.OSArchitecture) $($Global:ScriptParam.LocalPath)\$($Global:SystemInfo.OS.OSArchitecture) devcon.exe"
			}
			ELSE
			{
				WriteToLog -Severity "WARNING" -Message "Копирование завершено с ошибкой: $Result"
				$Global:ScriptParam.ScriptCopy = $False
			}
		}
		ELSE
		{
			WriteToLog -Severity "INFORMATION" -Message "Robocopy.exe не найдено, будет произведена попытка копирования стандартными методами."
			IF (Test-Path -Path $Global:ScriptParam.LocalPath)
			{
				WriteToLog -Severity "INFORMATION" -Message "Папка $($Global:ScriptParam.LocalPath) существует."
			}
			ELSE
			{
				WriteToLog -Severity "INFORMATION" -Message "Папка $($Global:ScriptParam.LocalPath) не найдена. Создаем папку."
				TRY
				{
					New-Item -path $Global:ScriptParam.LocalPath -ItemType Directory -Force -ErrorAction Stop
					WriteToLog -Severity "INFORMATION" -Message "Папка успешно создана."
				}
				CATCH
				{
					WriteToLog -Severity "WARNING" -Message "Ошибка создания папки. Код ошибки: $($Error[0].Exception.Message)"
				}
			}
			TRY
			{
				Copy-Item -path $Global:ScriptParam.FullName -destination $Global:ScriptParam.LocalPath -ErrorAction Stop -Force
				WriteToLog -Severity "INFORMATION" -Message "Скрипт успешно скопирован стандартными методами."
				$Global:ScriptParam.ScriptCopy = $True
				#New-Item -path "$($Global:ScriptParam.LocalPath)\$($Global:SystemInfo.OS.OSArchitecture)" -ItemType Directory -Force -ErrorAction Stop
				#Copy-Item -path "$($Global:ScriptParam.Folder)\$($Global:SystemInfo.OS.OSArchitecture)\devcon.exe" -destination "$($Global:ScriptParam.LocalPath)\$($Global:SystemInfo.OS.OSArchitecture)" -ErrorAction Stop -Force
			}
			CATCH
			{
				WriteToLog -Severity "WARNING" -Message "Ошибка копирования стандартными методами. Код ошибки: $($Error[0].Exception.Message)"
				$Global:ScriptParam.ScriptCopy = $False
			}
		}
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "Скрипт запущен с локальной папки."
		$Global:ScriptParam.ScriptCopy = $True
	}
	#endregion CopyScript
	IF (!$Global:ScriptParam.ScriptCopy)
	{
		WriteToLog -Severity "WARNING" -Message "Создание задачи планировщика отменено."
		WriteBD -QuitCode 51
		RETURN
	}
	#region Sheduler
	$ScheduledTask = $null
	$ScheduledTask = Get-ScheduledTask -TaskName $Global:ScriptParam.TaskName
	IF (![string]::IsNullOrEmpty($ScheduledTask))
	{
		WriteToLog -Severity "INFORMATION" -Message "Задача с именем $($Global:ScriptParam.TaskName) найдена. Выполняется проверка состояния задачи."
		WriteToLog -Severity "INFORMATION" -Message "Состояние задачи: $($ScheduledTask.State)"
		IF ($ScheduledTask.State -eq 'Disabled')
		{
			IF (($ScheduledTask | Enable-ScheduledTask).State -eq 'Disabled')
			{
				WriteToLog -Severity "WARNING" -Message "Ошибка перевода задачи в состояние ENABLE"
			}
			ELSE
			{
				WriteToLog -Severity "INFORMATION" -Message "Задача успешно переведена в состояние ENABLE"
			}
		}
		$Houre = Get-random (10 .. 17)
		$Minutes = Get-random (10 .. 59)
		[string]$Time = [string]$Houre + ":" + [string]$Minutes
		$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy RemoteSigned -WindowStyle Hidden -File $($Global:ScriptParam.LocalPath)\$($Global:ScriptParam.Name)"
		$Trigger = @(
			$(New-ScheduledTaskTrigger -Daily -At $Time),
			$(New-ScheduledTaskTrigger -AtStartup)
		)
		$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
		TRY
		{
			Set-ScheduledTask $Global:ScriptParam.TaskName -Action $Action -Trigger $Trigger -Settings $Settings
			Start-Sleep -Seconds 5
			$Task = Get-ScheduledTask -TaskName $($Global:ScriptParam.TaskName)
			$Task.Triggers[1].Delay = 'PT30M'
			$Task | Set-ScheduledTask
			WriteToLog -Severity "INFORMATION" -Message "Задача успешно изменена"
		}
		CATCH
		{
			WriteToLog -Severity "WARNING" -Message "Ошибка изменения задачи"
			WriteBD -QuitCode 51
		}
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "Задача с именем $($Global:ScriptParam.TaskName) не найдена. Выполняется создание задачи."
		$Houre = Get-random (10 .. 17)
		$Minutes = Get-random (10 .. 59)
		[string]$Time = [string]$Houre + ":" + [string]$Minutes
		$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy RemoteSigned -WindowStyle Hidden -File $($Global:ScriptParam.LocalPath)\$($Global:ScriptParam.Name)"
		$Trigger = @(
			$(New-ScheduledTaskTrigger -Daily -At $Time),
			$(New-ScheduledTaskTrigger -AtStartup)
		)
		$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
		Register-ScheduledTask -RunLevel Highest -TaskName $($Global:ScriptParam.TaskName) -Trigger $Trigger -Action $Action -User SYSTEM -Settings $Settings -ErrorAction Stop
		Start-Sleep -Seconds 5
		$Task = Get-ScheduledTask -TaskName $($Global:ScriptParam.TaskName)
		$Task.Triggers[1].Delay = 'PT30M'
		$Task | Set-ScheduledTask
		IF ($($Task).State -eq 'Ready')
		{
			WriteToLog -Severity "INFORMATION" -Message "Задача успешно создана и включена"
			WriteToLog -Severity "INFORMATION" -Message "Состояние задачи: Ready"
		}
		ELSE
		{
			WriteToLog -Severity "WARNING" -Message "Ошибка создания задачи"
			WriteBD -QuitCode 51
		}
	}
	#endregion
}

#endregion
#################################################################################
#                                     Script                                    #
#################################################################################
TRAP # Обработчик ошибок
{
	WriteToLog -Severity "WARNING" -Message "Error: $($Error[0].Exception.Message)"
	CONTINUE
}

WriteToLog -Severity "INFORMATION" -Message "Имя компьютера - $($Global:SystemInfo.CompName)"
WriteToLog -Severity "INFORMATION" -Message "Текущий пользователь - $($Global:SystemInfo.UserName)"
WriteToLog -Severity "INFORMATION" -Message "Скрипт запущен от имени - $env:USERNAME"
WriteToLog -Severity "INFORMATION" -Message "Версия PS - $($Global:SystemInfo.PSVersion)"
#region Get-OS
TRY
{ $OperatingSystem = Get-WmiObject -Class win32_operatingsystem -ErrorAction Stop }
CATCH
{
	RebuildWMI
	$OperatingSystem = Get-WmiObject -Class win32_operatingsystem -ErrorAction Stop
}
$add = New-Object -TypeName PSObject -Property @{
	Caption = $OperatingSystem.Caption;
	OS	    = 0
	OSArchitecture = $OperatingSystem.OSArchitecture;
	OSVersion = ($OperatingSystem.Version.ToString()).split('.')[0, 1] -join ".";
	OSBuild = $OperatingSystem.BuildNumber;
	OSLanguage = $OperatingSystem.OSLanguage;
	InstallDate = Get-Date ((([WMI]'').ConvertToDateTime($OperatingSystem.InstallDate)).ToUniversalTime()).AddMinutes($OperatingSystem.CurrentTimeZone) -Format "yyyy-MM-dd HH:mm:ss"
	LastBootUpTime = Get-Date((([WMI]'').ConvertToDateTime($OperatingSystem.LastBootUpTime)).ToUniversalTime()).AddMinutes($OperatingSystem.CurrentTimeZone) -Format "yyyy-MM-dd HH:mm:ss"
}

IF ($add.OSArchitecture -match '64') { $add.OSArchitecture = 64 }
ELSEIF ($add.OSArchitecture -match '32') { $add.OSArchitecture = 32 }
SWITCH ($add.OSVersion)
{
	"10.0" {
		$add.OS = 10 # Windows 10
		WriteToLog -Severity "INFORMATION" -Message "Версия OS - Windows 10"
	}
	"6.3" {
		$add.OS = 8 # Windows 8.1
		WriteToLog -Severity "INFORMATION" -Message "Версия OS - Windows 8.1"
	}
	"6.2" {
		$add.OS = 8 # Windows 8
		WriteToLog -Severity "INFORMATION" -Message "Версия OS - Windows 8"
	}
	"6.1" {
		$add.OS = 7 # Windows 7
		WriteToLog -Severity "INFORMATION" -Message "Версия OS - Windows 7"
	}
	"6.0" {
		$add.OS = 6 # Windows Vista
		WriteToLog -Severity "INFORMATION" -Message "Версия OS - Windows Vista"
	}
	"5.1" {
		$add.OS = 5 # Windows XP
		WriteToLog -Severity "INFORMATION" -Message "Версия OS - Windows XP"
	}
}
$Global:SystemInfo | Add-Member NoteProperty -Name OS -Value $add -Force
#endregion
WriteToLog -Severity "INFORMATION" -Message "Разрядность - $($Global:SystemInfo.OS.OSArchitecture)"
WriteToLog -Severity "INFORMATION" -Message "Сборка - $($Global:SystemInfo.OS.OSBuild)"
WriteToLog -Severity "INFORMATION" -Message "Система установлена - $($Global:SystemInfo.OS.InstallDate)"
IF ($($Global:SystemInfo.OS.OS) -eq 10) { ($Global:SystemInfo.Service | Where-Object { $_.Name -eq 'wuauserv' }).DefaultStartMode = 'Manual' }
IF ($($Global:SystemInfo.OS.Caption) -match 'server' -or $($Global:SystemInfo.OS.Caption) -match 'сервер')
{
	$Global:SystemInfo.ServerOS = $true
	WriteToLog -Severity "FAILURE" -Message "ERROR: Использование скрипта в серверной ОС отключено." # Завершает работу скрипта.
}
# Проверка корректности WMI.
#region CheckWMI
WriteToLog -Severity "INFORMATION" -Message "=== Проверка корректности WMI ==="
$CheckWMI = Invoke-Expression -Command "winmgmt /verifyrepository"
IF ($CheckWMI -match "База данных WMI не согласована" -or $CheckWMI -match "WMI repository is inconsistent")
{
	WriteToLog -Severity "WARNING" -Message "WMI: $CheckWMI"
	Invoke-Expression -Command "winmgmt /salvagerepository"
	$CheckWMI = Invoke-Expression -Command "winmgmt /verifyrepository"
	IF ($CheckWMI -match "База данных WMI не согласована" -or $CheckWMI -match "WMI repository is inconsistent")
	{
		WriteToLog -Severity "WARNING" -Message "WMI: $CheckWMI"
		Invoke-Expression -Command "winmgmt /resetrepository"
		$CheckWMI = Invoke-Expression -Command "winmgmt /verifyrepository"
		IF ($CheckWMI -match "База данных WMI не согласована" -or $CheckWMI -match "WMI repository is inconsistent")
		{
			WriteToLog -Severity "WARNING" -Message "WMI: $CheckWMI"
			RebuildWMI
		}
		ELSE
		{
			WriteToLog -Severity "INFORMATION" -Message "WMI: $CheckWMI"
		}
	}
	ELSE
	{
		WriteToLog -Severity "INFORMATION" -Message "WMI: $CheckWMI"
	}
}
ELSE
{
	WriteToLog -Severity "INFORMATION" -Message "WMI: $CheckWMI"
}
TRY
{
	$Global:WMI = Get-WmiObject -Namespace root\cimv2 -list -ErrorAction Stop
	WriteToLog -Severity "INFORMATION" -Message "WMI: Пространство имен CIMv2 корректно."
}
CATCH
{
	WriteToLog -Severity "WARNING" -Message "WMI: Не удалось подключиться к пространство имен CIMv2. Error is: $($Error[0].Exception.Message)"
	RebuildWMI
}
TRY
{
	$Test1 = Get-WmiObject -Namespace root\cimv2 -Class Win32_NetworkAdapterConfiguration -list -ErrorAction Stop
	WriteToLog -Severity "INFORMATION" -Message "WMI: Пространство имен Win32_NetworkAdapterConfiguration корректно."
}
CATCH
{
	WriteToLog -Severity "WARNING" -Message "WMI: Не удалось подключиться к пространство имен Win32_NetworkAdapterConfiguration. Error is: $($Error[0].Exception.Message)"
	RebuildWMI
}
#endregion
# Проверяем запущены ли другие копии скрипта в данный момент.
ScrCopyPsocCheck
# Определяем локацию клиента.
CheckLocation
# Настройка параметров в зависимости от определенной локации.
#region Location Settings
IF (Test-Path -Path HKLM:\SOFTWARE\Microsoft\CCM\Security)
{
	$AlwaysOnInternet = [int](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\Security -Name ClientAlwaysOnInternet -ErrorAction Stop).ClientAlwaysOnInternet
}
SWITCH ($Global:SCCMClientParam.Location)
{
	100 {
		$Global:ASP_Urls = $Global:SlpUrl.Omega
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - Omega"
	}
	101 {
		$Global:ASP_Urls = $Global:SlpUrl.Sigma
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - Sigma"
		IF ($AlwaysOnInternet -eq 1)
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\Security -Name ClientAlwaysOnInternet -Value 0 -ErrorAction Stop
			CheckService -ServiceName 'CCMExec' -Status Stopped -StartMode Disabled
			CheckService -ServiceName 'CCMExec' -Status Running -StartMode Automatic
		}
	}
	102 {
		$Global:ConfigParam.MaxExecAge = -1
		$Global:ASP_Urls = $Global:SlpUrl.Mobile
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - Mobile"
		IF ($AlwaysOnInternet -eq 0)
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\Security -Name ClientAlwaysOnInternet -Value 1 -ErrorAction Stop
			CheckService -ServiceName 'CCMExec' -Status Stopped -StartMode Disabled
			CheckService -ServiceName 'CCMExec' -Status Running -StartMode Automatic
		}
	}
	103 {
		$Global:ASP_Urls = $Global:SlpUrl.CIB
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - CIB"
	}
	0{
		WriteToLog -Severity "WARNING" -Message "Не определена локация клиента"
	}
}
SWITCH ($Global:SCCMClientParam.Location)
{
	102{
		$AppPool_1 = "mcs_slp_cert"
		$AppPool_2 = "cs_script_log"
	}
	100 {
		$AppPool_1 = "mcs_slp"
		$AppPool_2 = "mcs_slp"
	}
	DEFAULT
	{
		$AppPool_1 = "mcs_slp"
		$AppPool_2 = "cs_script_log"
	}
}
#endregion
# Определяем сетевые параметры. Раньше этого QC в БД не отправляются!
WriteToLog -Severity "INFORMATION" -Message "=== Определение сетевых параметров ==="
CheckIP
$Global:SystemInfo.DC_Name = $((nltest /dsgetdc:$($Global:SystemInfo.Domain) | Where-Object { $_ -match '\\\\([a-zA-Z0-9]+)' }).Split('\')[2])
WriteToLog -Severity "INFORMATION" -Message "Скрипт запущен из $($Global:SystemInfo.DC_Name)"
# Определение уникальных параметров
$Global:SystemInfo.BIOSSerial = (Get-WMIObject Win32_BIOS).SerialNumber
$Global:SystemInfo.MACAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $TRUE -and ![string]::IsNullOrEmpty($_.DefaultIPGateway) }).Macaddress
$Global:SystemInfo.UID = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes([string]"$($Global:SystemInfo.BIOSSerial):$($Global:SystemInfo.MACAddress)"))
###########################################################

WriteToLog -Severity "INFORMATION" -Message "=== START ==="
WriteBD -QuitCode 49
IF ($Global:SCCMClientParam.Location -ne 0) { WriteBD -QuitCode $Global:SCCMClientParam.Location } # Запись в БД определенной локации
#region check PC in BadClients
WriteToLog -Severity "INFORMATION" -Message "=== Проверка ПК в BadClients ==="
LocalSiteServer -RequestType BadClientsCheck
IF ($Global:SCCMClientParam.Bad)
{
	$Global:QCodeArray += 3
	WriteToLog -Severity "INFORMATION" -Message "ПК найден в BadClients"
	LocalSiteServer -RequestType BadClientsRemove
	CheckService -ServiceName smstsmgr -Status Stopped -StartMode Manual
	Get-Process -Name TSManager -ErrorAction SilentlyContinue | Stop-Process -Force
	Install
	Finish
}
ELSE
{
	$Global:QCodeArray += 2
	WriteToLog -Severity "INFORMATION" -Message "ПК не найден в BadClients"
}
#endregion
#region check client health
WriteToLog -Severity "INFORMATION" -Message "=== Проверка состояния клиента ==="
#region CheckService
WriteToLog -Severity "INFORMATION" -Message "=== Проверка состояния служб ==="
FOREACH ($SystemService IN $Global:SystemInfo.Service)
{
	CheckService -ServiceName $SystemService.Name -Status $SystemService.DefaultStatus -StartMode $SystemService.DefaultStartMode -Check
	IF ($SystemService.Status -eq $false)
	{
		WriteBD -QuitCode 16
		WriteToLog -Severity "WARNING" -Message "Не удалось установить параметры по-умолчанию для службы $($SystemService.Name)"
	}
	IF ($SystemService.Name -eq "CcmExec" -and $SystemService.Status -eq $false)
	{
		IF ([string]::IsNullOrEmpty($(Get-Service -Name $SystemService.Name -ErrorAction SilentlyContinue)))
		{
			$Global:ScriptParam.ClientHealth = 0
		}
		ELSE
		{
			$Global:ScriptParam.ClientHealth = 1
		}
	}
	ELSE
	{
		$Global:ScriptParam.ClientHealth = 2
	}
}


#endregion

#endregion

#region Проверка предыдущего запуска системы
TRY
{
	$EventDate = ''
	$EventDate = get-date((Get-EventLog -LogName System -Before (Get-Date -Hour 0 -Minute 0 -Second 0) -Newest 1).TimeGenerated) -Format D
	$EventTimeSpan = (New-TimeSpan -Start $EventDate -End (get-date -Format D)).days
}
CATCH
{
	WriteToLog -Severity "WARNING" -Message "Ошибка при получении из журнала событий даты предыдущего запуска системы: $($Error[0].Exception.Message)"
}
IF ($EventTimeSpan -gt 30)
{
	WriteToLog -Severity "WARNING" -Message "ПК запускался предыдущий раз $EventDate, что более 30 дней"
	WriteBD -QuitCode "820$EventTimeSpan"
}
#endregion
WriteToLog -Severity "INFORMATION" -Message "=== Проверка задания планировщика ==="
CreateScheduler


#region check log errors
WriteToLog -Severity "INFORMATION" -Message "=== Проверка логов ==="
CheckLog -LogName "$($Global:SCCMClientParam.Folders.CCM)\Logs\ClientIDManagerStartup.log" -SearchLine 'Failed to get certificate. Error: 0x80004005' -QuitCode 79 -ScriptBlock {
	#param ($Date)
	WriteToLog -Severity "INFORMATION" -Message "Выполняется восстановление и перезапуск службы."
	IF (Test-Path -Path "C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\RSA\MachineKeys\19c5cf9c7b5dc9de3e548adb70398402*")
	{
		Get-ChildItem -Path 'C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\RSA\MachineKeys' -Recurse -File -Filter "19c5cf9c7b5dc9de3e548adb70398402*" -Force | Remove-Item -Force
	}
	WriteToLog -Severity "INFORMATION" -Message "DateLastLine - $Date"
	CheckService -ServiceName 'CCMExec' -Status Stopped -StartMode Disabled
	CheckService -ServiceName 'CCMExec' -Status Running -StartMode Automatic
}
CheckLog -LogName "$($Global:SCCMClientParam.Folders.CCM)\Logs\WUAHandler.log" -SearchLine '0x80004005' -QuitCode 78 -ScriptBlock {
	WriteToLog -Severity "INFORMATION" -Message "Выполняется восстановление."
	Get-ChildItem -Path "C:\WINDOWS\System32\GroupPolicy\Machine\" -Recurse -File -Filter "Registry.pol" -Force | Remove-Item -Force
	$Command = Invoke-Expression -Command "gpupdate /force"
	WriteToLog -Severity "INFORMATION" -Message "CheckLog: $Command"
	RunCCMAction -ActionID '{00000000-0000-0000-0000-000000000113}'
	RunCCMAction -ActionID '{00000000-0000-0000-0000-000000000108}'
}




#endregion
#region check updates
WriteToLog -Severity "INFORMATION" -Message "=== Проверка состояния обновлений ==="

#endregion
#region check inventory
WriteToLog -Severity "INFORMATION" -Message "=== Проверка состояния инвентаризаций ==="

#endregion

#region NeedInstall
IF ($Global:ScriptParam.ClientHealth -eq 0)
{
	WriteToLog -Severity "WARNING" -Message "Клиент не установлен. Будет выполнена установка."
	Install
	Finish
}
#IF ($global:SCCMClientParam.Universal)
#{
#      WriteToLog -Severity "WARNING" -Message "Клиент определен как универсальный. Будет выполнена переустановка."
#      Install
#      Finish
#}
#endregion
IF ($Global:ScriptParam.AllCheck -eq 'OK')
{
	WriteToLog -Severity "INFORMATION" -Message "Все проверки пройдены. Клиент работоспособен."
	WriteBD -QuitCode 0
	$Global:ScriptParam.ClientHealth = 2
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallDate -Value "" -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallCount -Value 0 -ErrorAction Stop
	
}
ELSE
{
	WriteToLog -Severity "WARNING" -Message "Обнаружены ошибки в работе клиента."
	WriteBD -QuitCode 1
	$Global:ScriptParam.ClientHealth = 1
}
Finish