# Разработчик:             Воюш Артем Алексеевич
#################################################################################
#                                    Параметры                                  #
#################################################################################
#Region Parameters
$Global:SystemInfo = New-Object -TypeName PSObject -Property $([ordered] @{
		CompName = $env:COMPUTERNAME; # Имя ПК
		Domain   = (Get-WmiObject -Query "Select * from Win32_ComputerSystem").domain;
		FQDN	 = "$env:COMPUTERNAME.$((Get-WmiObject -Query "Select * from Win32_ComputerSystem").domain)"
		UserName = (Get-WmiObject -Query "Select * from Win32_ComputerSystem").username;
		OS	     = ''; # Версия ОС
		OSLanguage = '';
		IPAddress = "0.0.0.0";
		Subnet   = "0.0.0.0";
		DC_Name  = 'No';
		Category = ''; # 
		AutoAdminLogon = 0;
		Firewall = $True;
	});
$Global:ScriptParam = New-Object -TypeName PSObject -Property $([ordered] @{
		Version  = '5.0.0.1'
		#Определяется во время работы скрипта
		FullName = $Global:MyInvocation.MyCommand.Path; #"C:\Scripts\SCCM\!Git_Repo\SCCM2012\SCCM2012.ps1"; #
		Folder   = $Global:MyInvocation.MyCommand.Path | Split-Path -Parent; #"C:\Scripts\SCCM\!Git_Repo\SCCM2012"; #
		Name	 = $Global:MyInvocation.MyCommand.Path | Split-Path -Leaf; #"SCCM2012.ps1"; #$Global:MyInvocation.MyCommand.Path | Split-Path -Leaf;
		#
		TaskName = "SCCM_Check_Update"; # Имя задачи в планировщике на запуск скрипта
		LocalPath = $env:Windir + "\CCM_Install_Script"; # Локальная папка со скриптом
		FirstWriteToLog = $true; # Первая запись в лог в WriteToLog
		Log	     = $env:Windir + "\TEMP\$($Global:SystemInfo.CompName)_ConfigMgrDiag.Log"; # Лог выполнения скрипта
		ScriptCopy = $False;
		NeedScan = $true;
		LockedScreen = $false;
		Location = 0;
		LocalMP  = "";
		ClientHealth = 0; # 0 - Клиент отсутствует, 1 - проблемы с клиентом, 2 - все работает
	})
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
#IF (!(Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue)) { New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null }
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
		$LogText += "<" + $(Get-Date -Format "G") + "> BEGIN SCCM Update Check Script (Version $($Global:ScriptParam.Version))"
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
		$LogText += "<" + $(Get-Date -Format "G") + "> END SCCM Update Check Script (Version $($Global:ScriptParam.Version))"
		$LogText += "============================================================================================================================="
	}
	IF ($LogText.Length -gt 0)
	{
		$LogText | Out-File -FilePath $($Global:ScriptParam.Log) -Append -Force -Encoding default
	}
	IF ($Severity -like "FAILURE") { Finish }
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
FUNCTION Finish #
{
	
	WriteToLog -Severity "INFORMATION" -Message "=== END ==="
	IF ($Global:SCCMClientParam.LocalMP -ne '') { WriteBD -QuitCode 50 }
	WriteToLog -Severity "END"
	EXIT
}
FUNCTION WriteBD #
{
	PARAM (
		[Parameter(ParameterSetName = 'QuitCode', Mandatory = $false)]
		[string]$QuitCode = ''
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "WriteBD Error: HTTPRequest= $($Error[0].Exception.Message) URL=$URLBD"
		CONTINUE
	}
	IF ($Global:ScriptParam.Location -eq 102)
	{
		$ASP_Url = "https://Management_Point_1.internet_domain.ru"
		$cert = (Get-ChildItem -Path cert:\LocalMachine\My\ | Where-Object{ $_.Subject -Like "*CN=$env:COMPUTERNAME*" })[-1]
		IF ([string]::IsNullOrEmpty($cert))
		{
			WriteToLog -Severity "WARNING" -Message "Не удалось получить PKI сертификат. Запись в БД невозможна"
			RETURN
		}
	}
	ELSE
	{
		$ASP_Url = "http://$($Global:ScriptParam.LocalMP)"
	}
	$URLBD = "$ASP_Url/$AppPool_2/ClientCheck2012.asp?request=writelog&Subnet=$($Global:SystemInfo.Subnet)&IP=$($Global:SystemInfo.IPAddress)&CompName=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)&ScriptVersion=$($Global:ScriptParam.Version)&DC_Name=$($Global:SystemInfo.DC_Name)&QuitCode=$QuitCode"
	WriteToLog -Severity "INFORMATION" -Message "QuitCode: $QuitCode"
	IF ($Global:ScriptParam.Location -eq 102)
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
	PARAM (
		[Parameter(Mandatory = $true)]
		[ValidateSet("DP", "updatecheck", "badupdates", "exceptions", "listupdates")]
		[string]$RequestType
	)
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "LocalSiteServer Error: HTTPRequest= $($Error[0].Exception.Message) URL=$URL Result=$Result"
		CONTINUE
	}
	
	FOREACH ($ASP_Url IN $Global:ASP_Urls)
	{
		IF ($Global:ScriptParam.Location -eq 102)
		{
			$ASP_Url = "https://Management_Point_1.internet_domain.ru"
		}
		ELSE
		{
			$ASP_Url = "http://$($Global:ScriptParam.LocalMP)"
		}
		SWITCH ($RequestType)
		{
			"DP"{
				$URL = "$ASP_Url/$AppPool_1/mcs_slp.asp?request=dp&ip=$($Global:SystemInfo.Subnet)&ir=$($Global:SystemInfo.IPAddress)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос обслуживающих DP: $URL"
			}
			"updatecheck"{
				$URL = "$ASP_Url/$AppPool_1/updatecheck.asp?request=getcount&Compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Проверка на ПК долгов по обновлениям: $URL"
			}
			"badupdates"{
				$URL = "$ASP_Url/$AppPool_1/updatecheck.asp?request=badupdates&Compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Проверка ПК в списке на блокировку: $URL"
			}
			"exceptions"{
				$URL = "$ASP_Url/$AppPool_1/updatecheck.asp?request=exceptions&Compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Проверка ПК в списке исключений: $URL"
			}
			"listupdates"{
				$URL = "$ASP_Url/$AppPool_1/updatecheck.asp?request=listupdates&Compname=$($Global:SystemInfo.CompName).$($Global:SystemInfo.Domain)"
				WriteToLog -Severity "INFORMATION" -Message "HTTP: Запрос KB из писка долгов: $URL"
			}
		} #end switch url
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
	} #end foreach $ASP_Url
	
	# Проверка корректности ответа на запрос
	IF ([string]::IsNullOrWhiteSpace($HTTPResult) -or $HTTPResult -match "Error" -or $HTTPResult -match "not found" -or $HTTPResult -match "No Group Boundary")
	{
		WriteToLog -Severity "WARNING" -Message "HTTP: Получен некорректный ответ на HTTP-запрос: $HTTPResult"
		CreateScheduler
		Finish
	}
	# Обработка ответа на запрос
	RETURN $HTTPResult.trim()
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
		WriteBD -QuitCode 85
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
				Invoke-Expression -Command "robocopy $($Global:ScriptParam.Folder) $($Global:ScriptParam.LocalPath) LockedScreen.html"
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
				Copy-Item -path "$($Global:ScriptParam.Folder)\LockedScreen.html" -destination "$($Global:ScriptParam.LocalPath)" -ErrorAction Stop -Force
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
		$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy RemoteSigned -WindowStyle Hidden -File $($Global:ScriptParam.LocalPath)\$($Global:ScriptParam.Name)"
		TRY
		{
			Set-ScheduledTask $Global:ScriptParam.TaskName -Action $Action
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
		$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy RemoteSigned -WindowStyle Hidden -File $($Global:ScriptParam.LocalPath)\$($Global:ScriptParam.Name)"
		Register-ScheduledTask -RunLevel Highest -TaskName $($Global:ScriptParam.TaskName) -Action $Action -User SYSTEM -ErrorAction Stop
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
FUNCTION SearchKB ($KB)
{
	$KBInstalled = $false
	$SearchKB = Get-WmiObject -Namespace Root\CCM\clientsdk -Class CCM_SoftwareUpdate -ErrorAction Stop | Where-Object { $_.ArticleID -eq $KB }
	IF (![string]::IsNullOrEmpty($SearchKB))
	{
		WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: KB $KB еще не установлена, в WMI:CCM_SoftwareUpdate - EvaluationState: $($SearchKB.EvaluationState)"
		$KBInProgress = $true
	}
	IF (!$KBInProgress)
	{
		#1
		$HotFix = Get-HotFix | Where-Object { $_.HotFixID -match $KB }
		IF (![string]::IsNullOrEmpty($HotFix))
		{
			WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: KB $KB установлена в разделе HotFix"
			$KBInstalled = $true
		}
		#2
		IF (!$KBInstalled)
		{
			$RegKeys = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
				"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
			FOREACH ($RegKey IN $RegKeys)
			{
				IF ($(Get-ItemProperty -Path $RegKey | Where-Object { $_.DisplayName -match $KB }))
				{
					WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: KB $KB установлена в разделе \Microsoft\Windows\CurrentVersion\Uninstall"
					$KBInstalled = $true
					BREAK
				}
			}
		}
		#3
		IF (!$KBInstalled)
		{
			$RegKeys = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates\*",
				"HKLM:\SOFTWARE\Microsoft\Updates\*")
			FOREACH ($RegKey IN $RegKeys)
			{
				$SubKeys = (Get-Item -Path $RegKey).name
				FOREACH ($item IN $SubKeys)
				{
					$item = $item.Split("\", 2)[1]
					$SubSubKeys = (Get-Item -Path "HKLM:\$item\*" | Where-Object { $_.Name -match $KB }).Name
					FOREACH ($subitem IN $SubSubKeys)
					{
						$subitem = $subitem.Split("\", 2)[1]
						IF ((Get-ItemProperty -Path "HKLM:\$subitem").ThisVersionInstalled -eq "Y")
						{
							WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: KB $KB установлена в разделе \Microsoft\Updates"
							$KBInstalled = $true
							BREAK
						}
					}
				}
			}
		}
		#4
		IF (!$KBInstalled)
		{
			$RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\*"
			IF ($(Get-ItemProperty -Path $RegKey | Where-Object {
						$_.InstallClient -match "WindowsUpdateAgent" -and
						$_.InstallName -match $KB
					}))
			{
				WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: KB $KB установлена в разделе Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
				$KBInstalled = $true
				BREAK
			}
		}
		IF (!$KBInstalled)
		{
			WriteToLog -Severity "WARNING" -Message "UpdateCheck: KB $KB не установлена."
		}
	}
	RETURN $KBInstalled
}
FUNCTION RestartUpdatesScan
{
	$ScanRestart = $False
	RunCCMAction -ActionID '{00000000-0000-0000-0000-000000000113}'
	$LastUpdateScan = ""
	$LastUpdateScan = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name LastUpdateScan -ErrorAction Stop).LastUpdateScan
	IF ((New-TimeSpan -Start $LastUpdateScan -End (get-date -Format D)).days -gt 1 -or [string]::IsNullOrWhiteSpace($LastUpdateScan))
	{
		WriteToLog -Severity "INFORMATION" -Message "UpdateCheck : Run Updates Source Scan"
		WriteBD -QuitCode 83
		Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name LastUpdateScan -Value $(Get-Date -Format D) -ErrorAction Stop
	}
	ELSE
	{ WriteToLog -Severity "INFORMATION" -Message "UpdateCheck : Updates Source Scan сегодня уже запускался." }
}
FUNCTION LockedFirewall
{
	TRAP # Обработчик ошибок
	{
		WriteToLog -Severity "WARNING" -Message "Firewall: $($Error[0].Exception.Message)"
		CONTINUE
	}
	$Global:ScriptParam.LockedScreen = $true
	CreateLockedScreen
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Locked -Value 1 -ErrorAction Stop
	#Создание правила для selfservice
	IF ($Global:ScriptParam.Location -eq 100) { New-NetFirewallRule -DisplayName Rule_for_selfservice -Direction OutBound -Action Allow -RemoteAddress *.*.*.* -ErrorAction Stop }
	#Создание правила для PING
	New-NetFirewallRule -DisplayName Rule_for_ping -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -ErrorAction Stop
	#Создание правила для RDP
	New-NetFirewallRule -DisplayName Rule_for_RDP -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389
	#Создание правила для SCCM_ClientCenter
	New-NetFirewallRule -DisplayName Rule_for_SCCM_ClientCenter -Direction Inbound -Action Allow -Protocol TCP -LocalPort @(2701, 2702, 135)
	#Создание правил для Citrix
	IF ($Global:ScriptParam.Location -eq 100)
	{
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress "*.*.*.*-*.*.*.*" -Protocol TCP -LocalPort 80 -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol TCP -LocalPort 80 -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress "*.*.*.*-*.*.*.*" -Protocol TCP -LocalPort 80 -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol TCP -LocalPort 80 -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol TCP -LocalPort @(9998, 9999) -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol TCP -LocalPort @(9998, 9999) -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol UDP -LocalPort @(9998, 9999) -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol UDP -LocalPort @(9998, 9999) -ErrorAction Stop
	}
	ELSE
	{
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress "*.*.*.*-*.*.*.*" -Protocol TCP -LocalPort 80 -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress "*.*.*.*-*.*.*.*" -Protocol TCP -LocalPort 80 -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol TCP -LocalPort @(9998, 9999) -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol TCP -LocalPort @(9998, 9999) -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction Inbound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol UDP -LocalPort @(9998, 9999) -ErrorAction Stop
		New-NetFirewallRule -DisplayName Rule_for_CitrixDDC -Direction OutBound -Action Allow -RemoteAddress @("*.*.*.*", "*.*.*.*") -Protocol UDP -LocalPort @(9998, 9999) -ErrorAction Stop
	}
	#Создание правил для АВПО
	New-NetFirewallRule -DisplayName Rule_for_AVPO -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9998, 9999 -ErrorAction Stop
	New-NetFirewallRule -DisplayName Rule_for_AVPO -Direction OutBound -Action Allow -Protocol TCP -LocalPort 9998, 9999 -ErrorAction Stop
	New-NetFirewallRule -DisplayName Rule_for_AVPO -Direction Inbound -Action Allow -Protocol UDP -LocalPort 9999 -ErrorAction Stop
	New-NetFirewallRule -DisplayName Rule_for_AVPO -Direction OutBound -Action Allow -Protocol UDP -LocalPort 9999 -ErrorAction Stop
	#Создание правила для MP
	IF ($Global:ScriptParam.Location -eq 100)
	{
		New-NetFirewallRule -DisplayName Rule_for_MP -Direction OutBound -Action Allow -RemoteAddress "*.*.*.0/24"
	}
	ELSE
	{
		New-NetFirewallRule -DisplayName Rule_for_MP -Direction OutBound -Action Allow -RemoteAddress "*.*.*.0/24"
		New-NetFirewallRule -DisplayName Rule_for_MP -Direction OutBound -Action Allow -RemoteAddress "*.*.*.0/24"
		New-NetFirewallRule -DisplayName Rule_for_MP -Direction OutBound -Action Allow -RemoteAddress "*.*.*.0/24"
		New-NetFirewallRule -DisplayName Rule_for_MP -Direction OutBound -Action Allow -RemoteAddress "*.*.*.0/24"
	}
	#Создание правил для DP
	$DPList = LocalSiteServer -RequestType DP
	$DPs = @($DPList.Split(' ').trim())
	FOREACH ($DP IN $DPs)
	{
		$IPAddress = (Test-Connection -ComputerName $DP -Count 1).IPV4Address.IPAddressToString
		New-NetFirewallRule -DisplayName Rule_for_DP -Direction OutBound -Action Allow -RemoteAddress $IPAddress
	}
	#Создание правила для CcmExec
	New-NetFirewallRule -DisplayName Rule_for_CcmExec -Direction OutBound -Action Allow -Program C:\Windows\CCM\CcmExec.exe
	#Создание правила для SCClient
	New-NetFirewallRule -DisplayName Rule_for_SCClient -Direction OutBound -Action Allow -Program C:\Windows\CCM\SCClient.exe
	#Создание правила для DC
	IF ($Global:ScriptParam.Location -eq 100)
	{
		$IPAddress = (Test-Connection -ComputerName $Global:SystemInfo.DC_Name -Count 1).IPV4Address.IPAddressToString
		New-NetFirewallRule -DisplayName Rule_for_DС -Direction OutBound -Action Allow -RemoteAddress $IPAddress
		$DC_Name_OMEGA = $((nltest /dsgetdc:omega.ru | Where-Object { $_ -match '\\\\([a-zA-Z0-9]+)' }).Split('\')[2])
		$IPAddress = (Test-Connection -ComputerName $DC_Name_OMEGA -Count 1).IPV4Address.IPAddressToString
		New-NetFirewallRule -DisplayName Rule_for_DС -Direction OutBound -Action Allow -RemoteAddress $IPAddress
	}
	ELSE
	{
		$IPAddress = (Test-Connection -ComputerName $Global:SystemInfo.DC_Name -Count 1).IPV4Address.IPAddressToString
		New-NetFirewallRule -DisplayName Rule_for_DС -Direction OutBound -Action Allow -RemoteAddress $IPAddress
		$DC_Name_SIGMA = $((nltest /dsgetdc:sigma.ru | Where-Object { $_ -match '\\\\([a-zA-Z0-9]+)' }).Split('\')[2])
		$IPAddress = (Test-Connection -ComputerName $DC_Name_SIGMA -Count 1).IPV4Address.IPAddressToString
		New-NetFirewallRule -DisplayName Rule_for_DС -Direction OutBound -Action Allow -RemoteAddress $IPAddress
	}
	#Блокировка всех соединений, кроме созданных правил
	Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
	WriteToLog -Severity "INFORMATION" -Message "Firewall: Блокировка включена"
	WriteBD -QuitCode 92
}
FUNCTION UnLockedFirewall
{
	$CCMLocked = 0
	$CCMLocked = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Locked -ErrorAction Stop).Locked
	IF ($CCMLocked -eq 1)
	{
		Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Rule_for_*" } | Remove-NetFirewallRule
		Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Allow -ErrorAction Stop
		WriteToLog -Severity "INFORMATION" -Message "Firewall: Разблокировка всех соединений"
		# Оповещение пользователя
		IF ($Global:SystemInfo.AutoAdminLogon -ne 1 -and $Global:SystemInfo.Category -eq "")
		{
			$cmd = [regex]"cmd.exe /c chcp 1251 & (echo Внимание!& echo Сетевые соединения разблокированы.& echo Функциональность ПК восстановлена.) | msg *"
			Invoke-WmiMethod -Class Win32_process -Name Create -ArgumentList $cmd
		}
		WriteBD -QuitCode 93
	}
	$Global:ScriptParam.LockedScreen = $false
	CreateLockedScreen
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Locked -Value 0 -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LockedScreen -Value "" -ErrorAction Stop
}
FUNCTION CreateLockedScreen
{
	IF ($Global:SystemInfo.AutoAdminLogon -eq 1 -and $Global:SystemInfo.Category -ne "")
	{
		$Global:ScriptParam.LockedScreen = $false
	}
	[string]$Account = (Get-LocalGroup -SID 'S-1-5-32-545').Name
	$ScheduledTask = Get-ScheduledTask -TaskName SCCM_Locked_Screen
	IF (![string]::IsNullOrEmpty($ScheduledTask))
	{
		IF ($Global:ScriptParam.LockedScreen)
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LockedScreen -Value "C:\Program Files\internet explorer\iexplore.exe -k C:\Windows\CCM_Install_Script\LockedScreen.html" -ErrorAction Stop
			$cmd = 'cmd.exe /c SchTasks /Change /RU ' + $Account + ' /TN SCCM_Locked_Screen /TR "\"C:\Program Files\internet explorer\iexplore.exe\" -k C:\Windows\CCM_Install_Script\LockedScreen.html"'
			Invoke-WmiMethod -Class Win32_process -Name Create -ArgumentList $cmd
			Start-ScheduledTask SCCM_Locked_Screen -ErrorAction Stop
		}
		ELSE
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LockedScreen -Value "" -ErrorAction Stop
			Disable-ScheduledTask SCCM_Locked_Screen
		}
	}
	ELSE
	{
		IF ($Global:ScriptParam.LockedScreen)
		{
			$Houre = Get-random (10 .. 17)
			$Minutes = Get-random (10 .. 59)
			[string]$Time = [string]$Houre + ":" + [string]$Minutes
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LockedScreen -Value "C:\Program Files\internet explorer\iexplore.exe -k C:\Windows\CCM_Install_Script\LockedScreen.html" -ErrorAction Stop
			$cmd = 'cmd.exe /c SchTasks /Create /RU ' + $Account + ' /SC ONCE /RL HIGHEST /TN SCCM_Locked_Screen /TR "\"C:\Program Files\internet explorer\iexplore.exe\" -k C:\Windows\CCM_Install_Script\LockedScreen.html" /ST ' + $Time
			Invoke-WmiMethod -Class Win32_process -Name Create -ArgumentList $cmd
			Start-ScheduledTask SCCM_Locked_Screen -ErrorAction Stop
		}
		ELSE
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LockedScreen -Value "" -ErrorAction Stop
		}
	}
}
FUNCTION ScreenInfo
{
	PARAM (
		[Parameter(Mandatory = $true)]
		[ValidateSet("update", "client", "clientbad", "win7block", "win7pre")]
		[string]$Type
	)
	IF ($Global:ScriptParam.Location -eq 100)
	{
		$Segment = "omega"
	}
	ELSE
	{
		$Segment = "sigma"
	}
	$link = ""
	$komment = ""
	$errortitle = "Функциональность ограничена"
	$errorimage = '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'
	$errortext1 = ""
	$errortext2 = [system.Text.Encoding]::UTF8.GetString("Outlook и АС на данном ПК не работают.<br/><br/>Сделайте обращение<br/> для восстановлеения работоспособности ПК.")
	$buttontext = "Сделайте обращение в СберДруг"
	$fGoTo = ""
	IF ($Segment -eq "omega")
	{
		$link = "https://support.ru"
	}
	ELSEIF ($Segment -eq "sigma")
	{
		$link = "https://support.ru"
	}
	SWITCH ($Type)
	{
		"update"{
			$komment = '%23udp В связи с отсутствием на моём компьютере актуальных обновлений безопасности операционной системы, заблокированы все сетевые соединения, прошу устранить проблему или переустановить ОС при невозможности исправить ошибку неустановленных обновлений.'
			$errortext1 = "В связи с отсутствием на Вашем компьютере актуальных <br/>обновлений безопасности, его функциональность ограничена."
		}
		"client"{
			IF ($Global:SystemInfo.OSLanguage -ne 1049)
			{
				$errortitle = "Attention!"
				$errortext1 = "There are problems with SCCM client on your PC."
				$errortext2 = 'It is necessary to install and configure the SCCM client properly.<br/><br/>Please create a ticket <br/>to restore the functionality of the PC.'
				$buttontext = "Create a ticket in the FRIEND system"
			}
			ELSE
			{
				$errortitle = "Внимание"
				$errortext1 = 'На Вашем ПК обнаружены проблемы <br/>с работоспособностью клиента SCCM.'
				$errortext2 = 'Необходима установка и настройка клиента SCCM.<br/><br/>Сделайте обращение <br/>для восстановления работоспособности ПК.'
			}
			$komment = '%23udp В связи с отсутствием/некорректной работой клиента SCCM, на моём компьютере не установлены актуальные обновлений безопасности операционной системы. Прошу выполнить установку/настройку клиента SCCM или переустановить ОС при возникновении ошибок.'
			$errorimage = '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'
		}
		"clientbad"{
			$komment = '%23udp В связи с отсутствием/некорректной работой клиента SCCM на моём компьютере, заблокированы все сетевые соединения. Прошу выполнить установку/настройку клиента SCCM или переустановить ОС при возникновении ошибок.'
			$errortext1 = 'В связи с отсутствием на Вашем компьютере клиента SCCM,<br/>его функциональность ограничена.'
		}
		"win7pre"{
			IF ($Global:SystemInfo.OSLanguage -ne 1049)
			{
				$errortitle = "Attention!"
				$errortext1 = 'Due to the discontinuation of support for Windows 7.<br/>You need to migrate your OS to Windows 10.'
				$errortext2 = 'Windows 7 PCs will be blocked.<br/><br/>Please create a ticket <br/>to restore the functionality of the PC.'
				$buttontext = "Create a ticket"
			}
			ELSE
			{
				$errortitle = "Внимание"
				$errortext1 = 'В связи с прекращением поддержки Windows 7.<br/>ПК с Windows 7 будут заблокированы.'
				$errortext2 = 'Необходима миграция ОС на Windows 10.<br/><br/>Сделайте обращение <br/>для переустановки ОС на Windows 10.'
			}
			$komment = '%23udp В связи с прекращением поддержки Windows 7, на моём компьютере не установлены актуальные обновлений безопасности операционной системы. Прошу выполнить переустановку/миграцию ОС на Windows 10.'
			$errorimage = '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'
		}
		"win7block"
		{
			$komment = '%23udp В связи с прекращением поддержки Windows 7, на моём компьютере не установлены актуальные обновлений безопасности операционной системы. Прошу выполнить переустановку/миграцию ОС на Windows 10.'
			$errortext1 = 'В связи с прекращением поддержки Windows 7.<br/>Необходима миграция ОС на Windows 10.'
		}
	}
	$fGoTo = $link + "/support/#/interaction/new?template=Универсальный%20шаблон, %22komment%22:%22" + $komment + "%22%7D"
	$LockedScreenHTA = Get-Content C:\Windows\CCM_Install_Script\LockedScreen.html
	$StartTeg = @(
		[regex]"<p id='txt0'>",
		[regex]"<p id='txt1'>",
		[regex]"<p id='txt2'>",
		[regex]"var link = '",
		[regex]"<img style='width: 200px;' src='data:image/png;base64,")
	$EndTeg = @(
		[regex]"</p>",
		[regex]"</p>",
		[regex]"</p>",
		[regex]"'//end",
		[regex]"'>")
	FOR ($i = 0; $i -le $LockedScreenHTA.count; $i++)
	{
		FOR ($j = 0; $j -le $StartTeg.count; $j++)
		{
			$StrLine = $LockedScreenHTA[$i]
			IF ($StrLine -match ([regex]::Escape($StartTeg[$j])) -and $StrLine -match ([regex]::Escape($EndTeg[$j])))
			{
				$strTeg = $StrLine.Substring($StrLine.IndexOf($StartTeg[$j]) + $StartTeg[$j].length, $StrLine.IndexOf($EndTeg[$j]) - ($StrLine.IndexOf($StartTeg[$j]) + $StartTeg[$j].length))
				SWITCH ($j)
				{
					0{
						$LockedScreenHTA[$i] = $StrLine.Replace($strTeg, $errortitle)
					}
					1{
						$LockedScreenHTA[$i] = $StrLine.Replace($strTeg, $errortext1)
					}
					2{
						$LockedScreenHTA[$i] = $StrLine.Replace($strTeg, $errortext2)
					}
					3{
						$LockedScreenHTA[$i] = $StrLine.Replace($strTeg, $fGoTo)
					}
					4{
						$LockedScreenHTA[$i] = $StrLine.Replace($strTeg, $errorimage)
					}
				}
			}
		}
	}
	$LockedScreenHTA | Out-File -FilePath C:\Windows\CCM_Install_Script\LockedScreen.html -Force -Encoding default
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
IF (Test-Path -Path HKLM:\SOFTWARE\SCCM)
{
	$Global:SystemInfo.IPAddress = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name IPAddress -ErrorAction Stop).IPAddress
	$Global:SystemInfo.Subnet = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Subnet -ErrorAction Stop).Subnet
	$Global:SystemInfo.OS = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name OS -ErrorAction Stop).OS
	$Global:SystemInfo.OSLanguage = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name OSLanguage -ErrorAction Stop).OSLanguage
	$Global:ScriptParam.Location = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Location -ErrorAction Stop).Location
	$Global:ScriptParam.LocalMP = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name LocalMP -ErrorAction Stop).LocalMP
	$Global:SystemInfo.DC_Name = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name DC_Name -ErrorAction Stop).DC_Name
	$Global:ScriptParam.ClientHealth = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name ClientHealth -ErrorAction Stop).ClientHealth
}
ELSE
{
	WriteToLog -Severity "WARNING" -Message "В реестре не обнаружены необходимые параметры"
	EXIT
}
# Проверяем запущены ли другие копии скрипта в данный момент.
ScrCopyPsocCheck
# Настройка параметров в зависимости от определенной локации.
#region Location Settings
SWITCH ($Global:ScriptParam.Location)
{
	100 {
		$Global:ASP_Urls = $Global:SlpUrl.Omega
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - Omega"
	}
	101 {
		$Global:ASP_Urls = $Global:SlpUrl.Sigma
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - Sigma"
	}
	102 {
		$Global:ASP_Urls = $Global:SlpUrl.Mobile
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - Mobile"
	}
	103 {
		$Global:ASP_Urls = $Global:SlpUrl.CIB
		WriteToLog -Severity "INFORMATION" -Message "Определена локация - CIB"
	}
	0{
		WriteToLog -Severity "WARNING" -Message "Не определена локация клиента"
	}
}
SWITCH ($Global:ScriptParam.Location)
{
	102{
		$AppPool_1 = "mcs_slp_cert"
		$AppPool_2 = "cs_script_log"
	}
	DEFAULT
	{
		$AppPool_1 = "mcs_slp"
		$AppPool_2 = "cs_script_log"
	}
}
#endregion
###########################################################
WriteToLog -Severity "INFORMATION" -Message "=== START ==="
WriteBD -QuitCode 49
#region Определение категории АРМ
#ЕСЛИ (Наличие службы Smart Queue System) ИЛИ (Автологон DefaultUserName = DEEP) - СУО
#ЕСЛИ (SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall СОДЕРЖИТ AddReality Player) И (AutoAdminLogon=1) - ЕИРС
$Global:SystemInfo.AutoAdminLogon = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction Stop).AutoAdminLogon
IF ($Global:SystemInfo.AutoAdminLogon -eq 1) { WriteToLog -Severity "INFORMATION" -Message "Обнаружен автологон" }
IF ($(Get-Service 'Smart Queue System' -ErrorAction SilentlyContinue) -or
	$((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName) -eq "deep")
{
	WriteToLog -Severity "INFORMATION" -Message "Определена категория"
	$global:SystemInfo.Category = "S"
}
ELSE
{
	IF ($Global:SystemInfo.AutoAdminLogon -eq 1)
	{
		$AddRealityPlayer = $false
		$RegKeys = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
		FOREACH ($RegKey IN $RegKeys)
		{
			IF ($(Get-ItemProperty -Path $RegKey | Where-Object { $_.DisplayName -match ('addreality player') }))
			{
				WriteToLog -Severity "INFORMATION" -Message "Определена категория"
				$global:SystemInfo.Category = "E"
				BREAK
			}
		}
	}
}
#endregion
#region Проверка ошибки класса WMI
TRY
{
	Get-NetFirewallProfile -All -ErrorAction Stop | Select-Object Name, Enabled
}
CATCH
{
	Set-Service winmgmt -StartupType Disabled
	stop-Service winmgmt -Force
	Set-Location $env:windir\system32\wbem
	Get-ChildItem *.dll | ForEach-Object { regsvr32 /s $_ }
	wmiprvse /regserver
	Set-Service winmgmt -StartupType Automatic
	Start-Service winmgmt
	Get-ChildItem *.mof, *.mfl | ForEach-Object { mofcomp $_ }
	Set-Location $env:windir\system32\wbem\AutoRecover
	Get-ChildItem *.mof, *.mfl | ForEach-Object { mofcomp $_ }
}
#endregion
#region Создание разрешающих правил Firewall
TRY
{
	Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
	WriteToLog -Severity "INFORMATION" -Message "Firewall: Firewall включен"
	Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Allow -ErrorAction Stop
	WriteToLog -Severity "INFORMATION" -Message "Firewall: Настроены разрешающие правила"
}
CATCH
{
	WriteToLog -Severity "WARNING" -Message "Firewall: Не удалось применить параметры Firewall"
	$Global:SystemInfo.Firewall = $False
	WriteBD -QuitCode 5
}
#endregion
WriteToLog -Severity "INFORMATION" -Message "=== Проверка задания планировщика ==="
CreateScheduler
#region Проверка класса QFE
WriteToLog -Severity "INFORMATION" -Message "=== Проверка класса QFE ==="
$QFE = Get-HotFix -ErrorAction Stop
IF ([string]$QFE -match 'No instance available' -or [string]$QFE -match 'Отсутствуют экземпляры' -or [string]::IsNullOrWhiteSpace($QFE))
{
	WriteToLog -Severity "WARNING" -Message "UpdateCheck: Обнаружены неисправности класса QuickFixEngineering"
	WriteBD -QuitCode 95
}
#endregion
#region Проверка обновлений
WriteToLog -Severity "INFORMATION" -Message "=== Проверка обновлений ==="
FOR ($n = 0; $n -le 23; $n++)
{
	$c = @(Get-WmiObject -Namespace Root\CCM\clientsdk -Class CCM_SoftwareUpdate -ErrorAction Stop | Where-Object { $_.EvaluationState -eq $n })
	$CountForQC = 0
	$StateForQC = $n
	$CountForQC = $c.count
	IF ($CountForQC -gt 0)
	{
		$Global:ScriptParam.NeedScan = $false
		WriteToLog -Severity "INFORMATION" -Message "CountForQC: $CountForQC"
		IF ($StateForQC -lt 10) { $StateForQC = "0$StateForQC" }
		IF ($CountForQC -lt 10) { $CountForQC = "0$CountForQC" }
		WriteBD -QuitCode "810$StateForQC" + "0$CountForQC"
		FOREACH ($el IN $c)
		{
			WriteToLog -Severity "INFORMATION" -Message "KB: " + $el.ArticleID
			WriteToLog -Severity "INFORMATION" -Message "Name: " + $el.Name
			WriteToLog -Severity "INFORMATION" -Message "EvaluationState: " + $el.EvaluationState
			WriteToLog -Severity "INFORMATION" -Message "Deadline: " + ([wmi]"").ConvertToDateTime($el.Deadline)
			WriteToLog -Severity "INFORMATION" -Message "OverrideServiceWindows: " + $el.OverrideServiceWindows
		}
	}
}
#endregion
#region Проверка долгов по обновлениям
WriteToLog -Severity "INFORMATION" -Message "=== Проверка долгов по обновлениям ==="
$UpdateCheckResult = LocalSiteServer -RequestType updatecheck
IF ($UpdateCheckResult -eq 0)
{
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckReportDate -Value "" -ErrorAction Stop
}
ELSE
{
	$UpdateList = LocalSiteServer -RequestType listupdates
	IF (!([string]::IsNullOrWhiteSpace($UpdateList)))
	{
		$arrUpdateList = @($UpdateList.split(" ").trim())
		$Installed = $true
		FOREACH ($KB IN $arrUpdateList)
		{
			IF (!(SearchKB($KB))) { $Installed = $false }
		}
		IF ($Installed)
		{
			$UpdateCheckResult = 0
			WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: Все необходимые обновления установлены"
			$CheckReportDate = ""
			$CheckReportDate = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckReportDate -ErrorAction Stop).CheckReportDate
			IF ([string]::IsNullOrEmpty($CheckReportDate))
			{
				Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckReportDate -Value $(Get-Date -Format D) -ErrorAction Stop
			}
			$CheckReportDate = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckReportDate -ErrorAction Stop).CheckReportDate
			IF ((New-TimeSpan -Start $CheckReportDate -End (get-date -Format D)).days -gt 1)
			{
				#Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckReportDate -Value "" -ErrorAction Stop
				WriteToLog -Severity "WARNING" -Message "UpdateCheck: На ПК более 1 дня не обновляется отчет. Будет выполнена переустановка"
				#WriteBD -QuitCode 97
				#RebuildWMI
				#Install
			}
			
		}
	}
	ELSE
	{
		$UpdateCheckResult = 0
	}
}
#endregion
#region Проверка необходимости блокировки
IF (($UpdateCheckResult -gt 0 -and [string]::IsNullOrWhiteSpace($UpdateCheckResult)) -or $Global:SystemInfo.OS -eq 7)
{
	IF ($UpdateCheckResult -gt 0 -and [string]::IsNullOrWhiteSpace($UpdateCheckResult))
	{
		WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: На ПК обнаружены 'долги' по обновлениям."
		WriteBD -QuitCode 90
		IF ($Global:ScriptParam.NeedScan) { RestartUpdatesScan }
	}
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckReportDate -Value "" -ErrorAction Stop
	$CheckUpdateDate = ""
	$CheckUpdateCount = 0
	$CheckUpdateDate = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateDate -ErrorAction Stop).CheckUpdateDate
	$CheckUpdateCount = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateCount -ErrorAction Stop).CheckUpdateCount
	IF ((New-TimeSpan -Start $CheckUpdateDate -End (get-date -Format D)).days -gt 0 -or [string]::IsNullOrEmpty($CheckUpdateDate))
	{
		Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateDate -Value $(get-date -Format D) -ErrorAction Stop
		Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateCount -Value $([int]$CheckUpdateCount + 1) -ErrorAction Stop
		WriteBD -QuitCode "90$([int]$CheckUpdateCount + 1)"
	}
	$CheckUpdateCount = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateCount -ErrorAction Stop).CheckUpdateCount
	$MaxCheckUpdateCount = 8 # По-умолчанию
	IF ([int]$CheckUpdateCount -gt $MaxCheckUpdateCount)
	{
		WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: Счетчик превышает, будет выполнена блокировка. CheckUpdateCount: $CheckUpdateCount MaxCheckUpdateCount: $MaxCheckUpdateCount"
		IF (LocalSiteServer -RequestType badupdates -eq 1 -or $Global:SystemInfo.OS -eq 7)
		{
			IF (LocalSiteServer("exceptions") -eq 1)
			{
				WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: ПК находится в исключениях, блокировка отменена."
				WriteBD -QuitCode 91
				UnLockedFirewall
			}
			ELSE
			{
				IF ($Global:SystemInfo.OS -eq 7)
				{
					WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: Обнаружена Windows 7. Будет выполнена блокировка."
					WriteBD -QuitCode 99
					ScreenInfo("win7block")
					LockedFirewall
				}
				ELSE
				{
					ScreenInfo("update")
					LockedFirewall
				}
			}
		}
		ELSE
		{
			UnLockedFirewall
		}
	}
	ELSE
	{
		IF ($Global:SystemInfo.OS -eq 7)
		{
			WriteToLog -Severity "INFORMATION" -Message "UpdateCheck: Обнаружена Windows 7. Будет выполнено оповещение."
			WriteBD -QuitCode 98
			ScreenInfo("win7pre")
			$Global:ScriptParam.LockedScreen = $true
			CreateLockedScreen
		}
	}
}
ELSEIF ($Global:ScriptParam.ClientHealth -ne 2)
{
	$MaxNeedInstallCount = 2
	$MaxNeedInstallCountToLock = 8
	$NeedInstallCount = 0
	$NeedInstallCount = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name NeedInstallCount -ErrorAction Stop).NeedInstallCount
	$CCMLocked = 0
	$CCMLocked = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name Locked -ErrorAction Stop).Locked
	IF ($CCMLocked -ne 1)
	{
		IF ([int]$NeedInstallCount -gt $MaxNeedInstallCount)
		{
			WriteBD -QuitCode 89
			WriteToLog -Severity "INFORMATION" -Message "InstallCheck: Счетчик превышает, будет выполнено оповещение. MaxNeedInstallCount: $MaxNeedInstallCount NeedInstallCount: $NeedInstallCount"
			IF (LocalSiteServer("exceptions") -eq 1)
			{
				WriteToLog "INFORMATION", "UpdateCheck: ПК находится в исключениях."
				WriteBD -QuitCode 91
				UnLockedFirewall
			}
			ELSE
			{
				IF ([int]$NeedInstallCount -gt $MaxNeedInstallCountToLock)
				{
					ScreenInfo("clientbad")
					$LockedScreen = $true
					CreateLockedScreen
					LockedFirewall
				}
				ELSE
				{
					ScreenInfo("client")
					$LockedScreen = $true
					CreateLockedScreen
				}
				
			}
		}
	}
}
ELSE
{
	$CheckUpdateCount = ""
	$CheckUpdateCount = (Get-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateCount -ErrorAction Stop).CheckUpdateCount
	IF ([string]::IsNullOrEmpty($CheckUpdateCount))
	{
		$CheckUpdateCount = 0
	}
	ELSEIF ($CheckUpdateCount -gt 0)
	{
		WriteBD -QuitCode 94
	}
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateDate -Value "" -ErrorAction Stop
	Set-ItemProperty -Path HKLM:\SOFTWARE\SCCM -Name CheckUpdateCount -Value 0 -ErrorAction Stop
	UnLockedFirewall
}
#endregion

Finish