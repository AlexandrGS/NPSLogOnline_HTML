#https://github.com/AlexandrGS/NPSLogOnline_HTML
#Анализируя логи Windows NPS-Radius сервера показывает информацию о активных VPN-сессиях. Логи в DTS-формате. Все пользователи появляются примерно через 5 минут работы скрипта
#Такое время потому что Radius-клиент посялает пакеты о состоянии соединения Radius-серверу примерно каждые 5 минут. Так у моего сервера.
#
Param(
    #Папки с активными логами NPS-Radius сервера. Должны быть разделены символом из $DelimiterOfFilesList
    #$LogFiles = '"\\192.168.10.10\c$\Windows\System32\LogFiles\IN2104.log","\\192.168.10.11\c$\Windows\System32\LogFiles\IN2104.log"',
    $LogPath = '"\\192.168.10.10\c$\Windows\System32\LogFiles","\\192.168.10.11\c$\Windows\System32\LogFiles"',
    #ОТКЛЮЧЕНО. Сколько строк лога надо прочесть при старте скрипта. Когда сделал обработку нескольких лог файлов почему то перестало работать
    #$CountFirstReadLines = 10,
    #HTML-файл куда будут записываться результаты
    $OutHTMLFile = "D:\Programs\NPSLogOnline_HTML\index.html",
    #Файл куда пишется вывод
    $OutLogFile = ".\NPSLogOnline_HTML.log",
    #Файл с CSS-стилями для оформления веб-страницы
    $CssStyleFile = "D:\Programs\NPSLogOnline_HTML\NPSLogOnline_HTML_style.css",
    #Файл де постійно сохраняються ІР адреси і їх геопозиція
    $IPGeoLoc_FileName = "C:\inetpub\VPNstat\powershell\IPAndGeoLocation.csv",
    #Период обновления создаваемой HTML страницы в секундах. В HTML-коде страницы. Для браузера
    $RefreshHTMLPageSec = 30,
    #По какому полю упорядочивает выводимые результаты. Допустимые поля берутся из объекта $OneVPNSessionDesc
    $SortVPNSessionsByField = "UserName"
)

$Proxy = "http://proxy.dp.uz.gov.ua:3128" #Проксі-сервер для доступа в інет

#Символы, которые в строке разделяют названия файлов
$DelimiterOfFilesList = ",;"

#
$MaxOnlineSec  = 6*60
$MaxTimeOutSec = 2 * $MaxOnlineSec

$StatusOnline  = "Работает"
$StatusWarning = "Простой"
$StatusError   = "Тайм-Аут"

[array]$Script:OnlineVPNSessions = @{}

#Packet-Type
$AccessRequest = 1
$AccessAccept = 2
$AccessReject = 3
$AccountingRequest = 4
$AccountingResponse = 5
$AccessChallenge = 11
$StatusServer = 12
$StatusClient = 13
$DisconnectRequest = 40
$DisconnectACK = 41
$DisconnectNAK = 42
$ChangeOfAuthorizationRequest = 43
$ChangeOfAuthorizationACK = 44
$ChangeOgAuthorizationNAK = 45

#ACCT-Status-Type
$Start = 1
$Stop = 2
$InterimUpdate = 3
$AccountingOn = 7
$AccountingOff = 8

$Script:isDebugOn = $True

function PrintDebug($DebugMsg){
    if ($Script:isDebugOn){
        $CurrentDate = Get-Date -Format "dd:MM:yyyy HH:mm:ss"
        $Msg = $CurrentDate + " " + $DebugMsg
#        Write-Host $Msg
        $Msg | Out-File -FilePath $OutLogFile -Append -Force  #-Encoding utf8 
    }

}

#Возвращает целое число секунд от 01/01/1970 до текущей даты
function GetDateIntSecFrom1970(){
    [int64]$Result = ((Get-Date -UFormat %s).Split(".,"))[0]
    Return $Result
}

#Подсчитывает сколько в данном числе секунд часов минут секунд
#Получает количество секунд
#Возвращает строку вида 11:23:59 hh:mm:ss
function DurationSecToHourMinSec ([uint64]$DurationSec){
    $Result = ""
    $SecInMin = 60
    $SecInHour = 60 * $SecInMin

    if($DurationSec -lt 0){
        Write-Warning "  DurationSecToHourMinSec: Получено неверное число секунд: $DurationSec"
    } else {
        [int]$Hours   = [math]::Truncate( $DurationSec / $SecInHour )
        [int]$Minutes = [math]::Truncate( ($DurationSec % $SecInHour) / $SecInMin )
        [int]$Seconds = $DurationSec % $SecInMin
        $Result = [string]$Hours+ ":" + [string]$Minutes + ":" + [string]$Seconds
    }

    Return $Result    
}


#Удалить из массива с VPN сессиями все завершенные сессии
function PackOnlineVPNSesions(){
    $Script:OnlineVPNSessions = $Script:OnlineVPNSessions  | Where-Object {($_.SessionID -ne "") -and ($_.SessionID -ne $Null ) }
}

#Получает строку с датой временем вида MM/DD/YYYY hh:mm:ss.___ Например 02/01/2020 14:32:05.812
#Возвращаетколичество секунд от 01.01.1970 до этой даты
function ToSecFrom1970([datetime]$DateTime){
    $Result = Get-Date -UFormat %s -Year $DateTime.Year -Month $DateTime.Month -Day $DateTime.Day -Hour $DateTime.Hour -Minute $DateTime.Minute -Second $DateTime.Second -Millisecond $DateTime.Millisecond
    Return $Result
}

function ExportObjectToCSV ($Object,$CSVFileName) {
    $Object | Export-CSV -Path $CSVFileName -Delimiter ';' -Encoding UTF8 -NoTypeInformation #-Append
}

#Импортирует весь CSV-файл и возвращает объект с его содержимым
function ImportObjectFromCSV($CSVFileName) {
    $Object = Import-CSV -Path $CSVFileName -Delimiter ';' -Encoding UTF8
    Return $Object
}

#----- Геолокация по IP адресу -----

#Флаг включения геолокации
[bool]$Global:isIPGeoLocationEnable = $True
#Флаг первой проверки геолокации. Во время первой проверки проверяется связь с сайтом, выдающим геолокацию
[bool]$Script:isFirstIPGeoLocationTest = $True
#Содержит результаты предыдущих запросов IP локации в виде @{IP=""; Country=""; City = ""; Latitude = ""; Longitude = ""; ASN = ""; Organization = ""; ISP = ""}
[array]$Global:IPAndGeoLocation = @{}

$Script:CountHitToIPAndGeoArray = 0
$Script:CountResolvingIPGeo = 0

#Получает один элемент массива $Global:IPAndGeoLocation, возвращает строку с геопозицией в человеческом виде
function FormingIPGeoString($IPGeoLocationItem){
    $Result = $IPGeoLocationItem.Country + ", " + 
              $IPGeoLocationItem.Region + ", " + 
              $IPGeoLocationItem.City          #+  ", "
#              "latitude:" + $IPGeoLocationItem.Latitude + ", " + 
#              "longitude:" + $IPGeoLocationItem.Longitude + ", " + 
#              "asn:" + $IPGeoLocationItem.ASN + ", " + 
#              "org:" + $IPGeoLocationItem.Organization + ", " + 
#              "isp:" + $IPGeoLocationItem.ISP
    $OOO1 = $IPGeoLocationItem.Organization
    if( ($OOO1 -ne "") -or ($OOO1 -ne $null) ){
        $Result += ", org:" + $OOO1
    }
    $OOO2 = $IPGeoLocationItem.ISP
    if( ($OOO2 -ne "") -or ($OOO2 -ne $null) ){
        if($OOO1 -ne $OOO2){
            $Result += ", isp:" + $OOO2
        }
    }
    Return $Result
}

#Це перший визов функції після старту всього скрипта
[bool]$Script:isFirstStartOfScript = $True

$Script:CCC = 0

#Слідкуе щоб массив Global:IPAndGeoLocation був заповнен,сохранявся на діск
function PrepareIPAndGeoLocationArray(){
    
    if(-not $Global:isIPGeoLocationEnable){
        return
    }

    if( $Script:isFirstStartOfScript ){
        #Перший визов функції після запуску скрипта
        $Script:isFirstStartOfScript = $false
        Clear-Variable -Name IPAndGeoLocation
        $Global:IPAndGeoLocation = ImportObjectFromCSV $IPGeoLoc_FileName
        $Script:CCC = $Script:CountResolvingIPGeo
    }else{
        #Не перший визов функції після запуску скрипта
        if(($Script:CountResolvingIPGeo - $Script:CCC) -gt 1) {
            ExportObjectToCSV $Global:IPAndGeoLocation $IPGeoLoc_FileName
            $Script:CCC = $Script:CountResolvingIPGeo
        }
    }
}

#Получает IP адрес. Возвращает строку с географичесим положением country region city latitude longitude asn org isp
function GetIPGeoLocation([string]$IP){
    [string]$Result = ""
    
    if(($IP -eq "0.0.0.0") -or ($IP -eq "") -or ($IP -eq $null)){
        return ""
    }

    #При первом вызове проверяем есть ли доступ к сайту где проверяется локация по IP
    if(($Script:isFirstIPGeoLocationTest) -and ($Global:isIPGeoLocationEnable)){
        PrintDebug "Проверка связи с сервисом голокации http://ipwhois.app"
        $FirstTest = [xml](Invoke-RestMethod -method Get -Uri "http://ipwhois.app/xml/8.8.8.8" -Proxy $Proxy -ProxyUseDefaultCredentials) #| Out-Null
        if($FirstTest.query.success -eq 1){
            PrintDebug "Попытка проверить связь с сервисом геолокации удалась. Геолокация по IP будет включена. Бесплатно можно проверить до 10000 адресов за месяц"
        } else {
            PrintDebug "Попытка проверить связь с сервисом геолокации не удалась. Геолокация по IP будет отключена"
            $Global:isIPGeoLocationEnable = $False
        }
        $Script:isFirstIPGeoLocationTest = $False
    }

    PrepareIPAndGeoLocationArray

    #Ищем геолокацию IP адреса
    if($Global:isIPGeoLocationEnable){
        $isIPInArray = $False
        ForEach($I in $Global:IPAndGeoLocation){
            if($I.IP -eq $IP){
                $Script:CountHitToIPAndGeoArray++
                $Result = FormingIPGeoString $I
                $isIPInArray = $True
            }
        }
        if(-not $isIPInArray){
            $XMLWebRequest = [xml](Invoke-RestMethod -method Get -Uri "http://ipwhois.app/xml/$IP" -Proxy $Proxy -ProxyUseDefaultCredentials)
            if($XMLWebRequest.query.success -eq 1){
                $Script:CountResolvingIPGeo++
#                $Global:IPAndGeoLocation += @{IP=$IP; Country=$XMLWebRequest.query.country; Region = $XMLWebRequest.query.region; City = $XMLWebRequest.query.city; Latitude = $XMLWebRequest.query.latitude; Longitude = $XMLWebRequest.query.longitude; ASN = $XMLWebRequest.query.asn; Organization = $XMLWebRequest.query.org; ISP = $XMLWebRequest.query.isp}
                $IPAndGeo = New-Object -Type PSObject -Property([ordered]@{
                    IP      = [string]$IP;
                    Country = [string]$XMLWebRequest.query.country;
                    Region  = [string]$XMLWebRequest.query.region;
                    City    = [string]$XMLWebRequest.query.city;
                    Latitude = [string]$XMLWebRequest.query.latitude;
                    Longitude = [string]$XMLWebRequest.query.longitude;
                    ASN       = [string]$XMLWebRequest.query.asn;
                    Organization = [string]$XMLWebRequest.query.org;
                    ISP = [string]$XMLWebRequest.query.isp
                })
                $Global:IPAndGeoLocation += $IPAndGeo
                $Result = FormingIPGeoString $XMLWebRequest.query
            }
        }
    }
    Return $Result
}

#----- Конец функций геолокации по IP -----

#Печать результатов каждые $MinSecBetweenPrintResult сек, если сообщения в логе появляются реже, то с каждым сообщением в логе
[int64]$Script:LastPrintResultSecFrom1970 = GetDateIntSecFrom1970
function PrintOnlineVPNSessions(){
    [int]$MinSecBetweenPrintResult = 5
    [int64]$CurrentSecFrom1970 = GetDateIntSecFrom1970

    [string]$HTMLHeader = "<HEAD>
        <Title> Активные VPN сессии</Title>
        <meta http-equiv=""refresh"" content=""$RefreshHTMLPageSec"">
    </HEAD>"
#         <style>
#            table { 
#                width: 100%; /* Ширина таблицы */
#                border-spacing: 0; /* Расстояние между ячейками */
#            }
#            tr:nth-child(2n) {
#                background: #f0f0f0; /* Цвет фона */
#            } 
#            tr:nth-child(1) {
#                background: #666; /* Цвет фона */
#                color: #fff; /* Цвет текста */
#            } 
#        </style>   
    $CurrentDate = Get-Date -Format "dd MMMM yyyy HH:mm:ss"
    $PreHTMLContent = "<H4><Left>Активные VPN сессии на $CurrentDate</Left></H4>"
   
    $CountOfActiveVPNSessions = $Script:OnlineVPNSessions.Count
    $PostHTMLContent = "<H4>Всего $CountOfActiveVPNSessions сессии</H4>
    <Left>
    В столбце ""Статус"" всегда стоит слово ""$StatusOnline"", ""$StatusWarning"" или ""$StatusError"" и цифра в квадратных скобках.<br>
    Цифра означает сколько секунд назад в логах Radius-сервера было последнее появление этой сессии.<br>
    Слово ""$StatusOnline"" означает что это было меньше $MaxOnlineSec сек назад.<br>
    ""$StatusWarning"" что больше чем $MaxOnlineSec сек но меньше чем $MaxTimeOutSec сек назад,<br>
    ""$StatusError"" говорит что последнее появление в логах этой сессии было больше $MaxTimeOutSec сек назад и с этой сесией творится подозрительное<br>
    При проблемах с провайдером появляются пачки таких сессий <hr>
    При появлении-прекращении VPN сессии информация о ней обновляется примерно каждые $RefreshHTMLPageSec сек.<br>
    Инфо о существующей сессии обновляется примерно каждае 5.5 минут"

    if( $CurrentSecFrom1970 - $Script:LastPrintResultSecFrom1970 -ge $MinSecBetweenPrintResult ){
        $Script:LastPrintResultSecFrom1970 = $CurrentSecFrom1970
#        PackOnlineVPNSesions
#        $Script:OnlineVPNSessions  | Sort-Object -Property $SortVPNSessionsByField | Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP,TunnelClientIP,NASServerExternalIP,NASServerInternalIP,RadiusServer,TunnelType,InputOctets,OutputOctets,Status
#        Write-Host "Всего" $Script:OnlineVPNSessions.Count "сессий на " (Get-Date)
        
        PrintDebug "Сохраняю в файл $OutHTMLFile"
        $Script:OnlineVPNSessions  | Sort-Object -Property $SortVPNSessionsByField | 
            select @{expression={$_.UserName}; Label="Аккаунт"}, `
                @{expression={$_.Status}; Label="Статус"}, `
                @{expression={($_.Company)}; Label="Предприятие"}, `
                @{expression={$_.UserDevName}; Label="Имя устройства"}, `
                @{expression={$_.DurationHMS}; Label="Длит чч:мм:сс"}, `
                @{expression={$_.UserExternalIP}; Label="IP внешний"}, `
                @{expression={$_.TunnelClientIP}; Label="IP внутренний"}, `
                @{expression={$_.NASServerExternalIP}; Label="IP NAS внешний"}, `
                @{expression={$_.UserExternalIPGeolocation}; Label="Геолокация"}, `
                @{expression={$_.NASServerInternalIP}; Label="IP NAS внутренний"}, `
                @{expression={$_.RadiusServer}; Label="Radius сервер"}, `
                @{expression={$_.InputOctets}; Label="Входящих байт"}, `
                @{expression={$_.OutputOctets}; Label="Исходящих байт"} `
                |
            ConvertTo-Html -As Table -Head $HTMLHeader -PreContent $PreHTMLContent -PostContent $PostHTMLContent -CssUri $CssStyleFile | Out-File $OutHTMLFile 

        #$Script:OnlineVPNSessions | Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP
        #Write-Host "Всего" $Script:OnlineVPNSessions.Count "сессий"

        #Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP,SessionID
        #|  Select-Object UserName,UserDevName,DurationHMS,UserExternalIP,SessionID
        #Where-Object {($_.SessionID -ne "") -and ($_.SessionID -ne $Null ) } |
        #| Out-GridView -Title "Активные VPN пользователи"
    }
}

#Получает массив строк с именами папок где находятся лог-файлы. Возвращает массив строк с полными путями папка+логфайл в сиде c:\Logfiles\in2104.log
function FromFolderToFullPath([string[]]$Folders){
    [string[]]$FullPath = @()
    foreach($Folder in $Folders){
        $FullPath += $Folder + "\in" + ([string](Get-Date).Year).Remove(0,2) + ([string](Get-Date).Month).PadLeft(2,"0") + ".log"
    }
    $Msg = "Читаем логи из файлов:" + $FullPath
    PrintDebug $Msg
    return $FullPath
}


#Паралельное чтение из нескольких файлов.
#Взято из http://coderoad.ru
Workflow GetSeveralFilesContent
{
    Param([string[]] $Files)
    
    while($True){
        try{
            ForEach -parallel ($file in $Files) {
                Get-Content -Path $file -Tail 0 -Wait
            }
        }
        catch{
            "Error paralel reading"
        }
    }
}

#Обновляет поле Status в массиве с описанием каждой VPN-сессии
#Если последняя запись в логе для этой сессии меньше $MaxOnlineSec секунд, то сессия в состоянии $StatusOnline
#Если прошло секунд между $MaxOnlineSec и $MaxTimeOutSec, то стессия в состоянии $StatusWarning
#Если с последней записи в логе прошло больше $MaxTimeOutSec секунд, то сессия в состоянии $StatusError
function UpdateStatusForAllVPNSessions(){
    [int64]$CurrentSecFrom1970 = GetDateIntSecFrom1970
    ForEach($I in $Script:OnlineVPNSessions){
        [int64]$Sec = $CurrentSecFrom1970 - $I.LastActivitySecFrom1970
        if($Sec -ge $MaxTimeOutSec){
            $I.Status = $StatusError + " [" + $Sec + "]"
        }else{
            if($Sec -ge $MaxOnlineSec){
                $I.Status = $StatusWarning + " [" + $Sec + "]"
            }else{
                $I.Status = $StatusOnline + " [" + $Sec + "]"
            }
        }
    }
}

function DeleteSessionFromVPNSessionsArray($XMLOneLineLog){
    $isDeleted = $False
    ForEach($OneVPNSession in $Script:OnlineVPNSessions){
        if($OneVPNSession.SessionID -eq $XMLOneLineLog.Event."Acct-Session-Id"."#text"){
            $OneVPNSession.SessionID = ""
            $Msg = "Удаляю сессию " + $XMLOneLineLog.Event."Acct-Session-Id"."#text" + " пользователя " + $XMLOneLineLog.Event."User-Name"."#text"
            PrintDebug $Msg
            $isDeleted = $True
            Break
        }
    }
    if(-not $isDeleted){
        $Msg = "Cессия " + $XMLOneLineLog.Event."Acct-Session-Id"."#text" + " пользователя " + $XMLOneLineLog.Event."User-Name"."#text" + " не найдена для удаления."
        PrintDebug $Msg
    }
    PackOnlineVPNSesions #Почему-то при вызове отсюда в массиве остается одна пустая запись. Перенес в другое место
}

function UpdateVPNSessionsArray([xml]$XMLOneLine){
    $isVPNSessionInArray = $False
    $AcctSessionID = $XMLOneLine.Event."Acct-Session-Id"."#text"
    $UserName = ([string]$XMLOneLine.Event."User-Name"."#text").Split("\")[-1]
    if(($AcctSessionID -eq "") -or ($AcctSessionID -eq $Null)){
#        Write-Warning "В функцию UpdateVPNSessionsArray получен пакет с пустым атрибутом Acct-Session-Id " 
#        Write-Host $XMLOneLine
#        Write-Host $OLL
        return
    }
    ForEach( $I in $Script:OnlineVPNSessions){
        if( $I.SessionID -eq $AcctSessionID ){
            PrintDebug "Обновляю сессию  $AcctSessionID  пользователя $UserName"
            $I.DurationSec  = [uint64]$XMLOneLine.Event."Acct-Session-Time"."#text"
            $I.DurationHMS = DurationSecToHourMinSec $I.DurationSec
            $I.RadiusServer        = [string]$XMLOneLine.Event."Computer-Name"."#text"
            if( ($I.TunnelClientIP -eq "") -or ($I.TunnelClientIP -eq $Null) ){
                $I.TunnelClientIP = [string]$XMLOneLine.Event."Framed-IP-Address"."#text";
            }
            $I.InputOctets  = [uint64]$XMLOneLine.Event."Acct-Input-Octets"."#text"
            $I.InputPackets = [uint64]$XMLOneLine.Event."Acct-Input-Packets"."#text"
            $I.OutputOctets = [uint64]$XMLOneLine.Event."Acct-Output-Octets"."#text"
            $I.OutputPackets= [uint64]$XMLOneLine.Event."Acct-Output-Packets"."#text"
            $I.LastDateTimeActivity=[string]$XMLOneLine.Event."Timestamp"."#text"
            $I.LastActivitySecFrom1970 = GetDateIntSecFrom1970
#            $I.Company = (Get-ADUser -Identity $I.UserName -Properties Company).Company #???Надо ли при каждой записи в лог обновлять компанию акаунта или достаточно один раз при создании сессии
            $I.Status = $StatusOnline + "[0]";

            $isVPNSessionInArray = $True
        }
    }
    if( -not $isVPNSessionInArray){
        PrintDebug "Нашел сессию $AcctSessionID пользователя $UserName"
        $OneVPNSessionDesc = New-Object -Type PSObject -Property @{
            UserName            = $UserName;             #Имя пользователя этой сессии
            UserDevName         = [string]$XMLOneLine.Event."Tunnel-Client-Auth-ID"."#text"; #Имя устройства VPN-клиента
            DurationSec         = [uint64]$XMLOneLine.Event."Acct-Session-Time"."#text";   #Длительность сессии в секундах. Подсчитывается NAS-сервером
            DurationHMS         = ""; #Длительность сессии в часы:минуты:секунды
            RadiusServer        = [string]$XMLOneLine.Event."Computer-Name"."#text";         #Имя Радиус-сервера, который первым принял эту сессию
            TunnelType          = [string]$XMLOneLine.Event."Tunnel-Assignment-ID"."#text";  #Тип туннеля
            UserExternalIP      = [string]$XMLOneLine.Event."Tunnel-Client-Endpt"."#text";   #Наружный IP адрес VPN-клиента
            NASServerExternalIP = [string]$XMLOneLine.Event."Tunnel-Server-Endpt"."#text";   #Наружный IP адрес NAS сервера-Radius клиента
            UserExternalIPGeolocation = [string]"";                #Географическое расположение IP адреса клиента из поля UserExternalIP
            TunnelClientIP      = [string]$XMLOneLine.Event."Framed-IP-Address"."#text";    #IP адрес VPN-клиента внутри VPN-туннеля
            NASServerInternalIP = [string]$XMLOneLine.Event."NAS-IP-Address"."#text";       #IP адрес NAS сервера-Radius клиента внутри VPN-туннеля
            InputOctets         = [uint64]$XMLOneLine.Event."Acct-Input-Octets"."#text";     #Число входящих байт
            InputPackets        = [uint64]$XMLOneLine.Event."Acct-Input-Packets"."#text";    #Число входящих пакетов
            OutputOctets        = [uint64]$XMLOneLine.Event."Acct-Output-Octets"."#text";    #Число исходящих байт
            OutputPackets       = [uint64]$XMLOneLine.Event."Acct-Output-Packets"."#text";   #Число исходящих пакетов
            SessionID           = $AcctSessionID;      #Уникальный номер VPN сессии. Соответствует полю Acct-Session-Id.
                                                       #Если пробел или $Null, то этот объект будет пропускаться при обработке
            LastDateTimeActivity    =[string]$XMLOneLine.Event."Timestamp"."#text"; #Время последней записи в логах для этой сессии.
            LastActivitySecFrom1970 = GetDateIntSecFrom1970 ; #Время последней записи в логах для этой сессии. В секундах с 01.01.1970
            Company = "";
            Status = $StatusOnline + "[0]";
        }
        $OneVPNSessionDesc.Company = (Get-ADUser -Identity $OneVPNSessionDesc.UserName -Properties Company).Company
        $OneVPNSessionDesc.DurationHMS = DurationSecToHourMinSec $OneVPNSessionDesc.DurationSec
        $OneVPNSessionDesc.UserExternalIPGeolocation = GetIPGeoLocation $OneVPNSessionDesc.UserExternalIP
        $Script:OnlineVPNSessions += $OneVPNSessionDesc
    }
}

function HandleOneLineLog([string]$OneLineLog){
    $XMLOneLineLog = [xml]$OneLineLog
    #Если пакет завершения сессии. то удалить запись об этой сессии
    if(($XMLOneLineLog.Event."Packet-Type"."#text" -eq $AccountingRequest) -and ($XMLOneLineLog.Event."Acct-Status-Type"."#text" -eq $Stop) ) {
        DeleteSessionFromVPNSessionsArray $XMLOneLineLog
    }else{
    #Иначе обновить информацию о сессии
        UpdateVPNSessionsArray $XMLOneLineLog
    }
    UpdateStatusForAllVPNSessions
    PrintOnlineVPNSessions
}

PrintDebug "Анализ DTS-логов NPS-Radius сервера Windows. Показывает онлайн пользователей. Версия от 04.11.2020"
PrintDebug "https://github.com/AlexandrGS/NPSLogOnline_HTML"
PrintDebug "Всех пользователей покажет примерно через 5-6 минут работы скрипта"
#Get-Content $LogFiles -Wait -Tail $CountFirstReadLines | ForEach-Object { HandleOneLineLog  $_ }

#GetSeveralFilesContent ($LogFiles.Split($DelimiterOfFilesList)) | ForEach-Object { HandleOneLineLog  $_ }
GetSeveralFilesContent (FromFolderToFullPath $LogPath) | ForEach-Object { HandleOneLineLog  $_ }
PrintDebug "Завершение работы"
