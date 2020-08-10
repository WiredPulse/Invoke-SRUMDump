# Future project... system uptime... event ID 6013 in System.evtx

# https://github.com/libyal/esedb-kb/blob/master/documentation/System%20Resource%20Usage%20Monitor%20(SRUM).asciidoc

function wirelessAuth{
    # wlanautoconfig
    # Card information
    # 1 Get successful connection
    # 2 Use guid and get registry key
    Get-WinEvent -FilterHashtable @{logname = 'Microsoft-Windows-WLAN-AutoConfig/Operational';Id = '8001'} | 
        Select-Object timecreated, @{Label="Interface GUID";Expression={$_.properties.value[0]}}, @{Label="Network Adapter";Expression={$_.properties.value[1]}}, @{Label="SSID";Expression={$_.properties.value[4]}} , @{Label="WLAN Standard";Expression={$_.properties.value[6]}}, @{Label="Authentication";Expression={$_.properties.value[7]}}, @{Label="Encryption";Expression={$_.properties.value[8]}}, @{Label="Hidden";Expression={$_.properties.value[11]}}
}

# Check this first
Write-Verbose -Message "Shutting down database $Path due to normal close operation."
[Microsoft.Isam.Esent.Interop.Api]::JetCloseDatabase($Session, $DatabaseId, [Microsoft.Isam.Esent.Interop.CloseDatabaseGrbit]::None)
[Microsoft.Isam.Esent.Interop.Api]::JetDetachDatabase($Session, $Path)
[Microsoft.Isam.Esent.Interop.Api]::JetEndSession($Session, [Microsoft.Isam.Esent.Interop.EndSessionGrbit]::None)
[Microsoft.Isam.Esent.Interop.Api]::JetTerm($Instance)
Write-Verbose -Message "Completed shut down successfully."

[Microsoft.Isam.Esent.Interop.Api]::JetCloseDatabase([Microsoft.Isam.Esent.Interop.JET_SESID](0x29d07db0920),[Microsoft.Isam.Esent.Interop.JET_DBID](1), [Microsoft.Isam.Esent.Interop.CloseDatabaseGrbit]::None)
####

$EsentDllPath = "$env:SYSTEMROOT\Microsoft.NET\assembly\GAC_MSIL\microsoft.isam.esent.interop\v4.0_10.0.0.0__31bf3856ad364e35\Microsoft.Isam.Esent.Interop.dll"
$Path="C:\Windows\System32\sru\SRUDB.dat"

## Let's import the dll to have the API Available
Add-Type -Path $EsentDllPath

## Access the database file
[System.Int32]$FileType = -1
[System.Int32]$PageSize = -1
[Microsoft.Isam.Esent.Interop.Api]::JetGetDatabaseFileInfo($Path, [ref]$PageSize, [Microsoft.Isam.Esent.Interop.JET_DbInfo]::PageSize)
[Microsoft.Isam.Esent.Interop.Api]::JetGetDatabaseFileInfo($Path, [ref]$FileType, [Microsoft.Isam.Esent.Interop.JET_DbInfo]::FileType)
[Microsoft.Isam.Esent.Interop.JET_filetype]$DBType = [Microsoft.Isam.Esent.Interop.JET_filetype]($FileType)

## To access the database we need to open a JET session
[Microsoft.Isam.Esent.Interop.JET_INSTANCE]$Instance = New-Object -TypeName Microsoft.Isam.Esent.Interop.JET_INSTANCE
[Microsoft.Isam.Esent.Interop.JET_SESID]$Session = New-Object -TypeName Microsoft.Isam.Esent.Interop.JET_SESID
$Temp = [Microsoft.Isam.Esent.Interop.Api]::JetSetSystemParameter($Instance, [Microsoft.Isam.Esent.Interop.JET_SESID]::Nil, [Microsoft.Isam.Esent.Interop.JET_param]::DatabasePageSize, $PageSize, $null)
$Temp = [Microsoft.Isam.Esent.Interop.Api]::JetSetSystemParameter($Instance, [Microsoft.Isam.Esent.Interop.JET_SESID]::Nil, [Microsoft.Isam.Esent.Interop.JET_param]::Recovery, [int]$Recovery, $null)
$Temp = [Microsoft.Isam.Esent.Interop.Api]::JetSetSystemParameter($Instance, [Microsoft.Isam.Esent.Interop.JET_SESID]::Nil, [Microsoft.Isam.Esent.Interop.JET_param]::CircularLog, [int]$CircularLogging, $null)
[Microsoft.Isam.Esent.Interop.Api]::JetCreateInstance2([ref]$Instance, "Instance", "Instance", [Microsoft.Isam.Esent.Interop.CreateInstanceGrbit]::None)
$Temp = [Microsoft.Isam.Esent.Interop.Api]::JetInit2([ref]$Instance, [Microsoft.Isam.Esent.Interop.InitGrbit]::None)
[Microsoft.Isam.Esent.Interop.Api]::JetBeginSession($Instance, [ref]$Session, $UserName, $Password)

## Ok Now open the database
[Microsoft.Isam.Esent.Interop.JET_DBID]$DatabaseId = New-Object -TypeName Microsoft.Isam.Esent.Interop.JET_DBID
$Temp = [Microsoft.Isam.Esent.Interop.Api]::JetAttachDatabase($Session, $Path, [Microsoft.Isam.Esent.Interop.AttachDatabaseGrbit]::ReadOnly)
$Temp = [Microsoft.Isam.Esent.Interop.Api]::JetOpenDatabase($Session, $Path, $Connect, [ref]$DatabaseId, [Microsoft.Isam.Esent.Interop.OpenDatabaseGrbit]::ReadOnly)

#Check the session information
#Write-Output -InputObject ([PSCustomObject]@{Instance=$Instance;Session=$Session;DatabaseId=$DatabaseId;Path=$Path})

# Dumptable names
#Write-Output -InputObject ([Microsoft.Isam.Esent.Interop.Api]::GetTableNames($Session, $DatabaseId))

<#
{DD6636C4-8929-4683-974E-22C046A43763} Network Connectivity data
{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} Application Resource usage data
{973F5D5C-1D90-4944-BE8E-24B94231A174} Network usage data
{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86} Windows Push Notification data
{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} Energy usage data
{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT Energy usage data

Windows10
{5C8CF1C7-7257-4F13-B223-970EF5939312}
{973F5D5C-1D90-4944-BE8E-24B94231A174}
{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}
{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}
{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}
{DD6636C4-8929-4683-974E-22C046A43763}
{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}
{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT

#>

$TableNameDBID="SruDbIdMapTable"
[Microsoft.Isam.Esent.Interop.Table]$TableDBID = New-Object -TypeName Microsoft.Isam.Esent.Interop.Table($Session, $DatabaseId, $TableNameDBID, [Microsoft.Isam.Esent.Interop.OpenTableGrbit]::None)
Write-Output -InputObject ([Microsoft.Isam.Esent.Interop.ColumnInfo[]][Microsoft.Isam.Esent.Interop.Api]::GetTableColumns($Session, $TableDBID.JetTableid)) | select *

$tab = "{DD6636C4-8929-4683-974E-22C046A43763}"
[Microsoft.Isam.Esent.Interop.Table]$Tab2 = New-Object -TypeName Microsoft.Isam.Esent.Interop.Table($Session, $DatabaseId, $Tab, [Microsoft.Isam.Esent.Interop.OpenTableGrbit]::None)
Write-Output -InputObject ([Microsoft.Isam.Esent.Interop.ColumnInfo[]][Microsoft.Isam.Esent.Interop.Api]::GetTableColumns($Session, $Tab2.JetTableid)) | ft

## LET DUMP SOME TABLES

$NewTable = @{Name=$TableDBID.Name;Id=$TableDBID.JetTableid;Rows=@()}
$DBRows = @()
[Microsoft.Isam.Esent.Interop.ColumnInfo[]]$Columns = [Microsoft.Isam.Esent.Interop.Api]::GetTableColumns($Session, $Tab2.JetTableid)
$jettable = $tab2


Function Get-SRUMTableDataRows{
  Param(
      [Parameter(Position=0,Mandatory = $true)]
      [ValidateNotNull()]
      $Session,
      ## Need to figure out if I should include the variable type [Microsoft.Isam.Esent.Interop.JET_SESID].
      ## Don't think so but using it might be safer to ensure proper variable is passed
      [Parameter(Position=1,Mandatory = $true)]
      [ValidateNotNull()]
      $JetTable,
      [Parameter(Position=2,Mandatory = $false)]
      [ValidateNotNull()]
      $BlobStrType=[System.Text.Encoding]::UTF16,
      [Parameter(Position=3,Mandatory = $false)]
      [ValidateNotNull()]
      $FutureTimeLimit = [System.TimeSpan]::FromDays(36500) #100 years
  )

  Begin{
    #test
  }

  Process{
    $DBRows = @()
                $i = 1
    Try{

        [Microsoft.Isam.Esent.Interop.ColumnInfo[]]$Columns = [Microsoft.Isam.Esent.Interop.Api]::GetTableColumns($Session, $JetTable.JetTableid)

        if ([Microsoft.Isam.Esent.Interop.Api]::TryMoveFirst($Session, $JetTable.JetTableid)){
            $columnCount = 0
            while([Microsoft.Isam.Esent.Interop.Api]::TryMoveNext($Session, $JetTable.JetTableid)){
                $columnCount++
               }
               $columnCount = $columnCount * 9
                $dev = [Microsoft.Isam.Esent.Interop.Api]::TryMoveFirst($Session, $JetTable.JetTableid)
            do
            {
                $Row = New-Object PSObject

                foreach ($Column in $Columns)
                {
                #"dd"
                Write-Progress -Activity "Retrieving Table Contents..." -Status "$($i)" -PercentComplete (($i / $columnCount) * 100)  
                  $i++
                  #$i
                   # "ss"
                    switch ($Column.Coltyp)
                    {
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::Bit) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsBoolean($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::DateTime) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsDateTime($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::IEEEDouble) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsDouble($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::IEEESingle) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsFloat($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::Long) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt32($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::Binary) {
                            # Default string function retrieves UTF16, so we check the string type we are retrieving
                            if ( $BlobStrType -eq [System.Text.Encoding]::UTF16 ) {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid)
                            } else {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid, $BlobStrType)
                            }
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::LongBinary) {
                            # Default string function retrieves UTF16, so we check the string type we are retrieving
                            if ( $BlobStrType -eq [System.Text.Encoding]::UTF16 ) {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid)
                            } else {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid, $BlobStrType)
                            }
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::LongText) {
                            # Default string function retrieves UTF16, so we check the string type we are retrieving
                            if ( $BlobStrType -eq [System.Text.Encoding]::UTF16 ) {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid)
                            } else {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid, $BlobStrType)
                            }

                            #Replace null characters which are 0x0000 unicode
                            if (![System.String]::IsNullOrEmpty($Buffer)) {
                                $Buffer = $Buffer.Replace("`0", "")
                            }
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::Text) {
                            # Default string function retrieves UTF16, so we check the string type we are retrieving
                            if ( $BlobStrType -eq [System.Text.Encoding]::UTF16 ) {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid)
                            } else {
                                $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid, $BlobStrType)
                            }

                            #Replace null characters which are 0x0000 unicode
                            if (![System.String]::IsNullOrEmpty($Buffer)) {
                                $Buffer = $Buffer.Replace("`0", "")
                            }
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::Currency) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsString($Session, $JetTable.JetTableid, $Column.Columnid, [System.Text.Encoding]::UTF8)

                            #Replace null characters which are 0x0000 unicode
                            if (![System.String]::IsNullOrEmpty($Buffer)) {
                                $Buffer = $Buffer.Replace("`0", "")
                            }
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::Short) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt16($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        ([Microsoft.Isam.Esent.Interop.JET_coltyp]::UnsignedByte) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsByte($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        (14) {
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt32($Session, $JetTable.JetTableid, $Column.Columnid)
                            break
                        }
                        (15) {
                            try{
                            $Buffer = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt64($Session, $JetTable.JetTableid, $Column.Columnid)
                            } 
                            catch{ 
                                $Buffer = "Error"
                            }
                            if ( $Buffer -Ne "Error" -and $column.name -eq "ConnectStartTime") {
                                try {
                                    $DateTime = [System.DateTime]::FromBinary($Buffer)
                                    $DateTime = $DateTime.AddYears(1600)
                                    $buffer = $DateTime

                                    if ($DateTime -gt (Get-Date -Year 1970 -Month 1 -Day 1) -and $DateTime -lt ([System.DateTime]::UtcNow.Add($FutureTimeLimit))) {
                                        $Buffer = $DateTime
                                    }

                                }
                                catch {}
                            }
                            break
                        }
                        default {
                            Write-Warning -Message "Did not match column type to $_"
                            $Buffer = [System.String]::Empty
                            break
                        }
                    }
                     $Row | Add-Member -type NoteProperty -name $Column.Name -Value $Buffer

                }

                $DBRows += $Row

            } while ([Microsoft.Isam.Esent.Interop.Api]::TryMoveNext($Session, $JetTable.JetTableid))
        }
    }

    Catch{
      Write-Output "Could not read table"
      Break
    }
    return $DBRows
  }

  End{

  }
}

# 
$out = Get-SRUMTableDataRows -Session $Session -JetTable $Tab2

function counter($columns){
    $i = 1

    $WinSxS | ForEach-Object {
        Write-Progress -Activity "Counting WinSxS file $($_.name)" -Status "File $i of $($WinSxS.Count)" -PercentComplete (($i / $WinSxS.Count) * 100)  
        $i++
    }
}


# Total time connected
$duration = @()
$out[$out.count..-1] | % {
    $new = $_.connectStartTime.ticks

    if($new -notin $duration){
        $duration += @($new)
    }
} 



# Parsing Registry for profile
$keys = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces\*\profiles\' -Exclude metadata -Recurse).pspath

$table = @{}
foreach($key in $keys){
    $parsed = ''
    try{
        $temp = [System.Text.Encoding]::ascii.GetString(((Get-ItemProperty ($key + '\metadata')).'channel hints'))
        for($i = 0; $i -lt 100; $i++){
            if($temp[$i] -match "[a-zA-Z0-9]"){
            $parsed += @($temp[$i])
            }
        }
        $table[((Get-ItemProperty $key).profileindex)] = $parsed
    }
    catch{}

}


# Recplace profile id with actual SSID
foreach($entry in $table.keys){
    foreach($temp in $out){
        if($temp.l2profileid -eq $entry){
            $temp.l2profileid = $table.item($entry)
        }
    }   
}