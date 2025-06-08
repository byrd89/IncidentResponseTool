Invoke-WebRequest -Uri "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt" -OutFile "$PSScriptRoot\eff_wordlist_raw.txt"

Get-Content "$PSScriptRoot\eff_wordlist_raw.txt" | ForEach-Object {
    ($_ -split "\s+")[1]
} | Set-Content "$PSScriptRoot\eff_wordlist_clean.txt"
