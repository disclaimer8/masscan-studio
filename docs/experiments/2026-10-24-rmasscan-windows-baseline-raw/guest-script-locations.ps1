Get-ChildItem C:\Users\lab -Force -ErrorAction SilentlyContinue | Select Mode,LastWriteTime,Length,Name | Format-Table -Auto | Out-String -Width 200
"--- masscan-lab:"; Get-ChildItem C:\Users\lab\masscan-lab -Force -ErrorAction SilentlyContinue | Select Name,Length
"--- base:"; Get-ChildItem C:\Users\lab\base -Force -ErrorAction SilentlyContinue | Select Name,Length
"--- ps1 anywhere in profile (depth 2):"; Get-ChildItem C:\Users\lab -Filter *.ps1 -Recurse -Depth 2 -ErrorAction SilentlyContinue | ? FullName -notmatch '\\src\\|\\.cargo|\\.rustup' | Select FullName,Length,LastWriteTime
