$python = "C:\Program Files\Python314\python.exe"
$out = "C:\Users\werlist99\canaryguard\guard.out.log"
$err = "C:\Users\werlist99\canaryguard\guard.err.log"
Start-Process $python -ArgumentList '-u', 'C:\Users\werlist99\canaryguard\main.py' -WorkingDirectory 'C:\Users\werlist99\canaryguard' -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err