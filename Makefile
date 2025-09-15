debug:
	# powershell.exe "gcc -O0 -g .\testAntiDebug.c -o  .\testAntiDebug.exe"
	powershell.exe "gcc -O0 -g .\packer.c -o  .\packer.exe"
	powershell.exe "fasm ./stub/stub.asm ./stub/stub.bin"
release:
	# powershell.exe "gcc -O0 .\testAntiDebug.c -o  .\testAntiDebug.exe"
	powershell.exe "gcc -O0 .\packer.c -o  .\packer.exe"
	powershell.exe "fasm ./stub/stub.asm ./stub/stub.bin"
test:
	# powershell.exe "gcc -nostartfiles test.c -o test.exe"
	powershell.exe "gcc -O0 packer.c -o packer.exe"
