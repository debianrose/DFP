# DFP - Written in Go
> debianrose's file protocol

### Why?
i wanna create VCD/VCS Like Git or Subversion so uh... fir first i will create THIS protocol
### Can i write my own client? (Android/IOS/MacOS/Windows/Linux/BSD)
In theory yes! but for now it has only bulit-in TUI...
### How protocol works?
i will take Upload Mode for example.
1. Client open QUIC connection
2. Client sending Command to upload file
3. after that client send unit32 and name of file + in unit64 format size of file (eg. 128 bytes)
4. client start send files with 128 chunks!
6. Server compress, encrypts and saves the file!
Done! Thats how protocol works!
> for now.
