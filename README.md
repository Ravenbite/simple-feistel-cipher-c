# simple-feistel-cipher-c
simple feistel blockcipher [128,256,512]  with cipher feedback mode
(work in progress)


 Greetings fellow human beings,
 
 [...] well I'll make it short: Me computer science student created a simple feistel cipher for learning purposes.
 I know there is many on my todo list, but the goal is to first complete my idea and then add fancy code or precise error checking.
 
 My first prototype worked just fine, for a little challenge I deleted all :D and well here Iam now with my second iteration. 
 Behold, the software is at the moment only partially written. I'll write from time to time some more lines to complete the project.
 Thats why there might be some logic and syntax errors. Feel free to do anything what you want with my code.
 
 Best wishes
 
 
 Features:
 -[128,256,512]bit block cipher with encryption function and since -- it should be invertible (I guess) -- decryption should be no problem too.
 -memory mapping of small file views till full file has been encrypted
 -autodetect of encryption state and cipher parameters when decrypting a file
 
 TODO:
 -precise error checking
 -better interfaces
 -add more block ciphers
 -add more operation modi
 -unix port
