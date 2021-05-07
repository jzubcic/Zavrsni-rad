rule angler_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "482d6c24a824103f0bcd37fa59e19452"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "    2654435769,   Be"
	$string1 = "DFOMIqka "
	$string2 = ",  Zydr$>>16"
	$string3 = "DFOMIqka( 'OPPj_phuPuiwzDFo')"
	$string4 = "U0BNJWZ9J0vM43TnlNZcWnZjZSelQZlb1HGTTllZTm19emc0dlsYF13GvhQJmTZmbVMxallMdhWW948YWi t    P  b50GW"
	$string5 = "    auSt;"
	$string6 = " eval    (NDbMFR "
	$string7 = "jWUwYDZhNVyMI2TzykEYjWk0MDM5MA%ZQ1TD1gEMzj         3  D       ',"
	$string8 = "('fE').substr    (2    ,    1 "
	$string9 = ",  -1 "
	$string10 = "    )  );Zydr$  [ 1]"
	$string11 = " 11;PsKnARPQuNNZMP<9;PsKnARPQuNNZMP"
	$string12 = "new   Array  (2),  Ykz"
	$string13 = "<script> "
	$string14 = ");    CYxin "
	$string15 = "Zydr$    [    1]"
	$string16 = "var tKTGVbw,auSt, vnEihY, gftiUIdV, XnHs, UGlMHG, KWlqCKLfCV;"
	$string17 = "reXKyQsob1reXKyQsob3 "
condition:
	17 of them
}
rule eleonore_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "08f8488f1122f2388a0fd65976b9becd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var de"
	$string1 = "sdjk];"
	$string2 = "return dfshk;"
	$string3 = "function jkshdk(){"
	$string4 = "'val';"
	$string5 = "var sdjk"
	$string6 = "return fsdjkl;"
	$string7 = " window[d"
	$string8 = "var fsdjkl"
	$string9 = "function jklsdjfk() {"
	$string10 = "function rewiry(yiyr,fjkhd){"
	$string11 = " sdjd "
condition:
	11 of them
}
rule eleonore_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "2f5ace22e886972a8dccc6aa5deb1e79"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var dfshk "
	$string1 = "arrow_next_down"
	$string2 = "return eval('yiyr.replac'"
	$string3 = "arrow_next_over"
	$string4 = "arrow_prev_over"
	$string5 = "xcCSSWeekdayBlock"
	$string6 = "xcCSSHeadBlock"
	$string7 = "xcCSSDaySpecial"
	$string8 = "xcCSSDay"
	$string9 = " window[df "
	$string10 = "day_special"
	$string11 = "var df"
	$string12 = "function jklsdjfk() {"
	$string13 = " sdjd "
	$string14 = "'e(/kljf hdfk sdf/g,fjkhd);');"
	$string15 = "arrow_next"
condition:
	15 of them
}
rule eleonore_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "9dcb8cd8d4f418324f83d914ab4d4650"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "@mozilla.org/file/directory_service;1"
	$string1 = "var exe "
	$string2 = "var file "
	$string3 = "foStream.write(data, data.length);"
	$string4 = "  var file_data "
	$string5 = "return "
	$string6 = " Components.classes["
	$string7 = "url : "
	$string8 = "].createInstance(Components.interfaces.nsILocalFile);"
	$string9 = "  var bstream "
	$string10 = " bstream.readBytes(size); "
	$string11 = "@mozilla.org/supports-string;1"
	$string12 = "  var channel "
	$string13 = "tmp.exe"
	$string14 = "  if (channel instanceof Components.interfaces.nsIHttpChannel "
	$string15 = "@mozilla.org/network/io-service;1"
	$string16 = " bstream.available()) { "
	$string17 = "].getService(Components.interfaces.nsIIOService); "
condition:
	17 of them
}
rule fragus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "));ELI6Q3PZ"
	$string1 = "VGhNU2pWQmMyUXhPSFI2TTNCVGVEUXpSR3huYm1aeE5UaFhXRFI0ZFhCQVMxWkRNVGh0V0hZNFZVYzBXWFJpTVRoVFpFUklaVGxG"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "TkhXa0ZrT1haNGRFSXhRM3BrTkRoVGMxZEJSMmcyT0dwNlkzSTJYM1pCYkZnMVVqQmpWMEZIYURZNGFucGpjalpmZGtGc1dERXpT"
	$string4 = "byKZKkpZU<<18"
	$string5 = ");CUer0x"
	$string6 = "bzWRebpU3yE>>16"
	$string7 = "RUJEWlVvMGNsVTVNMEpNWDNaNGJVSkpPRUJrUlVwRVQwQlNaR2cyY0ZWSE5GbDBRVFZ5UjFnMk9HVldOWGhMYUdFelRIZG5NMWQz"
	$string8 = "WnZSVGxuT1ZSRkwwaFZSelZGUm5GRlJFVTBLVHQ0UWxKQ1drdzBiWEJ5WkhSdVBtdG9XVWd6TVVGSGFFeDVTMlk3ZUVKU1FscE1O"
	$string9 = "QmZjMGN4YjBCd1oyOXBURUJJZEhvMFdYcGtOamhFV1ZwU01GVlZZbXBpUUZKV1lqTXpWMDAwY0dSNlF6aE1SekZ5ZEc4ME9FeEtN"
	$string10 = "SCpMaWXOuME("
	$string11 = "VjJKcVkxZGlYMTlhUVdRNVNUTkhaRFk0YWpsYWJsWkRNVGh0V0hZNFZVYzBXWFJ2Tm5CVmFEUlpWVmhDT0ZWV05YaDBRa1ZTUkUw"
	$string12 = "2;}else{Yuii37DWU"
	$string13 = "ELI6Q3PZ"
	$string14 = "ZUhNNVZYQlZlRFY0UUZnMk9HMVlORkpFYkRsNGMxbEpPRUJSTVY5SGNETllPRXB0YjBsaloySnhPVVZ3UkZWQVgzTllORGgwV0RS"
	$string15 = "S05GbE1lalk0Vm1ORmVEWnpXbEpXZDBWaU5ubzJjRlkzVjFsbFgwVmlURlpuYnpCUE5HNTBhRFpaVEZrMVFYTjZObkIwWTBVNE4x"
	$string16 = "Vm5CWFFVZG9OamhxZW1OeU5sOTJRV3hZTVROSlpEWTRVM294V1VSUFFFdFdZalE0WlVjeGNsSmtObmhBYURVNFZVZEFjRlZDZGtO"
	$string17 = "Yuii37DWU<<12"
	$string18 = ";while(hdnR9eo3pZ6E3<ZZeD3LjJQ.length){eMImGB"
condition:
	18 of them
}
rule fragus_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(ELI6Q3PZ"
	$string1 = "SnJTbVJqV2tOa09VbGZSMHcwY0ZWZmRrRjBjRFY0Y3psVmNGVjROWGhBV0RZNGJWZzBVa1J4TjNCVlgwVmlhRjkyZURaS1NWOUhj"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "VUpKUVdWS05ISlZjMXBTTUdWRlNFQmpaMjlrVDBCTFYzY3pZbGRpZG5oeldFUndkSE16YjB4M2JXSnFZMWRpZVY4ellreDNaMko1"
	$string4 = "((Yuii37DWU"
	$string5 = "YURVNFZXUlhjRlZDZGxsQVJ6UlNaRTlBUzFkM00ySlhiekU0ZEhnMWNrUjZZM0kyWDNaQmJGZ3hNMGxrTmpoVGVqRlpkSEUyV1dW"
	$string6 = "String.fromCharCode(ZZeD3LjJQ);}else if(QIyZsvvbEmVOpp"
	$string7 = "1);ELI6Q3PZ"
	$string8 = "));Yuii37DWU"
	$string9 = ");CUer0x"
	$string10 = "T1ZaQ05IUkRTVGhqT1VWd1ZWOUpRMlZLZG5oNlQwQkxWM2N6WWxkQmRrRkFPVmR3VlRsYWJsWnNOWGhKT1ZkeFZWazFRbEU1UlZK"
	$string11 = "TlpkM2wxS3lzcExUUTRYU2s4UEhocFVqRk9jazA3SUdsbUtIaHBVakZPY2swcGV5QkdWek5NVnlzOVVrSklWVE0wVDJ0NlpTZzJP"
	$string12 = "String.fromCharCode(((eMImGB"
	$string13 = "RGRDUkV0WFV6VkJkRkV4WHpCalYwRkhhRFk0YW5wamNqWmZka0ZzV0RaSWExZzBXWEZDUlZsQVpEWkJOMEoyZUhwd1duSlRXVE5J"
	$string14 = "SCpMaWXOuME(mi1mm8bu87rL0W);eval(Pcii3iVk1AG);</script></body></html>"
	$string15 = "Yuii37DWU"
	$string16 = "Yuii37DWU<<12"
	$string17 = "eTVzWlc1bmRHZ3NJRWhWUnpWRlJuRkZSRVUwUFRFd01qUXNJR2hQVlZsRVJFVmxVaXdnZUVKU1FscE1ORzF3Y21SMGJpd2dSbGN6"
condition:
	17 of them
}
rule fragus_js_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "377431417b34de8592afecaea9aab95d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.appendChild(bdy);try{for (i"
	$string1 = "0; i<10; i"
	$string2 = "default"
	$string3 = "var m "
	$string4 = "/g, document.getElementById('divid').innerHTML));"
	$string5 = " n.substring(0,r/2);"
	$string6 = "document.getElementById('f').innerHTML"
	$string7 = "'atk' onclick"
	$string8 = "function MAKEHEAP()"
	$string9 = "document.createElement('div');"
	$string10 = "<button id"
	$string11 = "/g, document.getElementById('divid').innerHTML);"
	$string12 = "document.body.appendChild(gg);"
	$string13 = "var bdy "
	$string14 = "var gg"
	$string15 = " unescape(gg);while(n.length<r/2) { n"
condition:
	15 of them
}
rule fragus_js_java
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "7398e435e68a2fa31607518befef30fb"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "I></XML><SPAN DATASRC"
	$string1 = "setTimeout('vparivatel()',8000);function vparivatel(){document.write('<iframe src"
	$string2 = "I DATAFLD"
	$string3 = " unescape("
	$string4 = ", 1);swf.setAttribute("
	$string5 = "function XMLNEW(){var spray "
	$string6 = "vparivatel.php"
	$string7 = "6) ){if ( (lv"
	$string8 = "'WIN 9,0,16,0')"
	$string9 = "d:/Program Files/Outlook Express/WAB.EXE"
	$string10 = "<XML ID"
	$string11 = "new ActiveXObject("
	$string12 = "'7.1.0') ){SHOWPDF('iepdf.php"
	$string13 = "function SWF(){try{sv"
	$string14 = "'WIN 9,0,28,0')"
	$string15 = "C DATAFORMATAS"
	$string16 = " shellcode;xmlcode "
	$string17 = "function SNAPSHOT(){var a"
condition:
	17 of them
}
rule fragus_js_quicktime
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "6bfc7bb877e1a79be24bd9563c768ffd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "                setTimeout("
	$string1 = "wnd.location"
	$string2 = "window;"
	$string3 = "        var pls "
	$string4 = "        mem_flag "
	$string5 = ", 1500);} else{ PRyyt4O3wvgz(1);}"
	$string6 = "         } catch(e) { }"
	$string7 = " mem_flag) JP7RXLyEu();"
	$string8 = " 0x400000;"
	$string9 = "----------------------------------------------------------------------------------------------------"
	$string10 = "        heapBlocks "
	$string11 = "        return mm;"
	$string12 = "0x38);"
	$string13 = "        h();"
	$string14 = " getb(b,bSize);"
	$string15 = "getfile.php"
condition:
	15 of them
}
rule fragus_js_vml
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "8ab72337c815e0505fcfbc97686c3562"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " 0x100000;"
	$string1 = "            var gg "
	$string2 = "/g, document.getElementById('divid').innerHTML));"
	$string3 = "                                var sss "
	$string4 = "                }"
	$string5 = "                        document.body.appendChild(obj);"
	$string6 = "                                var hbs "
	$string7 = " shcode; }"
	$string8 = " '<div id"
	$string9 = " hbs - (shcode.length"
	$string10 = "){ m[i] "
	$string11 = " unescape(gg);"
	$string12 = "                                var z "
	$string13 = "                                var hb "
	$string14 = " Math.ceil('0'"
condition:
	14 of them
}
rule zeroaccess_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "a9f30483a197cfdc65b4a70b8eb738ab"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Square ad tag  (tile"
	$string1 = "  adRandNum "
	$string2 = " cellspacing"
	$string3 = "\\n//-->\\n</script>"
	$string4 = "format"
	$string5 = "//-->' "
	$string6 = "2287974446"
	$string7 = "NoScrBeg "
	$string8 = "-- start adblade -->' "
	$string9 = "3427054556"
	$string10 = "        while (i >"
	$string11 = "return '<table width"
	$string12 = "</scr' "
	$string13 = " s.substring(0, i"
	$string14 = " /></a></noscript>' "
	$string15 = "    else { isEmail "
	$string16 = ").submit();"
	$string17 = " border"
	$string18 = "pub-8301011321395982"
condition:
	18 of them
}
rule zeroaccess_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "b5fda04856b98c254d33548cc1c1216c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ApiClientConfig"
	$string1 = "function/.test(pa.toString())"
	$string2 = "background-image:url(http:\\/\\/static.ak.fbcdn.net\\/rsrc.php\\/v2\\/y6\\/x\\/s816eWC-2sl.gif)}"
	$string3 = "Music.init"
	$string4 = "',header:'bool',recommendations:'bool',site:'hostname'},create_event_button:{},degrees:{href:'url'},"
	$string5 = "cca6477272fc5cb805f85a84f20fca1d"
	$string6 = "document.createElement('form');c.action"
	$string7 = "javascript:false"
	$string8 = "s.onMessage){j.error('An instance without whenReady or onMessage makes no sense');throw new Error('A"
	$string9 = "NaN;}else h"
	$string10 = "sprintf"
	$string11 = "window,j"
	$string12 = "o.getUserID(),da"
	$string13 = "FB.Runtime.getLoginStatus();if(b"
	$string14 = ")');k.toString"
	$string15 = "rovide('XFBML.Send',{Dimensions:{width:80,height:25}});"
	$string16 = "{log:i};e.exports"
	$string17 = "a;FB.api('/fql','GET',f,function(g){if(g.error){ES5(ES5('Object','keys',false,b),'forEach',true,func"
	$string18 = "true;}}var ia"
condition:
	18 of them
}
rule zeroaccess_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "5f13fdfb53a3e60e93d7d1d7bbecff4f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.createDocumentFragment();img.src"
	$string1 = "typeOf(events)"
	$string2 = "var i,x,y,ARRcookies"
	$string3 = "callbacks.length;j<l;j"
	$string4 = "encodeURIComponent(value);if(options.domain)value"
	$string5 = "event,HG.components.get('windowEvent_'"
	$string6 = "'read'in Cookie){return Cookie.read(c_name);}"
	$string7 = "item;},get:function(name,def){return HG.components.exists(name)"
	$string8 = "){window.addEvent(windowEvents[i],function(){var callbacks"
	$string9 = "reunload:function(callback){HG.events.add('beforeunload',callback);},add:function(event,callback){HG"
	$string10 = "name){if(HG.components.exists(name)){delete HG.componentList[name];}}},util:{uuid:function(){return'"
	$string11 = "window.HG"
	$string12 = "x.replace(/"
	$string13 = "encodeURIComponent(this.attr[key]));}"
	$string14 = "options.domain;if(options.path)value"
	$string15 = "this.page_sid;this.attr.user_sid"
condition:
	15 of them
}
rule zeroaccess_js4
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "268ae96254e423e9d670ebe172d1a444"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ").join("
	$string1 = "JSON.stringify:function(o){if(o"
	$string2 = "){try{var a"
	$string3 = ");return $.jqotecache[i]"
	$string4 = "o.getUTCFullYear(),hours"
	$string5 = "seconds"
	$string6 = "')');};$.secureEvalJSON"
	$string7 = "isFinite(n);},secondsToTime:function(sec_numb){sec_numb"
	$string8 = "')');}else{throw new SyntaxError('Error parsing JSON, source is not valid.');}};$.quoteString"
	$string9 = "o[name];var ret"
	$string10 = "a[m].substr(2)"
	$string11 = ");if(d){return true;}}}catch(e){return false;}}"
	$string12 = "a.length;m<k;m"
	$string13 = "if(parentClasses.length"
	$string14 = "o.getUTCHours(),minutes"
	$string15 = "$.jqote(e,d,t),$$"
	$string16 = "q.test(x)){e"
	$string17 = "{};HGWidget.creator"
condition:
	17 of them
}
rule zerox88_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "cad8b652338f5e3bc93069c8aa329301"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "function gSH() {"
	$string1 = "200 HEIGHT"
	$string2 = "'sh.js'><\\/SCRIPT>"
	$string3 = " 2 - 26;"
	$string4 = "<IFRAME ID"
	$string5 = ",100);"
	$string6 = "200></IFRAME>"
	$string7 = "setTimeout("
	$string8 = "'about:blank' WIDTH"
	$string9 = "mf.document.write("
	$string10 = "document.write("
	$string11 = "Kasper "
condition:
	11 of them
}
rule zerox88_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "9df0ac2fa92e602ec11bac53555e2d82"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " new ActiveXObject(szHTTP); "
	$string1 = " Csa2;"
	$string2 = "var ADO "
	$string3 = " new ActiveXObject(szOx88);"
	$string4 = " unescape("
	$string5 = "/test.exe"
	$string6 = " szEtYij;"
	$string7 = "var HTTP "
	$string8 = "%41%44%4F%44%42%2E"
	$string9 = "%4D%65%64%69%61"
	$string10 = "var szSRjq"
	$string11 = "%43%3A%5C%5C%50%72%6F%67%72%61%6D"
	$string12 = "var METHOD "
	$string13 = "ADO.Mode "
	$string14 = "%61%79%65%72"
	$string15 = "%2E%58%4D%4C%48%54%54%50"
	$string16 = " 7 - 6; HTTP.Open(METHOD, szURL, i-3); "
condition:
	16 of them
}
rule zeus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Zeus Exploit Kit Detection"
	hash0 = "c87ac7a25168df49a64564afb04dc961"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var jsmLastMenu "
	$string1 = "position:absolute; z-index:99' "
	$string2 = " -1)jsmSetDisplayStyle('popupmenu' "
	$string3 = " '<tr><td><a href"
	$string4 = "  jsmLastMenu "
	$string5 = "  var ids "
	$string6 = "this.target"
	$string7 = " jsmPrevMenu, 'none');"
	$string8 = "  if(jsmPrevMenu "
	$string9 = ")if(MenuData[i])"
	$string10 = " '<div style"
	$string11 = "popupmenu"
	$string12 = "  jsmSetDisplayStyle('popupmenu' "
	$string13 = "function jsmHideLastMenu()"
	$string14 = " MenuData.length; i"
condition:
	14 of them
}

/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-05-07
   Identifier: 20170117
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_20170117_027a6bae8d394da269a4ca68842b0139 {
   meta:
      description = "20170117 - file 20170117_027a6bae8d394da269a4ca68842b0139.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-07"
      hash1 = "61ba0b7af091d0c4f70cd0d2ed2567dcef810a8f9a27e9337136c27d6343da65"
   strings:
      $s1 = "var ufvuba = [-87, 28, WScript, 19, 62, 71, 83, -24][2];" fullword ascii
      $s2 = "yspyvxebcivoxekvabduwatykufr[0] + hzepu;" fullword ascii
      $s3 = "atdezebanyqyfawduzybabyfedidlyjdeligebo[1] + eckunydzaqiwujdypwavyxfanweryrahofemidxybuposoptysatlewibwyby[1] + eduspyhcynalollu" ascii
      $s4 = "//var hozoho2 = ethagcupy2[kzadyrvezykanucewuklafnurymosbyhhoviwutidu[1] + sufexenodynegsucvitkopjemq[1] + binosekkuxpafsynemulo" ascii
      $s5 = "mefywofedsacigjanimsycikripbyhnyqxapepixcicrugcersumbabudulhighyzwelpuhmizubasenatmitgodximfarmujvo[1] + yqreqdevihymbinevcixuzq" ascii
      $s6 = "var wuzciximk0 = itfusarfefmozjedehwowojimafgalhitceknarruhbiltehjapezonjybgitanradxydpesozzytmykxycqyfnaqxubhuzizinalte[0] + ej" ascii
      $s7 = "//var hozoho2 = ethagcupy2[kzadyrvezykanucewuklafnurymosbyhhoviwutidu[1] + sufexenodynegsucvitkopjemq[1] + binosekkuxpafsynemulo" ascii
      $s8 = "var eduspyhcynalollumovilvazyriqupurbewupdelyjliwihapsihdufdevyxcucemrab = [\"ys\"];" fullword ascii
      $s9 = "var arimtosecisivxyrextapetarnotigirdezedybudammojezluwyspyvxebcivoxekvabduwatykufr = [\" \"];" fullword ascii
      $s10 = "var kzadyrvezykanucewuklafnurymosbyhhoviwutidu = [95, \"Get\"];" fullword ascii
      $s11 = "ycescegarrejtussenyspynetuwacatveddevxalafpudyxsuscycru[0] + oluvsihelajydqynygjyvidvirgenlaqgebixivfydypsagylaxmydcadnuze[0] + " ascii
      $s12 = "var ytvaqewi = anbyzwaperizykuwvuzucatqomno[1] + hfuqepbolowokixbepyrumygakylnadcufdebhevantyskempuzeviparisofmozlyfkavrorvaffan" ascii
      $s13 = "var rvuxfalcidzynukxytiwescivgikgisirlagodlovvunowadmysilvogolepromi = [\"Get\"];" fullword ascii
      $s14 = "var ifcygicfuntujyzlikgybqogtoxymyjrekehusecirihzapalpigulwihqejnyxakyjyxajuqxojnytnewuh = [-19, \"ate\", -84];" fullword ascii
      $s15 = "var obpapywniqokidwuhovadjikxunokeqvefronevwawtudi = [\"mg\", -63];" fullword ascii
      $s16 = "izuhvuxlivohsipcodacodcytoqinyrupzopgahenelk[1] + mykfodatazfujapbezningacciritixaculyzyzykqitkosxojemgohmyjbujofapqohkuxygmydop" ascii
      $s17 = "var vazcevajpudfipagizbazsussubgosypqyzzelohohgizescohfydoslekqufhavkykydqujzuzypqaknokumivighewygvutuj = [\"/l\", -51];" fullword ascii
      $s18 = "var ardibtydmaqlixapuntesxypnygbuzudtedlilakopdozlalamtypojtagoqrugokdanezjocirzitniddo = [21, -92, \"om\"];" fullword ascii
      $s19 = "var edmitecpedlugaxcohivzuglytkixodf = [83, \"leS\", -69];" fullword ascii
      $s20 = "var lubeqojdelfilgadotzamaxryzcozwunawycxamulwiwgugtojagusyptorrum = [-22, \"ect\", -48];" fullword ascii
   condition:
      uint16(0) == 0x6176 and filesize < 70KB and
      8 of them
}

rule sig_20170117_624e34d0e6825e4c256c7dd6e6182af6 {
   meta:
      description = "20170117 - file 20170117_624e34d0e6825e4c256c7dd6e6182af6.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-07"
      hash1 = "e9f9f8f257e8de58e953d5504792c37148a07b4516fc7ea6051ad94bf64add1b"
   strings:
      $s1 = "cgugweqon[lqurtihykigopoladoblalmelytjannatnadehgyswemqerrumbunejalkuccuvnuje[1] + utsogvawtypoqilymecylehywvawroqvefylhostyqjel" ascii
      $s2 = "var abrejwi = [54, 29, WScript, -24, 88, -2, -4, 71][2];" fullword ascii
      $s3 = "var babmijmajsuluwqakofceporedumamogtelemnykeregjilomaqimsoscynoqytomvajmixkywsaktetohyflifwor = [-89, -24, \"C:\"];" fullword ascii
      $s4 = "entahmolaxmupowjiravzyhpipebylyjivymwycqylzohejtyvvasidmicybsarsakkybgixezlobulvyvywoqri[0] + nylakpopgociwitalulsyvixvafrigqisy" ascii
      $s5 = "nulo[0]](ukwumebutolyhibqebmahewquvfyfozelcylruzilisupjudylaxbymyfiwlymircirrivfaguhusrybvut[2] + azuxmusavjocezetosnadelebavdez" ascii
      $s6 = "var kogezakamujkudifsontoxyjgyfzybdatkapehlufgokmuvypanurumdyrdynputjiveragetyloxuwitijfim = [\"leS\", -36, -100];" fullword ascii
      $s7 = "cgugweqon[lqurtihykigopoladoblalmelytjannatnadehgyswemqerrumbunejalkuccuvnuje[1] + utsogvawtypoqilymecylehywvawroqvefylhostyqjel" ascii
      $s8 = "var pzenpynak = wragpocijhigcodabujuqmidijamcelogtuzwuwigewsev[1] + rvepijegydikoginecemxotujerixebukkatmaqgeretydja[0] + kzojax" ascii
      $s9 = "var utsogvawtypoqilymecylehywvawroqvefylhostyqjelnulo = [\"n\", -1];" fullword ascii
      $s10 = "aqpupzaqjinohynweszuwkadriqbytmav[1] + kogezakamujkudifsontoxyjgyfzybdatkapehlufgokmuvypanurumdyrdynputjiveragetyloxuwitijfim[0]" ascii
      $s11 = "veragetyloxuwitijfim[0] + tecylipjuffupmewkeqpunusfalmabiqolowvoftijdyzwowejjyryhfizhobtepo[1] + aglesfydyjhinapvaluxgekytgakzyw" ascii
      $s12 = "var lyrepobuggetifnylfibquburvylafolxokiwej = [\"Typ\", -50];" fullword ascii
      $s13 = "lkykakti[1] + npuxopojvigtufypolhupidahzopawytdonsihcojjevlakjytly[0] + bindakadmelymwaszozuvowxecelmoztytoqsosesyplokuldoqfixha" ascii
      $s14 = "afuhysoqk[1] + sowoxepuramektitbeqijxikhoguvnynewxehdikovherdaspekbamollocvu[0] + jduhubinunadrafvoqbacbufolil[2] + ipdyjujkufyb" ascii
      $s15 = "var jduhubinunadrafvoqbacbufolil = [91, -15, \"m3\"];" fullword ascii
      $s16 = "//var ogygty = byjipx[ubejykzesujxytcanxambuvxukajiqujhacofqopqorimjosroduvmynedetukilbymebbicpikvukyndavagqapiwfuqmyvurl[0] + l" ascii
      $s17 = "var ipdyjujkufybentahmolaxmupowjiravzyhpipebylyjivymwycqylzohejtyvvasidmicybsarsakkybgixezlobulvyvywoqri = [\"2\\\\\"];" fullword ascii
      $s18 = "var dlugonuriboctologucmejjekipxiqtelvumyfgucwiqutwanozots = [\"am\", 14];" fullword ascii
      $s19 = "var pzenpynak = wragpocijhigcodabujuqmidijamcelogtuzwuwigewsev[1] + rvepijegydikoginecemxotujerixebukkatmaqgeretydja[0] + kzojax" ascii
      $s20 = "wygnagunontijedxawwajzixemircyqylgaksywisocpenozzobpykqarwysefitejovavamd[0];" fullword ascii
   condition:
      uint16(0) == 0x6176 and filesize < 70KB and
      8 of them
}

rule sig_20170117_87d0b00d7668835ed1ec91c61c5ef7ba {
   meta:
      description = "20170117 - file 20170117_87d0b00d7668835ed1ec91c61c5ef7ba.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-07"
      hash1 = "9e176c60af5f6405c6ae4fa044c7c5a55fa5d8f73eb0fad7fe542f16b21dd7d6"
   strings:
      $s1 = "uwujabditypcogyfitoxryswi[0] + nikzykfyjedtolodlequwmuwowputodwequbefuhe[0] + pnekyqohsozehekmespytpicommudowavlasof[0] + qarqed" ascii
      $s2 = "ullugnad2[covygwejufuvtildysfuhjiwiteribho[0] + xqeqytnuvaromtygonenuhultopihmowemtozydinyvevqoxaskesaqridifold[0] + uresadevila" ascii
      $s3 = "//var osbasfukyc6 = idetiwdy7[emaggesijugyvzufohynavewfaki[2] + ibgoprezgahomiqobywunucsymlejfyrexsejykuhmuflyhkiqdyckihipomyhma" ascii
      $s4 = "furkecizygorelnapafsytahrivlykypigsogpuspylelacmawbaw[1] + arhecyzifojdagxobylunudluwyxy[0] + ijahvysaknecixsizkotrybefubqyrsaze" ascii
      $s5 = "var jtosyqivdyrokvolmozdaczeqgosekzamulcurdirisirpivyndudsakbaravimyfhivterbesdyhihmemjusgylcyxunloggyra = [\"er\", -24];" fullword ascii
      $s6 = "lcyxunloggyra[0] + nyluhekhabolgolkumewkewejy[1] + gnizopbydirhanxagbohfuwxexenwygywqanryncowypunamezalihelfebydnumaflawogolxygg" ascii
      $s7 = "] + ylinaxnifmurykehrikakovaxnumfajophyqcetnysehihatuhxyhpovkilogejytaclygomobunqoccimpywsewbuxaneclyfn[1] + fjecegwopyqiwkukowa" ascii
      $s8 = "ullugnad2[covygwejufuvtildysfuhjiwiteribho[0] + xqeqytnuvaromtygonenuhultopihmowemtozydinyvevqoxaskesaqridifold[0] + uresadevila" ascii
      $s9 = "var pnekyqohsozehekmespytpicommudowavlasof = [\"seB\", 89, 0];" fullword ascii
      $s10 = "var mupru = tdabgoziwajmufpylqynxuminesyrinlaxxumoxhutqicyphafincogkycyttolebvytobnybydlutoworesrysti[1] + somudzomlecmafciwvuve" ascii
      $s11 = "ujyhugv9[mkobjehdyrfoqkacezerzizyntubraqotgoporwydmexuvoqkicquhnicyqonqicsumyzlixapyvijmicaquhybywsofahi[0] + yrjalsozlahuzleliv" ascii
      $s12 = "var uresadevilasgaksivbevkobutvuddujduvysigfukotavyqsowonygygapbaskalyrunecusbikruwv = [\"te\", 68];" fullword ascii
      $s13 = "jjovguxifunx[1] + lallolybpolyvapymwirebubarpajcejrunwyvyrhupyhaluzujtaduqenhuwiqtefmuwkudneplamokguqogemyxo[0]];" fullword ascii
      $s14 = "qgekigruhkifpetomdoqpihcumdyko[0] + lvavxekkabupzymimyddytiqomobyfhyclyskewabeccirzumakyquseryzcicibikyjuvyfuvqywdeqfyhyryfkus[1" ascii
      $s15 = "sgaksivbevkobutvuddujduvysigfukotavyqsowonygygapbaskalyrunecusbikruwv[0] + ojvifamqerakacmibjotizajypapiwybjacenxunfogpywymwakaj" ascii
      $s16 = "conbosygoqrapmumwixp[0])[vikogtaqqogcecrunupoqilxomlal[2] + ignizbopgiraqriciniquxgosararqyvomexhyqivcoztemefevxytmaryzyqhijyju[" ascii
      $s17 = "var vikogtaqqogcecrunupoqilxomlal = [-81, -23, \"At\"];" fullword ascii
      $s18 = "var rtefcitwinagozumhejvajsozecuvqeffetumosvorubiclynujihonxihucpuqkikwejevbyki = [80, \"C:\"];" fullword ascii
      $s19 = "var dzyczab = [66, 36, 82, 7, WScript, 46, 14, 64][4];" fullword ascii
      $s20 = "var apbicebujlogodqulwycwixcamgagbijylcigavlubwolonmansydfyzhanelahwynicwawvatqumtyvjetuqynawrutho = [\"OD\", -46];" fullword ascii
   condition:
      uint16(0) == 0x6176 and filesize < 80KB and
      8 of them
}

rule sig_20170117_8ee3104598a7285f26d7694fda5b325e {
   meta:
      description = "20170117 - file 20170117_8ee3104598a7285f26d7694fda5b325e.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-07"
      hash1 = "be7b6a5112f7fef0632eb87b5d9a4832b3743b32e13fdff252ae83a40437ec8d"
   strings:
      $s1 = "var mace3 = qikarlet9[ucezsyrtajjeqxirbujwupyzbezxupmyteqwotelyjowminropidynofesizivxyluwqihwafgotaxl[0] + oziwyrsodabgelugzikuf" ascii
      $s2 = "didybtenwazqowysluwzavgurykyrqircisopezcocpivgadhyfopbinqityryfsogm[0] + zrakosgapemojdysufitmilbolgilizo[0] + kydanyzeljetiwxax" ascii
      $s3 = "avukavku8[okexunxyhvilfovoxixruxkeqojegduzdijadradytorbaqtezzeruvedehakalyhpupitisolihokzuzcafiwtofdaxirc[0] + ucniposaquhxuhutl" ascii
      $s4 = "var egbuqohp = [26, -9, -97, -86, WScript, 34, -18][4];" fullword ascii
      $s5 = "var dlanlumwawincicralirunozumahpytulhyvxidxepbuqyhakduzguzfyzvusyzizfadcyqekeqapel = [\"C:\"];" fullword ascii
      $s6 = "var ikniro3 = ibattagosxuvsazacedotyvzotjynihlogjajekjywbenduxovujpedfyhemcebrubodkozysw[0] + gynfuhyhpoparkijjogyhunsuxife[1] +" ascii
      $s7 = "var oziwyrsodabgelugzikufdidybtenwazqowysluwzavgurykyrqircisopezcocpivgadhyfopbinqityryfsogm = [\"Spe\", 16];" fullword ascii
      $s8 = "var uqhezyqejotohygnujuwoqpewpybmyvopawbinewyslibuwepemmivxatawpamyfkikahjuqjerepjekazelapicw = [-69, -69, \"st\"];" fullword ascii
      $s9 = "ykuvberjo[0] + tawobmehefebtidilzatkafgesyganernejrubiznixputy[0] + uqhezyqejotohygnujuwoqpewpybmyvopawbinewyslibuwepemmivxatawp" ascii
      $s10 = "var wlupzafegnycrunyrmunicxusjalpyddetkosfovafobosebjuwozuznycpuvpushe = [-10, -6, \"am\"];" fullword ascii
      $s11 = "ubbyjanjyxkysamygagepyhydahr[0] + wlupzafegnycrunyrmunicxusjalpyddetkosfovafobosebjuwozuznycpuvpushe[2];" fullword ascii
      $s12 = "var scomotzodaxkinkedgipakumkaxvultaqzypivabkynxysitkocnapnimnazxyzhithobavkimyjotahehatadregi = [\"le\", -70];" fullword ascii
      $s13 = "cgybyvjuha[1] + imgypozjipipelovusebpekukdeqgehuriwtapwacarebbido[0] + ugapsuvorrermiglyvcevaqguzhopjezyspamilziglixyrtohfolbore" ascii
      $s14 = "//var ejyhe0 = aznajkeha6[xuzaxibeqavtepwulfojiqisjyhijoxrellehargepufaxixsebyxnuxgynzugytuxuvetyvxovanamyluqulijfikyhp[0] + ijx" ascii
      $s15 = "var ibattagosxuvsazacedotyvzotjynihlogjajekjywbenduxovujpedfyhemcebrubodkozysw = [\"htt\"];" fullword ascii
      $s16 = "var ucezsyrtajjeqxirbujwupyzbezxupmyteqwotelyjowminropidynofesizivxyluwqihwafgotaxl = [\"Get\"];" fullword ascii
      $s17 = "var igygyjsexl08 = new Function(ogelxazijwutceqojibvadrebyxcamverusakosatypyvitavahzarxubyrkirgovorylyganaduwe[1] + iwsepwasirty" ascii
      $s18 = "avukavku8[okexunxyhvilfovoxixruxkeqojegduzdijadradytorbaqtezzeruvedehakalyhpupitisolihokzuzcafiwtofdaxirc[0] + ucniposaquhxuhutl" ascii
      $s19 = " + axqabajjunnofasmyswanynqosusicdaqravboxatehevubpejultylogisuwudcacyrybdaxmimxiftumrumy[0] + idedivijgapukiwacolavoxwujysqeslo" ascii
      $s20 = "var egrypifewwafezxajzafwabbyxxehitjirqeqdolohylomik = [\"Get\", 45];" fullword ascii
   condition:
      uint16(0) == 0x6176 and filesize < 80KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

