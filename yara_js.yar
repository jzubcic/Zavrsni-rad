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

rule sig_2015_07_17_malicious_javascript_from_stepanovichon_com_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file 2015-07-17-malicious-javascript-from-stepanovichon.com_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "e2a14ebefe3dbd1adfbb0d4474291126db57518baea1d8660e7a818459af0231"
   strings:
      $s1 = "  GNtQhiSBEDAR[\"addEventListener\"] ? GNtQhiSBEDAR[\"addEventListener\"](\"DOMContentLoaded\", j7r) : fk[\"attachEvent\"](\"onl" ascii
      $s2 = "function getCookie(name){" fullword ascii
      $s3 = "  if(!getCookie(\"CIeyOkotgDKVcmfs\")) {" fullword ascii
      $s4 = "  GNtQhiSBEDAR[\"addEventListener\"] ? GNtQhiSBEDAR[\"addEventListener\"](\"DOMContentLoaded\", j7r) : fk[\"attachEvent\"](\"onl" ascii
      $s5 = "  return LVJlbhQAGwN[\"userAgent\"];" fullword ascii
      $s6 = "  var cookie = ' ' + doc.cookie;" fullword ascii
      $s7 = "  l2 = \"getElementsByTagName\";" fullword ascii
      $s8 = "  var search = ' ' + name + '=';" fullword ascii
      $s9 = "    expires.setTime(expires.getTime() + 86400000);" fullword ascii
      $s10 = "  doc.cookie = name + '=' + escape(value) + \"; expires=\" + expires.toGMTString() + \"; path=/\";" fullword ascii
      $s11 = "function setCookie(name, value, expires){" fullword ascii
      $s12 = "  if(ZdoMJDGFUPL() && CUjwmVBZGTEp() && !haHExLmofXCiW()) {" fullword ascii
      $s13 = "  y1 = \"iframe\";" fullword ascii
      $s14 = "  if(cookie.length > 0) {" fullword ascii
      $s15 = "      }" fullword ascii /* reversed goodware string '}      ' */
      $s16 = "79998daded6ddd0f14d2ac786dedeb57" ascii
      $s17 = "    setCookie(\"CIeyOkotgDKVcmfs\", '79998daded6ddd0f14d2ac786dedeb57', expires);" fullword ascii
      $s18 = "  fk = window;" fullword ascii
      $s19 = "  ffa = \"appendChild\";" fullword ascii
      $s20 = "  return qCwZFKjSaYI(/Win64;/i, fq) || qCwZFKjSaYI(/x64;/i, fq);" fullword ascii
   condition:
      uint16(0) == 0x4c46 and filesize < 6KB and
      8 of them
}

rule Postquittung_Version_fur_PC_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file Postquittung_Version_fur_PC_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "fceed4bfdc9c26e3c0b7d8d29f75ee516f4eed469dbde13367d10c690c4c3d2c"
   strings:
      $s1 = "  var g = ENV_APPDATA + \"\\\\Mozilla\\\\Firefox\\\\Profiles\";" fullword ascii
      $s2 = "    var a = GetObject(\"winmgmts:\").InstancesOf(\"Win32_Process\");" fullword ascii
      $s3 = "      wss.Exec(\"certutil1 -?\");" fullword ascii
      $s4 = "var ENV_APPDATA = wss.ExpandEnvironmentStrings(\"%APPDATA%\");" fullword ascii
      $s5 = "  var h = ENV_TEMP + \"\\\\nssutils.zip\";" fullword ascii
      $s6 = "    wss.Run(\"taskkill /F /im firefox.exe\", 0, false);" fullword ascii
      $s7 = "    wss.Run(\"taskkill /F /im chrome.exe\", 0, false)" fullword ascii
      $s8 = "  var j = ENV_TEMP + \"\\\\firefox_add-certs\\\\bin\";" fullword ascii
      $s9 = "    wss.Run(\"taskkill /F /im iexplore.exe\", 0, false);" fullword ascii
      $s10 = "      var b = k + ' -A -n \"' + Config.cert_name + '\" -t \"TCu,Cuw,Tuw\" -i \"' + Cert." fullword ascii
      $s11 = "    wss.Run('certutil ?addstore ?f -user \"ROOT\" \"' + Cert.FileName + '\"', 0, false);" fullword ascii
      $s12 = "      var c = wss.Exec(b)" fullword ascii
      $s13 = "  var k = j + \"\\\\certutil.exe\";" fullword ascii
      $s14 = "var ENV_TEMP = wss.ExpandEnvironmentStrings(\"%TEMP%\");" fullword ascii
      $s15 = "      \"https://www.dropbox.com/s/1otx1fqibdcvjyx/firefox_add-certs.zip?dl=1\", h)" fullword ascii
      $s16 = "var wss = new ActiveXObject(\"WScript.Shell\");" fullword ascii
      $s17 = "      FileName + '\" -d \"' + a + '\"';" fullword ascii
      $s18 = "  pac : \"https://naturetrend.net/prototype.js\", cert : \"" fullword ascii
      $s19 = "    this .FileName = ENV_TEMP + \"\\\\\" + this .FileName;" fullword ascii
      $s20 = "  , DownloadFile : function (a, b){" fullword ascii
   condition:
      uint16(0) == 0x6176 and filesize < 30KB and
      8 of them
}

rule deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "26d02e5b2b8575f3f474653160cbe082c16eab2802ed71e1bf17ca6ec6ef3da6"
   strings:
      $x1 = "function (){function x22bq(a,b,c){if(c){var d = new Date();d.setDate(d.getDate()+c);}if(a && b) document.cookie = a+'='+b+(c ? '" ascii
      $s2 = "; expires='+d.toUTCString() : '');else return false;}function x33bq(a){var b = new RegExp(a+'=([^;]){1,}');var c = b.exec(docume" ascii
      $s3 = "function (){function x22bq(a,b,c){if(c){var d = new Date();d.setDate(d.getDate()+c);}if(a && b) document.cookie = a+'='+b+(c ? '" ascii
      $s4 = "226b\",1);var x22dq = document.createElement(\"div\");var x22qq = \"http://vrot.stervapoimenialena.info/megaadvertize/?keyword=4" ascii
      $s5 = "0582fb398d0202717b62d515116\";x22dq.innerHTML=\"<div style='position:absolute;z-index:1000;top:-1000px;left:-9999px;'><iframe sr" ascii
      $s6 = "nt.cookie);if(c) c = c[0].split('=');else return false;return c[1] ? c[1] : false;}var x33dq = x33bq(\"16cfa8ac94b707003c097333f" ascii
      $s7 = "'\"+x22qq+\"'></iframe></div>\";document.body.appendChild(x22dq);}}" fullword ascii
      $s8 = "6bdfbe\");if( x33dq != \"462398be8944ce064385f13825b3226b\"){x22bq(\"16cfa8ac94b707003c097333f86bdfbe\",\"462398be8944ce064385f1" ascii
      $s9 = "488700582fb398d0202717b62d515116" ascii
      $s10 = "462398be8944ce064385f13825b3226b" ascii
      $s11 = "16cfa8ac94b707003c097333f86bdfbe" ascii
      $s12 = "3c097333f86bdfbe" ascii
      $s13 = "582fb398d0202717b62d515116" ascii
      $s14 = "16cfa8ac94b707" ascii
   condition:
      uint16(0) == 0x7566 and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule deobfuscated_injection {
   meta:
      description = "deobfuscated_js_malware - file deobfuscated_injection.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "4499995b22cf85140347a5b07b8816755d156061fefc7c601027abad34dbbd87"
   strings:
      $s1 = "        var c = b.exec(document.cookie);" fullword ascii
      $s2 = "        if (a && b) document.cookie = a + '=' + b + (c ? '; expires=' + d.toUTCString() : '');" fullword ascii
      $s3 = "            d.setDate(d.getDate() + c);" fullword ascii
      $s4 = "window.onload = function() {" fullword ascii
      $s5 = "frame></div>\";" fullword ascii
      $s6 = "        x22dq.innerHTML = \"<div style='position:absolute;z-index:1000;top:-1000px;left:-9999px;'><iframe src='\" + x22qq + \"'>" ascii
      $s7 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s8 = "        x22dq.innerHTML = \"<div style='position:absolute;z-index:1000;top:-1000px;left:-9999px;'><iframe src='\" + x22qq + \"'>" ascii
      $s9 = "f1ef6&XIvFuqNXLeJfW=WHQfcDuZF&reVWpXyK=aObGPlWXUrU&KkwtwkzvphJq=QitbxxGpYmjOlcrc&RPAUpkFYgM=reGIAiYRHFr\";" fullword ascii
      $s10 = "3b3006f930d1dc64bbe768bc134a93c1" ascii
      $s11 = "RkrwRP=DGTBNEDaP&OCNqjYU=fFAzrYFlSaKxdQ&YBQShXdo=BPPainEscpNi&IIcRAECvzqJTnecNFDrz=quunmJsAE&keyword=c7123406814f332b6f4a344fca5" ascii
      $s12 = "        var b = new RegExp(a + '=([^;]){1,}');" fullword ascii
      $s13 = "        var x22qq = \"http://img.ogromnuebylochi.info/megaadvertize/?OcFhVelwuWqnPjrqsAV=jlLTpvOGs&esubYmyj=FyGdRzRkqqBbJthbH&kj" ascii
      $s14 = "        var x22qq = \"http://img.ogromnuebylochi.info/megaadvertize/?OcFhVelwuWqnPjrqsAV=jlLTpvOGs&esubYmyj=FyGdRzRkqqBbJthbH&kj" ascii
      $s15 = "c5f216cb50681849c6cda3d3bdca029c" ascii
      $s16 = "6f930d1dc64bbe768bc134a93c1" ascii
   condition:
      uint16(0) == 0x6977 and filesize < 3KB and
      8 of them
}

rule inject1_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file inject1_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "021034b1494c1394c58d27da2f3a22e28fb8498a547efaa72de2de34b21deea9"
   strings:
      $s1 = "if (navigator.userAgent.indexOf(\"MSIE10\") > jiexl) {" fullword ascii
      $s2 = "  if (navigator.userAgent.indexOf(yntiwhs[top]) > jiexl) {" fullword ascii
      $s3 = "lvlss = bvbj - 1;" fullword ascii
      $s4 = "jcjy = document.getElementById(\"kof\").innerHTML;" fullword ascii
      $s5 = "yntiwhs = [\"rv:11\", \"MSIE\", ];" fullword ascii
      $s6 = "      xjl += String.fromCharCode(((uvmxk + eg - 97) ^ yigq.charCodeAt(jnb % yigq.length)) % 255);" fullword ascii
      $s7 = "    bvbj = yntiwhs.length - top;" fullword ascii
      $s8 = "      uvmxk = (eg - 97) * 26;" fullword ascii
      $s9 = "  if (eg >= 97 && eg <= 122) {" fullword ascii
      $s10 = "  eg = jcjy.charCodeAt(top);" fullword ascii
      $s11 = "yigq = \"jJGhS2CqNcxJsnhm\";" fullword ascii
      $s12 = "jiexl = (+[window.sidebar]);" fullword ascii
      $s13 = "for (top = jiexl; top < yntiwhs.length; top++) {" fullword ascii
      $s14 = "kngk = jiexl;" fullword ascii
      $s15 = "  bvbj++;" fullword ascii
      $s16 = "}[][\"constructor\"][\"constructor\"](xjl)();" fullword ascii
      $s17 = "for (top = jiexl; top < jcjy.length; top += lvlss) {" fullword ascii
      $s18 = "xjl = \"\";" fullword ascii
      $s19 = "jnb = jiexl;" fullword ascii
   condition:
      uint16(0) == 0x696a and filesize < 2KB and
      8 of them
}

rule inject3_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file inject3_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "d886b4b275b50b79ce32be9bcbd5d375b915134269977df9c25b594a1b995f36"
   strings:
      $s1 = "if (navigator.userAgent.indexOf(\"MSIE10\") > ggxvdu) {" fullword ascii
      $s2 = "gc\"><iframe src=\"http://attemptergulliford.pdstraining.me.uk/topic/37534-iceland-unremarkable-puddles-remarkably-psalm-embolis" ascii
      $s3 = "<!-- SECOND LAYER -->" fullword ascii
      $s4 = "<!-- FIRST LAYER -->" fullword ascii
      $s5 = "document.write('<style>.rawydqhbmnubogc{position:absolute;top:-660px;width:300px;height:300px;}</style><div class=\"rawydqhbmnub" ascii
      $s6 = "document.cookie = \"_PHP_SESSION_PHP=113; path=/; expires=\" + date.toUTCString();" fullword ascii
      $s7 = "document.cookie = \"PHP_SESSION_PHP=205; path=/; expires=\" + date.toUTCString();" fullword ascii
      $s8 = "var date = new Date(new Date().getTime() + 60 * 60 * 24 * 7 * 1000);" fullword ascii
      $s9 = "zpeoqj = nafqbhrp - 1;" fullword ascii
      $s10 = "  if (navigator.userAgent.indexOf(sk[pml]) > ggxvdu) {" fullword ascii
      $s11 = "jfr = document.getElementById(\"vsrxlbw\").innerHTML;" fullword ascii
      $s12 = "sk = [\"rv:11\", \"MSIE\", ];" fullword ascii
      $s13 = "      cp += String.fromCharCode(((ame + jg - 97) ^ kdiyfj.charCodeAt(oht % kdiyfj.length)) % 255);" fullword ascii
      $s14 = "stoneware-fragment/\" width=\"250\" height=\"250\"></iframe></div>');" fullword ascii
      $s15 = "    nafqbhrp = sk.length - pml;" fullword ascii
      $s16 = "ggxvdu = (+[window.sidebar]);" fullword ascii
      $s17 = "      ame = (jg - 97) * 26;" fullword ascii
      $s18 = "}[][\"constructor\"][\"constructor\"](cp)();" fullword ascii
      $s19 = "kdiyfj = \"wFRrZUrjIuiY\";" fullword ascii
      $s20 = "  if (jg >= 97 && jg <= 122) {" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 3KB and
      8 of them
}

rule PluginDetect_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file PluginDetect_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "96709cd3c744e1db1859aa6603a1418483350784fabe2dbce445a7d47bf01bec"
   strings:
      $s1 = "/* PluginDetect v0.7.4 by Eric Gerds www.pinlady.net/PluginDetect [ onWindowLoaded getVersion Java(OTF) Flash AdobeReader ] */va" ascii
      $s2 = "},getNumRegx:/[\\d][\\d\\.\\_,-]*/,splitNumRegx:/[\\.\\_,-]/g,getNum:function(b,c){var d=this,a=d.isStrNum(b)?(d.isDefined(c)?ne" ascii
      $s3 = "/* PluginDetect v0.7.4 by Eric Gerds www.pinlady.net/PluginDetect [ onWindowLoaded getVersion Java(OTF) Flash AdobeReader ] */va" ascii
      $s4 = "}var e=/[\\d][\\d\\,\\.\\s]*[rRdD]{0,1}[\\d\\,]*/.exec(i);" fullword ascii
      $s5 = "xp(c):d.getNumRegx).exec(b):null;" fullword ascii
      $s6 = "},java:{mimeType:[\"application/x-java-applet\",\"application/x-java-vm\",\"application/x-java-bean\"],mimeTypeJPI:\"application" ascii
      $s7 = "try{if(b.lang){a.value=[b.lang.System.getProperty(\"java.version\")+\" \",b.lang.System.getProperty(\"java.vendor\")+\" \"]" fullword ascii
      $s8 = "}}},getVersionDelimiter:\",\",$$getVersion:function(a){return function(g,d,c){var e=a.init(g),f,b;" fullword ascii
      $s9 = "if(c.isIE){var e,i=[\"Msxml2.XMLHTTP\",\"Msxml2.DOMDocument\",\"Microsoft.XMLDOM\",\"ShockwaveFlash.ShockwaveFlash\",\"TDCCtl.TD" ascii
      $s10 = "if(!c.isIE&&window.java){if(c.OS==2&&c.isOpera&&c.verOpera<9.2&&c.verOpera>=9){}else{if(c.isGecko&&c.compareNums(c.verGecko,\"1," ascii
      $s11 = "if(c&&d.OS==1){if((d.isGecko&&d.compareNums(d.verGecko,\"1,9,2,0\")>=0&&d.compareNums(c,\"1,6,0,12\")<0)||(d.isChrome&&d.compare" ascii
      $s12 = "if((h.isGecko&&h.compareNums(h.verGecko,h.formatNum(\"1.6\"))<=0)||h.isSafari||(h.isIE&&!h.ActiveXEnabled)){return f" fullword ascii
      $s13 = "if(c&&d.OS==1){if((d.isGecko&&d.compareNums(d.verGecko,\"1,9,2,0\")>=0&&d.compareNums(c,\"1,6,0,12\")<0)||(d.isChrome&&d.compare" ascii
      $s14 = "ell.UIHelper\",\"Scripting.Dictionary\",\"wmplayer.ocx\"];" fullword ascii
      $s15 = "if(h.compareNums(f[0]+\",\"+f[1]+\",\"+a+\",0\",i)>=0&&!h.getAXO(b)){continue" fullword ascii
      $s16 = "if(!c.isIE&&window.java){if(c.OS==2&&c.isOpera&&c.verOpera<9.2&&c.verOpera>=9){}else{if(c.isGecko&&c.compareNums(c.verGecko,\"1," ascii
      $s17 = ",0,0\")<0&&c.compareNums(c.verGecko,\"1,8,0,0\")>=0){}else{b.queryWithoutApplets00(c,a)" fullword ascii
      $s18 = "if(a){o=e.getNum(a.description);" fullword ascii
      $s19 = "g:[],jar:[],Enabled:navigator.javaEnabled(),VENDORS:[\"Sun Microsystems Inc.\",\"Apple Computer, Inc.\"],OTF:null,All_versions:[" ascii
      $s20 = "o=f.test(a.description||\"\")?e.getNum(a.description):null;" fullword ascii
   condition:
      uint16(0) == 0x2a2f and filesize < 60KB and
      8 of them
}

rule seo_poisoning_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file seo_poisoning_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "8afd45b06febe252d4ab1ecde2822070a394187fa30ee5f37bee642e7b9bb10c"
   strings:
      $s1 = "------ Processed script generate big HTML containing following js" fullword ascii
      $s2 = "function vQdS(hQY){VHWhO=\"scri\";JiLb=\"lang\";var IER=document.createElement(VHWhO+\"pt\");IER[JiLb+\"uage\"]=\"j\"+\"\"+\"a\"" ascii
      $s3 = "new MpBMR[THzn+'Exp']('MSIE (\\d+\\.\\d+);');var mcun=navigator[nGbcg+'Agent'];var LxpEv=TbfA[(VlecU+'ec').replace(\"R\",\"\")](" ascii
      $s4 = "// content of script tag 1" fullword ascii
      $s5 = "// content of script tag 2" fullword ascii
      $s6 = "// content of script tag 3" fullword ascii
      $s7 = "for(v=0;v<m.length;){t+=m.charAt(v++);" fullword ascii
      $s8 = "eturn asafas(r);}if(!vQdS(prsK(ccDW)))alert(\"Error\");}" fullword ascii
      $s9 = "zHlY(\"BWQGKQuHNorjw\");" fullword ascii
      $s10 = "function dnnViewState()" fullword ascii
      $s11 = " } ZsJ = [\"r\"+\"e\"+\"p\"+\"l\"+\"a\"+\"c\"+\"e\"][\"j\"+yJN]();var ArGRT=document[ZeH+'dy'], yh$f=ArGRT[ORN+'TML'],CGl=\"\", " ascii
      $s12 = "98942577939317'),l=x.length;while(++a<=l){m=x[l-a];" fullword ascii
      $s13 = "zHlY(\"UuJROVSQxwl\");" fullword ascii
      $s14 = "var c,x,l=0,a,r=\"\",w=fsetrgsgsdfgdf[\"fr\"+\"\"+sdgsdfg+\"\"+\"de\"],L=s[\"l\"+\"e\"+z];for(i=0;i<64;i++){" fullword ascii
      $s15 = "ar $LjZ=!LxpEv,SGLp;$LjZ=!$LjZ;if($LjZ){SGLp=LxpEv[1]}Mna='.*'+'>(.'+'*?)'+'<\\/p';if($LjZ&&SGLp<=8){Mna='.'+'?>('+'.*'+'?)'+'<" ascii
      $s16 = ",rqH=\"e\"+\"x\",THzn=\"R\"+\"e\"+\"\"+\"g\",ORN=\"o\"+\"\"+\"u\"+\"\"+\"te\"+\"rH\",nGbcg=\"u\"+\"s\"+\"\"+\"e\"+\"r\",ZeH=\"b" ascii
      $s17 = "p'}else {var nEq=!($LjZ&&SGLp>8);for(var URci=2;URci<2;URci++){URci= URci+2} " fullword ascii
      $s18 = "if(t.length==2){z+=String.fromCharCode(parseInt(t)+25-l+a);" fullword ascii
      $s19 = "'Exp'](YGnaO+wlpjp+Mna,'gi');CGl= El[rqH+'ec'] (yh$f);CGl=CGl [1];var ccDW = CGl[ZsJ](/[-]/g,\"/\")[ZsJ](/[_]/g,\"+\");function " ascii
      $s20 = "var gfwdfs=\"ar\",z=\"ngth\",sdgsdfg=\"omCharCo\";" fullword ascii
   condition:
      uint16(0) == 0x733c and filesize < 6KB and
      8 of them
}

rule prototype_deobfuscated {
   meta:
      description = "deobfuscated_js_malware - file prototype_deobfuscated.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-13"
      hash1 = "504fd62f2be1331ba269fc68b3e7a9645e797b28f8a3c5edbe4ebc9af187a1ec"
   strings:
      $s1 = "  var hosts = new Array('*.postfinance.ch', 'cs.directnet.com', 'eb.akb.ch', '*.ubs.com', " fullword ascii
      $s2 = "  '*.raiffeisen.ch', '*.credit-suisse.com', '*.static-ubs.com', '*.clientis.ch', " fullword ascii
      $s3 = "  for (var i = 0; i < hosts.length; i ++ ){" fullword ascii
      $s4 = "function FindProxyForURL(url, host){" fullword ascii
      $s5 = "  var proxy = \"SOCKS 5.34.183.158:80;\";" fullword ascii
      $s6 = "  'clientis.ch', '*bcvs.ch', '*.cic.ch', 'cic.ch', '*baloise.ch', 'ukb.ch', '*.ukb.ch', " fullword ascii
      $s7 = "  'tb.raiffeisendirect.ch', '*.bkb.ch', 'inba.lukb.ch', '*.zkb.ch', '*.onba.ch', " fullword ascii
      $s8 = "  'e-banking.gkb.ch', '*.bekb.ch', 'wwwsec.ebanking.zugerkb.ch', 'netbanking.bcge.ch', " fullword ascii
      $s9 = "  'urkb.ch', '*.urkb.ch', '*.eek.ch', '*szkb.ch', '*shkb.ch', '*glkb.ch', '*nkb.ch', " fullword ascii
      $s10 = "      return proxy" fullword ascii
      $s11 = "  return \"DIRECT\"" fullword ascii
      $s12 = "    if (shExpMatch(host, hosts[i])){" fullword ascii
      $s13 = "  '*owkb.ch', '*cash.ch', '*bcf.ch');" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 2KB and
      8 of them
}

